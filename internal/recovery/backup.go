package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/gatewayconfig"
)

// Taken is what a backup copied, and each configured key whose file or
// directory was not there to copy.
type Taken struct {
	Manifest Manifest
	Absent   []string
}

// Backup copies the state of every class cfg configures into dir, a
// directory it makes for its owner alone, and writes the manifest last, so a
// directory without one is no backup. It holds the spool's and the hold
// journal's locks while it runs, refusing while a plane holds either. It
// refuses the memory authority with ErrMemory, a dir that exists with
// ErrExists, an entry of the state that is neither a regular file nor a
// directory with ErrNotRegular, and a backup past MaxEntries or a file past
// MaxFileBytes with ErrManifest.
func Backup(ctx context.Context, cfg *gatewayconfig.Config, dir string, now time.Time) (_ Taken, err error) {
	authority := cfg.Approvals.Authority
	if authority != gatewayconfig.AuthorityDirectory && authority != gatewayconfig.AuthoritySigned {
		return Taken{}, fmt.Errorf("%w: approvals.authority is %q", ErrMemory, authority)
	}
	release, err := holdPlane(cfg)
	if err != nil {
		return Taken{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return Taken{}, fmt.Errorf("%w: %s", ErrExists, dir)
		}
		return Taken{}, err
	}
	b := &backup{dir: dir}
	out := Taken{Manifest: Manifest{Authority: authority, Tenant: cfg.TenantID, Project: cfg.ProjectID, TakenAt: now.UTC().Truncate(time.Second)}}
	if out.Absent, err = b.copyClasses(ctx, cfg); err != nil {
		return Taken{}, err
	}
	out.Manifest.Entries = b.entries
	if err := b.finish(out.Manifest); err != nil {
		return Taken{}, err
	}
	return out, nil
}

type backup struct {
	dir     string
	entries []Entry
}

// copyClasses copies every class cfg configures under its authority, and
// returns the keys of those where nothing stood.
func (b *backup) copyClasses(ctx context.Context, cfg *gatewayconfig.Config) ([]string, error) {
	var absent []string
	for _, c := range classes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value := c.value(cfg)
		if value == "" || !c.applies(cfg.Approvals.Authority) {
			continue
		}
		src, err := filepath.Abs(cfg.Resolve(value))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.key, err)
		}
		found, err := b.copyClass(c, src)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.key, err)
		}
		if !found {
			absent = append(absent, c.key)
		}
	}
	return absent, nil
}

// copyClass copies what stands at src, and reports false when nothing does.
func (b *backup) copyClass(c class, src string) (bool, error) {
	info, err := os.Lstat(src)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	case !c.dir:
		return true, b.copyFile(c, src, c.name+"/"+filepath.Base(src), info)
	case !info.IsDir():
		return false, fmt.Errorf("%w: %s is not a directory", ErrNotRegular, src)
	}
	return true, filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		at := c.name
		if rel != "." {
			at += "/" + filepath.ToSlash(rel)
		}
		if d.IsDir() {
			return b.mkdir(at)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return b.copyFile(c, p, at, info)
	})
}

func (b *backup) mkdir(at string) error {
	p := filepath.Join(b.dir, filepath.FromSlash(at))
	return os.MkdirAll(p, 0o700)
}

// copyFile copies the regular file src, as Lstat found it, to at in the
// backup, and lists it.
func (b *backup) copyFile(c class, src, at string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is %s", ErrNotRegular, src, info.Mode().Type())
	}
	if len(b.entries) >= MaxEntries {
		return fmt.Errorf("%w: more than %d files", ErrManifest, MaxEntries)
	}
	raw, err := readRegular(src, info)
	if err != nil {
		return err
	}
	if err := b.mkdir(filepath.ToSlash(filepath.Dir(filepath.FromSlash(at)))); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if err := writeNew(filepath.Join(b.dir, filepath.FromSlash(at)), raw); err != nil {
		return err
	}
	b.entries = append(b.entries, Entry{Class: c.name, Key: c.key, Source: src, Path: at, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(raw))})
	return nil
}

// readRegular reads the file Lstat found at src, refusing one replaced since
// or larger than MaxFileBytes.
func readRegular(src string, before fs.FileInfo) ([]byte, error) {
	f, err := os.Open(src) //nolint:gosec // G304: a path the plane's configuration names, judged as a regular file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, fmt.Errorf("%w: %s changed while it was read", ErrNotRegular, src)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxFileBytes {
		return nil, fmt.Errorf("%w: %s is over %d bytes", ErrManifest, src, MaxFileBytes)
	}
	return raw, nil
}

func writeNew(p string, raw []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a path inside the backup this call made
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	return errors.Join(err, f.Sync(), f.Close())
}

// finish forces every directory made to disk, then writes the manifest.
func (b *backup) finish(m Manifest) error {
	body, err := MarshalManifest(m)
	if err != nil {
		return err
	}
	err = filepath.WalkDir(b.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		return files.SyncDir(p)
	})
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(b.dir)
	if err != nil {
		return err
	}
	if err := files.CreateNoReplaceIn(root, ManifestName, body, 0o600); err != nil {
		return errors.Join(err, root.Close())
	}
	return errors.Join(root.Close(), files.SyncDir(b.dir))
}
