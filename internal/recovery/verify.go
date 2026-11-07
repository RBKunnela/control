package recovery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/guardana/control/internal/gatewayconfig"
)

// readBackup reads dir's manifest and holds dir and the manifest to cfg: the
// same authority, tenant and project, every entry from where cfg puts that
// file today and of a class cfg's authority backs up, each file of the size
// and SHA-256 the manifest names, and no file the manifest does not name. It
// writes the bytes it verified into into, an empty owner-only directory, and
// checks that copy against the manifest again: a restore reads only the copy,
// so a file of dir changed after the check is never taken.
func readBackup(cfg *gatewayconfig.Config, dir, into string) (Manifest, error) {
	raw, err := readListed(filepath.Join(dir, ManifestName), MaxManifestBytes)
	if err != nil {
		return Manifest{}, fmt.Errorf("%s: %w", ManifestName, err)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return Manifest{}, err
	}
	if err := samePlane(cfg, m); err != nil {
		return Manifest{}, err
	}
	listed := make(map[string]bool, len(m.Entries))
	for _, e := range m.Entries {
		if err := fromConfigured(cfg, e); err != nil {
			return Manifest{}, err
		}
		raw, err := sameFile(dir, e)
		if err != nil {
			return Manifest{}, err
		}
		if err := copyVerified(into, e.Path, raw); err != nil {
			return Manifest{}, err
		}
		listed[e.Path] = true
	}
	if err := onlyListed(dir, listed, into); err != nil {
		return Manifest{}, err
	}
	return m, checkCopy(into, m, listed)
}

// samePlane refuses a manifest of another authority, tenant or project than
// cfg's, and a cfg of the memory authority.
func samePlane(cfg *gatewayconfig.Config, m Manifest) error {
	authority := cfg.Approvals.Authority
	switch {
	case authority != gatewayconfig.AuthorityDirectory && authority != gatewayconfig.AuthoritySigned:
		return fmt.Errorf("%w: approvals.authority is %q", ErrMemory, authority)
	case m.Authority != authority:
		return fmt.Errorf("%w: the backup is of the %s authority, the configuration names %s", ErrOtherPlane, m.Authority, authority)
	case m.Tenant != cfg.TenantID || m.Project != cfg.ProjectID:
		return fmt.Errorf("%w: the backup is of %s/%s, the configuration names %s/%s",
			ErrOtherPlane, m.Tenant, m.Project, clip(cfg.TenantID), clip(cfg.ProjectID))
	}
	return nil
}

// checkCopy holds the copy in into to the manifest again: each file of its
// size and SHA-256, and nothing else.
func checkCopy(into string, m Manifest, listed map[string]bool) error {
	for _, e := range m.Entries {
		if _, err := sameFile(into, e); err != nil {
			return err
		}
	}
	return onlyListed(into, listed, "")
}

// copyVerified writes raw at the slash path rel under into, making the
// directories on its way owner-only.
func copyVerified(into, rel string, raw []byte) error {
	p := filepath.Join(into, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return writeNew(p, raw)
}

// fromConfigured refuses an entry whose source is not where cfg puts its
// class's file today, whose path in the backup does not follow from that
// source, or of a class cfg's authority does not back up.
func fromConfigured(cfg *gatewayconfig.Config, e Entry) error {
	c, _ := classNamed(e.Class)
	value := c.value(cfg)
	switch {
	case !c.applies(cfg.Approvals.Authority):
		return fmt.Errorf("%w: %s under the %s authority", ErrSource, c.name, cfg.Approvals.Authority)
	case value == "":
		return fmt.Errorf("%w: the configuration names no %s", ErrSource, c.key)
	}
	at, err := filepath.Abs(cfg.Resolve(value))
	if err != nil {
		return fmt.Errorf("%s: %w", c.key, err)
	}
	want := at
	wantPath := c.name + "/" + filepath.Base(at)
	if c.dir {
		rel := strings.TrimPrefix(e.Path, c.name+"/")
		want, wantPath = filepath.Join(at, filepath.FromSlash(rel)), e.Path
	}
	if e.Source != want || e.Path != wantPath {
		return fmt.Errorf("%w: %s came from %s, and %s names %s", ErrSource, e.Path, clip(e.Source), c.key, clip(at))
	}
	return nil
}

// sameFile reads the file of e under dir and returns its bytes when they are
// of the size and SHA-256 e names.
func sameFile(dir string, e Entry) ([]byte, error) {
	raw, err := readListed(filepath.Join(dir, filepath.FromSlash(e.Path)), MaxFileBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrTampered, e.Path, err)
	}
	sum := sha256.Sum256(raw)
	if int64(len(raw)) != e.Bytes || hex.EncodeToString(sum[:]) != e.SHA256 {
		return nil, fmt.Errorf("%w: %s", ErrTampered, e.Path)
	}
	return raw, nil
}

// onlyListed refuses a file under dir the manifest does not name, and any
// entry that is neither a regular file nor a directory. Where into is set it
// makes each directory of dir there too, owner-only, since a class may need
// one that holds no file.
func onlyListed(dir string, listed map[string]bool, into string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir() && into != "":
			return os.MkdirAll(filepath.Join(into, filepath.FromSlash(rel)), 0o700)
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return fmt.Errorf("%w: %s is %s", ErrUnlisted, rel, d.Type())
		case rel != ManifestName && !listed[rel]:
			return fmt.Errorf("%w: %s", ErrUnlisted, rel)
		}
		return nil
	})
}

// readListed reads the regular file at p, of at most limit bytes, without
// following a link at its name.
func readListed(p string, limit int64) ([]byte, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, info.Mode().Type())
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%w: %d bytes, the bound is %d", ErrManifest, info.Size(), limit)
	}
	raw, err := readRegular(p, info)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("over its bound")
	}
	return raw, nil
}
