package runs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/guardana/control/internal/files"
)

// maxFileBytes bounds every read. A record at its longest identity is well
// under it.
const maxFileBytes = 4 << 10

// lockRetry is how often a lock another file holds is tried again.
const lockRetry = 2 * time.Millisecond

// dir is one runs directory, opened once. Both handles embed it and neither
// exports it, so a composite literal of either from another package has no
// open directory and every method on it fails closed.
type dir struct {
	// mu lets calls run side by side and keeps Close from pulling the root
	// out from under one.
	mu sync.RWMutex
	// name is the directory as the caller named it, for judging whether the
	// name still names root.
	name string
	// root is the directory as it was opened. Every file is reached through
	// it, never through name.
	root   *os.Root
	opened dirID
	open   bool
	// role says which names the directory holds.
	role role
	// owner is whose account the directory and every file read in it have
	// to be.
	owner ownership
	// mode is what a file this handle creates is given.
	mode fs.FileMode
}

// effectiveUID is the user a runs directory has to belong to.
var effectiveUID = os.Geteuid

// ownership is whose account a directory has to be.
type ownership uint8

const (
	// ownedByThisUser is every directory but a plane's records/.
	ownedByThisUser ownership = iota
	// ownedByAnother is the records/ a plane under the signed authority
	// reads: an operators' account owns it and every record in it, and the
	// plane's own account, which could rewrite them, owns none of them.
	ownedByAnother
	// anyOwner is ownedByAnother that lets the plane's own account own
	// records/, for a plane whose one account is the operator's too.
	anyOwner
)

// openDir opens name as a directory of role r and judges it as a directory:
// the caller judges what it holds, so a plane's binary carries none of the
// code that makes an empty directory a runs directory. The directory has to
// be this user's under ownedByThisUser; otherwise its owner owns every file
// read in it, and under ownedByAnother that owner may not be this user.
func openDir(name string, r role, o ownership) (*dir, error) {
	// The trailing "." fails on anything but a directory rather than wait on
	// a named pipe put at name.
	root, err := os.OpenRoot(name + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotRunsDir, err)
	}
	info, err := root.Stat(".")
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%w: %w", ErrNotRunsDir, err), root.Close())
	}
	if info.Mode().Perm()&writableByOthers != 0 {
		return nil, errors.Join(fmt.Errorf("%w: mode %04o", ErrPermissions, info.Mode().Perm()), root.Close())
	}
	id, err := identify(info)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	if err := o.judgeDir(id.uid); err != nil {
		return nil, errors.Join(fmt.Errorf("%s: %w", clip(name), err), root.Close())
	}
	mode := fs.FileMode(0o600)
	if r == roleRecords {
		mode = recordsFileMode
	}
	return &dir{name: name, root: root, opened: id, open: true, role: r, owner: o, mode: mode}, nil
}

// judgeDir refuses a directory owned by uid that o does not let it be.
func (o ownership) judgeDir(uid uint32) error {
	euid := effectiveUID()
	mine := euid >= 0 && int64(uid) == int64(euid)
	switch {
	case o == ownedByThisUser && !mine:
		return fmt.Errorf("%w: owned by uid %d", ErrOwner, uid)
	case o == ownedByAnother && (mine || euid < 0):
		return fmt.Errorf("%w: uid %d", ErrPlaneOwned, uid)
	}
	return nil
}

// checkContents reads the marker and refuses a directory holding anything
// this package does not write.
func (d *dir) checkContents() error {
	entries, err := d.readDir()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotRunsDir, err)
	}
	return d.judgeContents(entries)
}

func (d *dir) judgeContents(entries []os.DirEntry) error {
	if d.role == roleState {
		_, err := d.scan(entries)
		return err
	}
	if !slices.ContainsFunc(entries, func(e os.DirEntry) bool { return e.Name() == markerFile }) {
		return fmt.Errorf("%w: it holds no %s", ErrNotRunsDir, markerFile)
	}
	if err := d.readMarker(); err != nil {
		return err
	}
	_, err := d.scan(entries)
	return err
}

// lockDir takes the directory's exclusive lock, which only the operator's
// side takes, and returns what releases it.
func (d *dir) lockDir(ctx context.Context) (func() error, error) {
	f, err := d.root.Open(".")
	if err != nil {
		return nil, err
	}
	if err := lockWaiting(ctx, f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f.Close, nil
}

// lockWaiting takes f's exclusive lock, trying again while another open file
// holds it, until ctx ends. A platform with no lock answers at once.
func lockWaiting(ctx context.Context, f *os.File) error {
	timer := time.NewTimer(lockRetry)
	defer timer.Stop()
	for {
		ok, err := tryLock(f)
		if err != nil || ok {
			return err
		}
		timer.Reset(lockRetry)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// begin holds the handle open for one call, refusing a closed handle, an
// ended context and a directory that changed, and returns what ends the call.
func (d *dir) begin(ctx context.Context) (func(), error) {
	if d == nil {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.RLock()
	if !d.open {
		d.mu.RUnlock()
		return nil, ErrClosed
	}
	if err := d.judge(); err != nil {
		d.mu.RUnlock()
		return nil, err
	}
	return d.mu.RUnlock, nil
}

// judge holds the directory to what it was at open: the same directory, the
// same owner, writable by nobody else, and still at the name it was opened
// under.
func (d *dir) judge() error {
	info, err := d.root.Stat(".")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDirectoryChanged, err)
	}
	now, err := identify(info)
	if err != nil {
		return err
	}
	if err := d.opened.still(now); err != nil {
		return err
	}
	named, err := os.Stat(d.name)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDirectoryChanged, err)
	}
	at, err := identify(named)
	if err != nil {
		return err
	}
	if at.dev != d.opened.dev || at.ino != d.opened.ino {
		return fmt.Errorf("%w: another directory stands at its name", ErrDirectoryChanged)
	}
	return nil
}

func (d *dir) close() error {
	if d == nil {
		return ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.open {
		return ErrClosed
	}
	d.open = false
	return d.root.Close()
}

// readDir lists the directory, sorted by name.
func (d *dir) readDir() ([]os.DirEntry, error) {
	f, err := d.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := f.ReadDir(-1)
	if err = errors.Join(err, f.Close()); err != nil {
		return nil, err
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

// scan returns the run ids that have a record, sorted, and refuses the whole
// listing over one entry this package did not write: guessing what else is in
// the directory is how a forged name gets read.
func (d *dir) scan(entries []os.DirEntry) ([]string, error) {
	var ids []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, clip(e.Name()))
		}
		switch k, id := classify(e.Name(), d.role); k {
		case kindRecord:
			ids = append(ids, id)
		case kindMarker, kindOther:
		case kindForeign:
			return nil, fmt.Errorf("%w: %q", ErrForeignFile, clip(e.Name()))
		}
	}
	return ids, nil
}

// openRegular opens name with flag and refuses anything but the regular file
// that stood at name when it looked: a symbolic link, a pipe, a device, or a
// file swapped in between the look and the open. It also refuses a file a
// group or the world may write, or another user owns: such an account may
// rewrite it in place, which a directory only its owner may write does not
// prevent.
func (d *dir) openRegular(name string, flag int) (*os.File, error) {
	before, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, clip(name))
	}
	f, err := d.root.OpenFile(name, flag|nonBlocking, 0)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.Join(fmt.Errorf("%w: %q changed while it was opened", ErrForeignFile, clip(name)), f.Close())
	}
	if after.Mode().Perm()&writableByOthers != 0 {
		return nil, errors.Join(fmt.Errorf("%w: %q has mode %04o", ErrForeignFile, clip(name), after.Mode().Perm()), f.Close())
	}
	if d.owner == ownedByAnother && files.CheckOwnedBy(after, effectiveUID()) == nil {
		return nil, errors.Join(fmt.Errorf("%w: %q", ErrPlaneOwned, clip(name)), f.Close())
	}
	if err := files.CheckOwnedBy(after, d.fileOwner()); err != nil {
		return nil, errors.Join(fmt.Errorf("%w: %q: %w", ErrForeignFile, clip(name), err), f.Close())
	}
	return f, nil
}

// fileOwner is the user every file read has to belong to.
func (d *dir) fileOwner() int {
	if d.owner != ownedByThisUser {
		return int(d.opened.uid)
	}
	return effectiveUID()
}

// readFile reads one regular file of at most maxFileBytes. A file of exactly
// the bound is read; one byte more is refused.
func (d *dir) readFile(name string) ([]byte, error) {
	f, err := d.openRegular(name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFileBytes {
		return nil, fmt.Errorf("%w: %q is over %d bytes", ErrTooLarge, clip(name), maxFileBytes)
	}
	return raw, nil
}

// replace puts body at name whole: a fresh file at the fixed temporary name,
// forced to disk, renamed over name, and the directory forced to disk after.
// Whatever stood at tmp is removed first, so the exclusive create never
// writes through a link a writer of the directory left there.
func (d *dir) replace(tmp, name string, body []byte) error {
	if err := d.root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := d.createNew(tmp)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return errors.Join(err, d.root.Remove(tmp))
	}
	if err := d.root.Rename(tmp, name); err != nil {
		return errors.Join(err, d.root.Remove(tmp))
	}
	return d.syncDir()
}

// createNew creates name with the directory's file mode, which a umask
// does not narrow, so a plane of another account in the records' group can
// read a record. It refuses a name that exists already, a link included,
// rather than write through it.
func (d *dir) createNew(name string) (*os.File, error) {
	f, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, d.mode)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(d.mode); err != nil {
		return nil, errors.Join(err, f.Close(), d.root.Remove(name))
	}
	return f, nil
}

func (d *dir) syncDir() error {
	f, err := d.root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// markerKind is what the marker of a directory of each role names: an
// unsigned layout's directory and a signed layout's records/ are told apart
// by it, so neither is read as the other.
var markerKind = map[role]string{roleFlat: "runs", roleRecords: "signed-runs"}

var markerKeys = []string{"schema_version", "kind"}

func (d *dir) readMarker() error {
	raw, err := d.readFile(markerFile)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotRunsDir, err)
	}
	f, err := fields(raw, markerKeys)
	if err != nil {
		return fmt.Errorf("%w: the marker: %w", ErrNotRunsDir, err)
	}
	version, err := stringField(f, "schema_version")
	if err == nil {
		err = checkSchemaVersion(version)
	}
	if err != nil {
		return fmt.Errorf("%w: the marker: %w", ErrNotRunsDir, err)
	}
	if k, err := stringField(f, "kind"); err != nil || k != markerKind[d.role] {
		return fmt.Errorf("%w: the marker names another kind", ErrNotRunsDir)
	}
	return nil
}

func (d *dir) writeMarker() error {
	body := `{"schema_version":"` + SchemaVersion + `","kind":"` + markerKind[d.role] + "\"}\n"
	if err := files.CreateNoReplaceIn(d.root, markerFile, []byte(body), d.mode); err != nil {
		return fmt.Errorf("%w: %w", ErrNotRunsDir, err)
	}
	return d.root.Chmod(markerFile, d.mode)
}
