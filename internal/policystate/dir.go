package policystate

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

// maxFileBytes bounds every read. A floor file at the longest bundle id and
// reason, every character escaped, is under it.
const maxFileBytes = 8 << 10

// lockRetry is how often a lock another open file holds is tried again.
const lockRetry = 2 * time.Millisecond

// othersAccess is the mode bits that give a directory's or a file's group or
// the world any access.
const othersAccess fs.FileMode = 0o077

// The names this package writes under a directory.
const (
	markerFile      = "floors.meta"
	floorSuffix     = ".floor.json"
	routeMarkerFile = "routes.meta"
	routeSuffix     = ".route.json"
)

// effectiveUID is the user a floor directory and its files have to belong to.
var effectiveUID = os.Geteuid

// replaceIn replaces a file whole; a test swaps it to stop a write where a
// crash would.
var replaceIn = files.ReplaceIn

// fileID is what a directory or a file is judged by: which one it is, who
// owns it, and its permission bits.
type fileID struct {
	dev, ino uint64
	uid      uint32
	perm     fs.FileMode
}

// judgeOwned refuses a file or directory another user owns or whose mode
// gives its group or the world access.
func judgeOwned(id fileID) error {
	if euid := effectiveUID(); euid < 0 || int64(id.uid) != int64(euid) {
		return fmt.Errorf("%w: owned by uid %d", ErrOwner, id.uid)
	}
	if id.perm&othersAccess != 0 {
		return fmt.Errorf("%w: mode %04o", ErrPermissions, id.perm)
	}
	return nil
}

// dir is one floor directory, opened once. Store embeds it unexported, so a
// Store from another package's composite literal has no open directory and
// every method on it fails closed.
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
	opened fileID
	open   bool
}

// openDir opens name and judges it as a directory: not a link, owned by this
// user, and no access for the group or the world. What it holds the caller
// judges.
func openDir(name string) (*dir, error) {
	if err := isDirectory(name); err != nil {
		return nil, err
	}
	// The trailing "." fails on anything but a directory rather than wait on
	// a named pipe put at name.
	root, err := os.OpenRoot(name + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	d := &dir{name: name, root: root, open: true}
	if err := d.identifyOpened(); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return d, nil
}

// isDirectory refuses a name where no directory stands. The name is not
// followed, so a link to a directory is refused too.
func isDirectory(name string) error {
	info, err := os.Lstat(name)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %w", ErrNotStateDir, err)
	case !info.IsDir():
		return fmt.Errorf("%w: %q is not a directory: %s", ErrNotStateDir, name, info.Mode().Type())
	}
	return nil
}

func (d *dir) identifyOpened() error {
	info, err := d.root.Stat(".")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	id, err := identify(info)
	if err != nil {
		return err
	}
	if err := judgeOwned(id); err != nil {
		return err
	}
	d.opened = id
	return d.stillNamed()
}

// stillNamed refuses a directory no longer at the name it was opened under.
func (d *dir) stillNamed() error {
	named, err := os.Lstat(d.name)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDirectoryChanged, err)
	}
	at, err := identify(named)
	if err != nil {
		return err
	}
	if !named.IsDir() || at.dev != d.opened.dev || at.ino != d.opened.ino {
		return fmt.Errorf("%w: another entry stands at its name", ErrDirectoryChanged)
	}
	return nil
}

// judge holds the directory to what it was at open: the same owner, no
// access for the group or the world, and still at its name. The root is the
// directory opened, so whether another stands at the name is stillNamed's to
// say.
func (d *dir) judge() error {
	info, err := d.root.Stat(".")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDirectoryChanged, err)
	}
	now, err := identify(info)
	if err != nil {
		return err
	}
	switch {
	case now.uid != d.opened.uid:
		return fmt.Errorf("%w: owned by uid %d, opened owned by uid %d", ErrDirectoryChanged, now.uid, d.opened.uid)
	case now.perm&othersAccess != 0:
		return fmt.Errorf("%w: %w: mode %04o", ErrDirectoryChanged, ErrPermissions, now.perm)
	}
	return d.stillNamed()
}

// begin holds the directory open for one call, refusing a closed handle, an
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

// lock takes the directory's exclusive lock for a read, so a read never sees
// a file between a write's look and its rename. It first waits while a writer
// of this process waits for the lock or holds it, so reads that follow one
// another never keep it from a raise here, and writes that follow one another
// can hold reads off until their contexts end; across processes the lock
// favours no one. It returns what releases the lock.
func (d *dir) lock(ctx context.Context) (func() error, error) {
	if err := turnOf(d.opened).read(ctx); err != nil {
		return nil, err
	}
	return d.take(ctx)
}

// lockToWrite takes the directory's exclusive lock for a write, ahead of the
// reads of this process that start while it waits.
func (d *dir) lockToWrite(ctx context.Context) (func() error, error) {
	done := turnOf(d.opened).write()
	unlock, err := d.take(ctx)
	if err != nil {
		done()
		return nil, err
	}
	return func() error {
		defer done()
		return unlock()
	}, nil
}

// take takes the directory's exclusive lock, trying again while another open
// file holds it, until ctx ends, and judges the directory again once it holds
// it, since the wait can last as long as ctx allows. It returns what releases
// the lock.
func (d *dir) take(ctx context.Context) (func() error, error) {
	f, err := d.root.Open(".")
	if err != nil {
		return nil, err
	}
	if err := lockWaiting(ctx, f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if err := d.judge(); err != nil {
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

// judgeContents reads the marker, which has to name kind, and refuses a
// directory holding anything this package does not write, a floor file of an
// id the marker does not list among them: guessing what else is there is how
// a planted name gets read. It returns the ids the marker lists.
func (d *dir) judgeContents(entries []os.DirEntry, kind Kind) ([]string, error) {
	if !holds(entries, markerFile) {
		if holds(entries, routeMarkerFile) {
			return nil, fmt.Errorf("%w: it holds route floors, not a %s's", ErrWrongKind, kind)
		}
		return nil, fmt.Errorf("%w: it holds no %s", ErrNotStateDir, markerFile)
	}
	ids, err := d.readMarker(kind)
	if err != nil {
		return nil, err
	}
	if err := judgeEntries(entries, markerFile, ids, floorName); err != nil {
		return nil, err
	}
	return ids, nil
}

// holds reports whether entries hold an entry called name.
func holds(entries []os.DirEntry, name string) bool {
	return slices.ContainsFunc(entries, func(e os.DirEntry) bool { return e.Name() == name })
}

// judgeEntries refuses an entry that is not a regular file, and any name but
// the marker, the file name gives a listed id, and what a crash left.
func judgeEntries(entries []os.DirEntry, marker string, ids []string, name func(string) string) error {
	listed := make(map[string]bool, len(ids))
	for _, id := range ids {
		listed[name(id)] = true
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, clip(e.Name()))
		}
		if n := e.Name(); n != marker && !listed[n] && !files.IsTemp(n) {
			return fmt.Errorf("%w: %q", ErrForeignFile, clip(n))
		}
	}
	return nil
}

// openRegular opens name read-only and refuses anything but the regular file
// that stood at name when it looked, owned by this user and closed to the
// group and the world: a link, a pipe, a device, or a file swapped in between
// the look and the open.
func (d *dir) openRegular(name string) (*os.File, error) {
	before, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, clip(name))
	}
	f, err := d.root.OpenFile(name, os.O_RDONLY|nonBlocking, 0)
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
	id, err := identify(after)
	if err == nil {
		err = judgeOwned(id)
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%q: %w", clip(name), err), f.Close())
	}
	return f, nil
}

// readFile reads one regular file of at most limit bytes. A file of exactly
// the bound is read; one byte more is refused.
func (d *dir) readFile(name string, limit int64) ([]byte, error) {
	f, err := d.openRegular(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%w: %q is over %d bytes", ErrTooLarge, clip(name), limit)
	}
	return raw, nil
}

// clip shortens a name a directory's writer chose before it goes into an
// error.
func clip(s string) string {
	const limit = 80
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
