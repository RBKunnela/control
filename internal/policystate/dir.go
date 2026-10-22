package policystate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/guardana/control/internal/files"
)

// maxFileBytes bounds every read. A floor file at the longest bundle id and
// reason, every character escaped, is under it.
const maxFileBytes = 8 << 10

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

// clip shortens a name a directory's writer chose before it goes into an
// error.
func clip(s string) string {
	const limit = 80
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
