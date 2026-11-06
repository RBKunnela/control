//go:build unix

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/guardana/control/internal/files"
)

// socketBound runs between the bind and the mode change with the path the
// socket was bound at; a test swaps that path through it.
var socketBound func(string)

// bindSocket binds a Unix socket that appears at final with mode, and never
// changes a mode or removes a name through a path another account could
// swap: it binds in a new directory of its own, sets the mode there through
// a root that refuses a link out of it, and links the socket into place,
// which fails rather than replaces whatever is at final. The caller has
// judged final's directory.
func bindSocket(final string, mode fs.FileMode) (*boundSocket, error) {
	private, err := os.MkdirTemp(filepath.Dir(final), ".s")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(private) }()
	root, err := os.OpenRoot(private)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	tmp := filepath.Join(private, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmp, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	info, err := placeSocket(root, tmp, final, mode)
	if err != nil {
		return nil, errors.Join(err, ln.Close())
	}
	return &boundSocket{UnixListener: ln, path: final, bound: info}, nil
}

// placeSocket sets the socket at tmp to mode, checks it is still the socket
// bound there, and links it to final, which it checks again.
func placeSocket(root *os.Root, tmp, final string, mode fs.FileMode) (fs.FileInfo, error) {
	bound, err := root.Lstat("s")
	if err != nil {
		return nil, err
	}
	if socketBound != nil {
		socketBound(tmp)
	}
	if err := root.Chmod("s", mode); err != nil {
		return nil, err
	}
	if err := ownSocket(root.Lstat("s")); err != nil {
		return nil, err
	}
	now, _ := root.Lstat("s")
	if !os.SameFile(now, bound) || now.Mode().Perm() != mode {
		return nil, fmt.Errorf("the bound socket was replaced or has mode %v", now.Mode())
	}
	if err := unix.Linkat(unix.AT_FDCWD, tmp, unix.AT_FDCWD, final, 0); err != nil {
		return nil, fmt.Errorf("%s: %w", final, err)
	}
	placed, err := os.Lstat(final)
	if err == nil {
		err = ownSocket(placed, nil)
	}
	if err == nil && !os.SameFile(placed, bound) {
		err = fmt.Errorf("%s is not the socket bound", final)
	}
	return placed, err
}

// ownSocket refuses what is not a socket this account owns.
func ownSocket(info fs.FileInfo, err error) error {
	switch {
	case err != nil:
		return err
	case info.Mode().Type() != fs.ModeSocket:
		return fmt.Errorf("%s is not a socket", info.Name())
	}
	return files.CheckOwnedBy(info, os.Geteuid())
}

// boundSocket is a listener whose name is the path it was linked to. Closing
// removes that name only while it is still the socket bound.
type boundSocket struct {
	*net.UnixListener
	path   string
	bound  fs.FileInfo
	once   sync.Once
	closed error
}

func (s *boundSocket) Addr() net.Addr { return &net.UnixAddr{Name: s.path, Net: "unix"} }

func (s *boundSocket) Close() error {
	s.once.Do(func() {
		s.closed = s.UnixListener.Close()
		if now, err := os.Lstat(s.path); err == nil && os.SameFile(now, s.bound) {
			s.closed = errors.Join(s.closed, os.Remove(s.path))
		}
	})
	return s.closed
}

// checkSocketDir refuses a directory for a socket that is a link, is not a
// directory, is owned by an account other than this one or root, or that
// the group or others may write unless it is sticky.
func checkSocketDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	owner := files.CheckOwnedBy(info, os.Geteuid()) == nil || files.CheckOwnedBy(info, 0) == nil
	switch {
	case !info.IsDir():
		return fmt.Errorf("%s is a link or not a directory", dir)
	case !owner:
		return fmt.Errorf("%s is owned by another account, which could replace the socket", dir)
	case info.Mode().Perm()&0o022 != 0 && info.Mode()&fs.ModeSticky == 0:
		return fmt.Errorf("%s is writable by the group or others and not sticky, so they could replace the socket", dir)
	}
	return nil
}

// listenCollectSocket binds collect's socket at path with mode 0666: every
// account may connect, as every account can reach a loopback port, since
// the credential decides who writes and the plane checks this account
// answers before it sends the credential.
func listenCollectSocket(path string) (net.Listener, error) {
	if err := checkSocketDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return bindSocket(path, 0o666)
}
