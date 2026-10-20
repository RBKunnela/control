//go:build unix

package enforce

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

// staleDial bounds the dial that tells a stale socket from a live one.
const staleDial = time.Second

// dialSocket is the probe clearStale runs against an existing socket.
var dialSocket = func(path string) (net.Conn, error) {
	return (&net.Dialer{Timeout: staleDial}).DialContext(context.Background(), "unix", path)
}

// Listen binds the configured socket with mode 0600 in a directory this
// process owns and nobody else may enter, and checks both once bound. It
// first takes the lock beside the socket, which the listener holds until it
// is closed; a lock another receiver holds is refused with ErrSocketInUse. A
// stale socket of this user that refuses a connection is then replaced;
// anything else at the path is refused with ErrSocketInUse, a directory that
// is not the plane's alone with ErrSocketDir, and a bound socket that is not
// this process's with mode 0600 with ErrSocketMode.
func (a *Adapter) Listen() (net.Listener, error) {
	return a.listen(nil)
}

// CheckSocketDir refuses, as Listen does and binding and locking nothing, a
// socket directory that is not a directory this process's user owns with no
// permission for group or others, and a lock file beside the socket that
// Listen would refuse to lock.
func (a *Adapter) CheckSocketDir() error {
	if err := ownDir(filepath.Dir(a.cfg.Socket)); err != nil {
		return err
	}
	return checkLock(a.cfg.Socket)
}

// listen is Listen with chmodded, when set, run between the chmod and the
// checks after the bind, which is where a test changes what they see.
func (a *Adapter) listen(chmodded func()) (net.Listener, error) {
	path := a.cfg.Socket
	dir := filepath.Dir(path)
	if err := ownDir(dir); err != nil {
		return nil, err
	}
	release, err := lockSocket(path)
	if err != nil {
		return nil, err
	}
	if err := clearStale(path); err != nil {
		return nil, errors.Join(err, release())
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%w: %w", ErrSocketInUse, err), release())
	}
	// Until the chmod the socket has the umask's mode; nobody else can reach
	// it meanwhile, because nobody else may enter its directory.
	err = os.Chmod(path, 0o600)
	if chmodded != nil {
		chmodded()
	}
	if err == nil {
		err = ownSocket(path)
	}
	if err == nil {
		err = ownDir(dir)
	}
	if err != nil {
		return nil, errors.Join(err, ln.Close(), release())
	}
	return &lockedListener{Listener: ln, release: release, owner: a}, nil
}

// lockedListener is a listener Listen bound with the socket's lock held. It
// releases the lock once it is closed, and Serve takes it once, for the
// adapter that bound it.
type lockedListener struct {
	net.Listener
	release func() error
	owner   *Adapter
	served  atomic.Bool
}

func (l *lockedListener) Close() error {
	return errors.Join(l.Listener.Close(), l.release())
}

// claim reports whether a may serve ln: a listener a's Listen returned that
// no Serve has taken yet. A listener bound elsewhere holds no lock, so a
// second plane could serve the same socket beside it.
func (a *Adapter) claim(ln net.Listener) bool {
	l, ok := ln.(*lockedListener)
	return ok && l.owner == a && l.served.CompareAndSwap(false, true)
}

// ownDir refuses anything but a directory, not a link to one, that this
// process's user owns with no permission for group or others.
func ownDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSocketDir, err)
	}
	if !info.IsDir() || !ownedByMe(info) || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s is not a directory of this user with mode 0700 or narrower", ErrSocketDir, dir)
	}
	return nil
}

// ownSocket refuses a path that is not a socket this user owns with mode 0600.
func ownSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSocketMode, err)
	}
	if info.Mode().Type() != fs.ModeSocket || !ownedByMe(info) || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: %v", ErrSocketMode, info.Mode())
	}
	return nil
}

// clearStale removes a socket of this user that refuses a connection, which a
// plane that ended without closing its listener leaves behind. It runs under
// the socket's lock, which proves no receiver that takes it is alive; the
// dial still guards against one that holds no lock. A timeout, a full backlog
// on Linux, a permission error or exhausted resources can come from a live
// receiver, so any other dial error leaves the path and refuses with
// ErrSocketInUse, as does anything else at the path.
func clearStale(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSocketInUse, err)
	}
	if info.Mode().Type() != fs.ModeSocket || !ownedByMe(info) {
		return fmt.Errorf("%w: %v", ErrSocketInUse, info.Mode())
	}
	conn, err := dialSocket(path)
	if err == nil {
		return errors.Join(fmt.Errorf("%w: something answers on it", ErrSocketInUse), conn.Close())
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%w: %w", ErrSocketInUse, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("%w: %w", ErrSocketInUse, err)
	}
	return nil
}

func ownedByMe(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(os.Geteuid())
}
