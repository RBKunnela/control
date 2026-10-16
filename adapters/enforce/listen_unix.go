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
// process owns and nobody else may enter, and checks both once bound. A stale
// socket of this user that refuses a connection is replaced; anything else at
// the path is refused with ErrSocketInUse, a directory that is not the
// plane's alone with ErrSocketDir, and a bound socket that is not this
// process's with mode 0600 with ErrSocketMode.
func (a *Adapter) Listen() (net.Listener, error) {
	return a.listen(nil)
}

// CheckSocketDir refuses, as Listen does and binding nothing, a socket
// directory that is not a directory this process's user owns with no
// permission for group or others.
func (a *Adapter) CheckSocketDir() error {
	return ownDir(filepath.Dir(a.cfg.Socket))
}

// listen is Listen with chmodded, when set, run between the chmod and the
// checks after the bind, which is where a test changes what they see.
func (a *Adapter) listen(chmodded func()) (net.Listener, error) {
	path := a.cfg.Socket
	dir := filepath.Dir(path)
	if err := ownDir(dir); err != nil {
		return nil, err
	}
	if err := clearStale(path); err != nil {
		return nil, err
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSocketInUse, err)
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
		return nil, errors.Join(err, ln.Close())
	}
	return ln, nil
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
// plane that ended without closing its listener leaves behind. A timeout, a
// full backlog on Linux, a permission error or exhausted resources can come
// from a live receiver, so any other dial error leaves the path and refuses
// with ErrSocketInUse, as does anything else at the path. On macOS a live
// receiver whose backlog is full refuses too, so there a refusal is no proof.
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
