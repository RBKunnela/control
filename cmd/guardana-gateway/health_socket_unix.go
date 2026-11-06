//go:build unix

package main

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

	"github.com/guardana/control/internal/files"
)

// staleHealthDial bounds the dial that tells a stale socket from a live one.
const staleHealthDial = time.Second

// listenHealthSocket binds a socket at path that only this account may
// open, with mode 0600, in a directory healthDir admits before the bind and
// after it. A socket of this account that refuses connections is what a
// plane that did not stop leaves, and is replaced; anything else at the path
// is refused and left as it is. reachable says health.socket_uid names
// another account, which may then search the directory.
func listenHealthSocket(path string, reachable bool) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := healthDir(dir, reachable); err != nil {
		return nil, err
	}
	if err := clearStaleHealthSocket(path); err != nil {
		return nil, err
	}
	ln, err := bindSocket(path, 0o600)
	if err != nil {
		return nil, fmt.Errorf("health.socket: %w", err)
	}
	if err := healthDir(dir, reachable); err != nil {
		return nil, errors.Join(err, ln.Close())
	}
	return ln, nil
}

// healthDir refuses a directory for the health socket that is not a
// directory of this account, that the group or others may write, or, unless
// another account is to reach the socket, that they may enter at all.
func healthDir(dir string, reachable bool) error {
	info, err := os.Lstat(dir)
	forbidden := fs.FileMode(0o077)
	if reachable {
		forbidden = 0o022
	}
	switch {
	case err != nil:
		return fmt.Errorf("health.socket: %w", err)
	case !info.IsDir() || files.CheckOwnedBy(info, os.Geteuid()) != nil || info.Mode().Perm()&forbidden != 0:
		return fmt.Errorf("health.socket: %s is not a directory of this account with mode %s or narrower", dir, map[bool]string{false: "0700", true: "0755"}[reachable])
	}
	return nil
}

// clearStaleHealthSocket removes a socket of this account at path that
// refuses a connection, and refuses anything else that is there.
func clearStaleHealthSocket(path string) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("health.socket: %w", err)
	case info.Mode().Type() != fs.ModeSocket || files.CheckOwnedBy(info, os.Geteuid()) != nil:
		return fmt.Errorf("health.socket: %s is there and is not a socket of this account; nothing is bound over it", path)
	}
	conn, err := (&net.Dialer{Timeout: staleHealthDial}).DialContext(context.Background(), "unix", path)
	if err == nil {
		return errors.Join(fmt.Errorf("health.socket: something answers on %s", path), conn.Close())
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("health.socket: %s is there and may be live: %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("health.socket: %w", err)
	}
	return nil
}
