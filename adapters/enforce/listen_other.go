//go:build !unix

package enforce

import "net"

// unixSocket reports whether ln listens on a Unix socket.
func unixSocket(ln net.Listener) bool {
	_, ok := ln.(*net.UnixListener)
	return ok
}

// Listen refuses with ErrPlatform: nothing here can check who owns a socket.
func (*Adapter) Listen() (net.Listener, error) {
	return nil, ErrPlatform
}

// CheckSocketDir refuses with ErrPlatform, as Listen does.
func (*Adapter) CheckSocketDir() error {
	return ErrPlatform
}
