//go:build !unix

package enforce

import "net"

// claim refuses every listener: Listen binds none here.
func (*Adapter) claim(net.Listener) bool { return false }

// Listen refuses with ErrPlatform: nothing here can check who owns a socket.
func (*Adapter) Listen() (net.Listener, error) {
	return nil, ErrPlatform
}

// CheckSocketDir refuses with ErrPlatform, as Listen does.
func (*Adapter) CheckSocketDir() error {
	return ErrPlatform
}
