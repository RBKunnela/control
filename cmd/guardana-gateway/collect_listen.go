package main

import (
	"fmt"
	"net"
	"path"
	"strings"
)

// collectListener binds what --listen names, unix:/// and a socket at an
// absolute, clean path where nothing is yet, in a directory no other account
// can replace it in. A TCP address is refused: a plane exports to no
// plaintext collector.
func collectListener(listen string) (net.Listener, error) {
	socket, ok := strings.CutPrefix(listen, "unix://")
	if !ok {
		return nil, fmt.Errorf("--listen takes unix:///<path>; a TCP address was removed in 0.17, as a plane no longer exports over plaintext")
	}
	if !path.IsAbs(socket) || path.Clean(socket) != socket {
		return nil, fmt.Errorf("--listen unix:// is followed by an absolute, clean socket path")
	}
	ln, err := listenCollectSocket(socket)
	if err != nil {
		return nil, fmt.Errorf("--listen: %w", err)
	}
	return ln, nil
}
