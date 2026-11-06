package main

import (
	"context"
	"fmt"
	"net"
	"path"
	"strings"
)

// collectListener binds what --listen names: a loopback address, or with
// unix:/// a socket at an absolute, clean path where nothing is yet, in a
// directory no other account can replace it in.
func collectListener(ctx context.Context, listen string) (net.Listener, error) {
	socket, ok := strings.CutPrefix(listen, "unix://")
	if !ok {
		if err := loopbackOnly(listen); err != nil {
			return nil, err
		}
		return (&net.ListenConfig{}).Listen(ctx, "tcp", listen)
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
