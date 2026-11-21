package main

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
)

// collectListener binds what --listen names, unix:/// and a socket at an
// absolute, clean path where nothing is yet, in a directory no other account
// can replace it in. The path is read as a URL's, escapes undone, so the URL
// collect prints names the socket again; a host, a query or a fragment is
// refused. A TCP address is refused: a plane exports to no plaintext
// collector.
func collectListener(listen string) (net.Listener, error) {
	if !strings.HasPrefix(listen, "unix://") {
		return nil, fmt.Errorf("--listen takes unix:///<path>; a TCP address was removed in 0.17, as a plane no longer exports over plaintext")
	}
	u, err := url.Parse(listen)
	switch {
	case err != nil:
		return nil, fmt.Errorf("--listen is not a URL: %w", err)
	case u.Host != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(listen, "#"):
		return nil, fmt.Errorf("--listen unix:// is followed by a path alone, with no host, query or fragment; escape a #, a ? or a %% in it")
	}
	socket := u.Path
	if !path.IsAbs(socket) || path.Clean(socket) != socket {
		return nil, fmt.Errorf("--listen unix:// is followed by an absolute, clean socket path")
	}
	ln, err := listenCollectSocket(socket)
	if err != nil {
		return nil, fmt.Errorf("--listen: %w", err)
	}
	return ln, nil
}
