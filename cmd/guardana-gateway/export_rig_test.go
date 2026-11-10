package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/peercred"
)

// exportSocket is a path for a test collector's socket, in a new directory
// of this account short enough for the bound on a socket's path. A plane
// exports to no collector where the platform cannot name a socket's peer.
func exportSocket(t *testing.T) string {
	t.Helper()
	if !peercred.Supported {
		t.Skip("this platform cannot name a socket peer's account, so a plane exports to no collector here")
	}
	dir, err := os.MkdirTemp("", "gx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

// ownUID is this account's numeric user id, the collector account of a
// collector the test runs.
func ownUID() string { return strconv.Itoa(os.Geteuid()) }

// exportTo points the plane at the collector on the unix:// endpoint, which
// runs as this account.
func exportTo(t *testing.T, endpoint string) {
	t.Helper()
	setEnv(t, "export.endpoint", endpoint)
	setEnv(t, "export.collector_uid", ownUID())
}

// socketOf is the path a unix:// URL names.
func socketOf(endpoint string) string { return strings.TrimPrefix(endpoint, "unix://") }

// unixClient sends every request to the socket at path, whatever its URL's
// host.
func unixClient(path string) *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
}

// serveUnix serves h on a new socket until the test ends and returns its
// unix:// URL.
func serveUnix(t *testing.T, h http.Handler) string {
	t.Helper()
	socket := exportSocket(t)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "unix://" + socket
}

// shortTempDir is a new directory under the system's temporary directory,
// with a name far shorter than a test's own.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "td")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
