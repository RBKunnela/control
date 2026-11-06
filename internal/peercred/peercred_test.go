package peercred_test

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/peercred"
)

// TestBothEndsOfASocketNameThisAccount: a real socket's two ends each read
// the other's account, which is this process's own.
func TestBothEndsOfASocketNameThisAccount(t *testing.T) {
	if !peercred.Supported {
		t.Skip("this platform names no peer; TestAnUnsupportedPlatformRefuses holds it")
	}
	path := filepath.Join(shortDir(t), "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck // a test's listener
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck // a test's connection
	server := <-accepted
	if server == nil {
		t.Fatal("nothing was accepted")
	}
	defer server.Close() //nolint:errcheck // a test's connection
	for name, conn := range map[string]net.Conn{"the accepted end": server, "the dialing end": client} {
		uid, err := peercred.UID(conn)
		if err != nil || int64(uid) != int64(os.Geteuid()) {
			t.Errorf("%s reads uid %d, %v; want %d", name, uid, err, os.Geteuid())
		}
	}
}

// TestATCPConnectionHasNoPeerCredential: only a Unix socket names its peer.
func TestATCPConnectionHasNoPeerCredential(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck // a test's listener
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck // a test's connection
	if _, err := peercred.UID(client); !errors.Is(err, peercred.ErrNotUnix) {
		t.Errorf("a TCP connection: %v, want ErrNotUnix", err)
	}
	if _, err := peercred.UID(nil); !errors.Is(err, peercred.ErrNotUnix) {
		t.Errorf("no connection: %v, want ErrNotUnix", err)
	}
}

// TestAClosedSocketIsUnreadable: a connection whose descriptor is gone names
// no account, and the error says so rather than a uid of zero.
func TestAClosedSocketIsUnreadable(t *testing.T) {
	a, b, err := pair()
	if err != nil {
		t.Skip("no Unix socket pair on this platform:", err)
	}
	_ = b.Close()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if uid, err := peercred.UID(a); !errors.Is(err, peercred.ErrUnreadable) && !errors.Is(err, peercred.ErrUnsupported) {
		t.Errorf("a closed socket reads uid %d, %v; want ErrUnreadable", uid, err)
	}
}

// pair is two connected ends of a Unix socket.
func pair() (*net.UnixConn, *net.UnixConn, error) {
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir) //nolint:errcheck // a test's scratch
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close() //nolint:errcheck // a test's listener
	c, err := net.DialUnix("unix", nil, ln.Addr().(*net.UnixAddr))
	if err != nil {
		return nil, nil, err
	}
	s, err := ln.AcceptUnix()
	if err != nil {
		return nil, nil, err
	}
	return c, s, nil
}

// shortDir is a directory whose socket paths stay under the platform's bound
// on a socket's name, which t.TempDir can pass on darwin.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
