//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package enforce_test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
)

// serveOnce runs Serve on ln until it returns or a short context ends, and
// returns what it returned.
func serveOnce(t *testing.T, a *enforce.Adapter, ln net.Listener) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	return a.Serve(ctx, ln)
}

func adapterOn(t *testing.T, socket string) *enforce.Adapter {
	t.Helper()
	cfg := validConfig()
	cfg.Socket = socket
	a, err := enforce.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestServeTakesOnlyItsOwnLockedListenerOnce: a listener bound without the
// socket's lock, another adapter's, or its own a second time would let two
// planes serve one socket, so each is refused before anything is served.
func TestServeTakesOnlyItsOwnLockedListenerOnce(t *testing.T) {
	t.Run("a Unix listener bound elsewhere", func(t *testing.T) {
		socket := socketPath(t)
		ln, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		if err := serveOnce(t, adapterOn(t, socket), ln); !errors.Is(err, enforce.ErrListener) {
			t.Fatalf("Serve = %v, want ErrListener", err)
		}
	})
	t.Run("another adapter's listener", func(t *testing.T) {
		socket := socketPath(t)
		ln, err := adapterOn(t, socket).Listen()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		other := adapterOn(t, filepath.Join(filepath.Dir(socket), "o"))
		if err := serveOnce(t, other, ln); !errors.Is(err, enforce.ErrListener) {
			t.Fatalf("Serve = %v, want ErrListener", err)
		}
	})
	t.Run("its own listener a second time", func(t *testing.T) {
		a := adapterOn(t, socketPath(t))
		ln, err := a.Listen()
		if err != nil {
			t.Fatal(err)
		}
		if err := serveOnce(t, a, ln); err != nil {
			t.Fatalf("the first Serve = %v", err)
		}
		if err := serveOnce(t, a, ln); !errors.Is(err, enforce.ErrListener) {
			t.Fatalf("a second Serve on one listener = %v, want ErrListener", err)
		}
	})
}
