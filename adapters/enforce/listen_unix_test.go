//go:build unix

package enforce_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/adapters/enforce"
)

func listenAt(t *testing.T, socket string) error {
	t.Helper()
	cfg := validConfig()
	cfg.Socket = socket
	a, err := enforce.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := a.Listen()
	if err == nil {
		t.Cleanup(func() { _ = ln.Close() })
	}
	return err
}

// refusedDir fails unless both CheckSocketDir and Listen refuse socket's
// directory with ErrSocketDir.
func refusedDir(t *testing.T, socket string) {
	t.Helper()
	cfg := validConfig()
	cfg.Socket = socket
	a, err := enforce.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CheckSocketDir(); !errors.Is(err, enforce.ErrSocketDir) {
		t.Errorf("CheckSocketDir = %v, want ErrSocketDir", err)
	}
	if err := listenAt(t, socket); !errors.Is(err, enforce.ErrSocketDir) {
		t.Fatalf("Listen = %v, want ErrSocketDir", err)
	}
}

func TestListenBindsASocketOnlyItsOwnerCanReach(t *testing.T) {
	socket := socketPath(t)
	cfg := validConfig()
	cfg.Socket = socket
	a, err := enforce.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CheckSocketDir(); err != nil {
		t.Fatalf("CheckSocketDir: %v", err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CheckSocketDir left something at the path: %v", err)
	}
	if err := listenAt(t, socket); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	info, err := os.Lstat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Type() != os.ModeSocket || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, want a socket with 0600", info.Mode())
	}
}

func TestListenRefusesADirectoryThePlaneDoesNotHoldAlone(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{"group and world readable", 0o755},
		{"group readable", 0o750},
		{"world traversable", 0o701},
		{"group writable", 0o720},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := socketPath(t)
			if err := os.Chmod(filepath.Dir(socket), tc.mode); err != nil {
				t.Fatal(err)
			}
			refusedDir(t, socket)
			if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a socket was left at the path: %v", err)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		refusedDir(t, filepath.Join(filepath.Dir(socketPath(t)), "absent", "s"))
	})
	t.Run("a file", func(t *testing.T) {
		parent := filepath.Join(filepath.Dir(socketPath(t)), "f")
		if err := os.WriteFile(parent, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		refusedDir(t, filepath.Join(parent, "s"))
	})
	t.Run("a link to the plane's own directory", func(t *testing.T) {
		dir := filepath.Dir(socketPath(t))
		link := filepath.Join(filepath.Dir(socketPath(t)), "l")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		refusedDir(t, filepath.Join(link, "s"))
	})
}

func TestListenNeverReplacesAFileOrALink(t *testing.T) {
	t.Run("a regular file", func(t *testing.T) {
		socket := socketPath(t)
		if err := os.WriteFile(socket, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := listenAt(t, socket); !errors.Is(err, enforce.ErrSocketInUse) {
			t.Fatalf("Listen = %v, want ErrSocketInUse", err)
		}
		if data, err := os.ReadFile(filepath.Clean(socket)); err != nil || string(data) != "keep" {
			t.Fatalf("the file changed: %q, %v", data, err)
		}
	})
	t.Run("a link", func(t *testing.T) {
		socket := socketPath(t)
		if err := os.Symlink(filepath.Join(filepath.Dir(socket), "elsewhere"), socket); err != nil {
			t.Fatal(err)
		}
		if err := listenAt(t, socket); !errors.Is(err, enforce.ErrSocketInUse) {
			t.Fatalf("Listen = %v, want ErrSocketInUse", err)
		}
	})
}

func TestListenReplacesOnlyAStaleSocketOfItsOwn(t *testing.T) {
	t.Run("a socket something answers on", func(t *testing.T) {
		socket := socketPath(t)
		live, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = live.Close() })
		if err := listenAt(t, socket); !errors.Is(err, enforce.ErrSocketInUse) {
			t.Fatalf("Listen = %v, want ErrSocketInUse", err)
		}
	})
	t.Run("a stale socket of this user", func(t *testing.T) {
		socket := socketPath(t)
		stale, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		ul, ok := stale.(*net.UnixListener)
		if !ok {
			t.Fatal("not a unix listener")
		}
		ul.SetUnlinkOnClose(false)
		if err := stale.Close(); err != nil {
			t.Fatal(err)
		}
		if err := listenAt(t, socket); err != nil {
			t.Fatalf("Listen over a stale socket: %v", err)
		}
	})
}
