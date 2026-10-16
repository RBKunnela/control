//go:build unix

package enforce

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

type noRuns struct{}

func (noRuns) Resolve(_ context.Context, _ string, _ gateway.RunIdentity, _ time.Time) (gateway.OpenedRun, error) {
	return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunUnknown}
}

// After the bind Listen checks the socket and its directory again, so a mode
// or a directory that changed between the first check and the bind is
// refused, and nothing is left listening.
func TestListenChecksTheSocketAndItsDirectoryAfterTheBind(t *testing.T) {
	for _, tc := range []struct {
		name string
		dir  bool
		mode os.FileMode
		want error
	}{
		{"a socket group readable", false, 0o640, ErrSocketMode},
		{"a socket its owner can execute", false, 0o700, ErrSocketMode},
		{"a socket its owner cannot write", false, 0o400, ErrSocketMode},
		{"a directory others may enter", true, 0o711, ErrSocketDir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "enf")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			socket := filepath.Join(dir, "s")
			a, err := New(Config{
				Socket: socket, ExecutionLifetime: time.Minute, Runs: noRuns{},
				Identity: Identity{Principal: &controlv1.Principal{Id: "user-1"}, Agent: &controlv1.Agent{Id: "agent-1"}},
				Tools:    []Tool{{Name: "read_file", Effect: controlv1.EffectClass_EFFECT_CLASS_READ, Provider: "files", ResourceType: "file"}},
				Clock:    time.Now, NewID: func() string { return "id" },
			})
			if err != nil {
				t.Fatal(err)
			}
			ln, err := a.listen(func() {
				target := socket
				if tc.dir {
					target = dir
				}
				if err := os.Chmod(target, tc.mode); err != nil {
					t.Error(err)
				}
			})
			if !errors.Is(err, tc.want) || ln != nil {
				t.Fatalf("Listen = %v, %v; want %v", ln, err, tc.want)
			}
			if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a socket was left at the path: %v", err)
			}
		})
	}
}

// Only a refused connection proves a socket stale: a timeout, a full backlog
// or a permission error leaves the path in place and refuses the bind.
func TestClearStaleRemovesOnlyARefusedSocket(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dialErr error
		removed bool
	}{
		{"connection refused", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, true},
		{"a timeout", &net.OpError{Op: "dial", Net: "unix", Err: os.ErrDeadlineExceeded}, false},
		{"a full backlog", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.EAGAIN)}, false},
		{"permission denied", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.EACCES)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "enf")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			socket := filepath.Join(dir, "s")
			ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			ul, ok := ln.(*net.UnixListener)
			if !ok {
				t.Fatal("not a unix listener")
			}
			ul.SetUnlinkOnClose(false)
			if err := ln.Close(); err != nil {
				t.Fatal(err)
			}
			prev := dialSocket
			dialSocket = func(string) (net.Conn, error) { return nil, tc.dialErr }
			t.Cleanup(func() { dialSocket = prev })

			err = clearStale(socket)
			_, statErr := os.Lstat(socket)
			if tc.removed {
				if err != nil || !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("clearStale = %v, path: %v; want nil and the path removed", err, statErr)
				}
				return
			}
			if !errors.Is(err, ErrSocketInUse) || !errors.Is(err, tc.dialErr) {
				t.Fatalf("clearStale = %v, want ErrSocketInUse naming %v", err, tc.dialErr)
			}
			if statErr != nil {
				t.Fatalf("the socket was removed: %v", statErr)
			}
		})
	}
}
