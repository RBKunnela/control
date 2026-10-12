//go:build unix

package enforce

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
