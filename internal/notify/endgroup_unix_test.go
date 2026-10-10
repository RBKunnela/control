//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package notify

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestEndGroupAsksAgainWhileTheKernelSettles: EPERM before the group is
// gone is asked again; a group that stays EPERM past the settle bound, or
// any other refusal, is an error.
func TestEndGroupAsksAgainWhileTheKernelSettles(t *testing.T) {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		answers  []error
		wantErr  error
		wantCall int
	}{
		"gone at once":            {[]error{syscall.ESRCH}, nil, 1},
		"a leftover child killed": {[]error{nil}, nil, 1},
		"EPERM, then gone":        {[]error{syscall.EPERM, syscall.EPERM, syscall.ESRCH}, nil, 3},
		"EINVAL":                  {[]error{syscall.EINVAL}, syscall.EINVAL, 1},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			replaceKill(t, func(int) error {
				calls++
				return c.answers[min(calls, len(c.answers))-1]
			})
			err := endGroup(&exec.Cmd{Process: proc})
			if !errors.Is(err, c.wantErr) || (c.wantErr == nil) != (err == nil) || calls != c.wantCall {
				t.Fatalf("endGroup = %v after %d call(s), want %v after %d", err, calls, c.wantErr, c.wantCall)
			}
		})
	}
	t.Run("EPERM for good", func(t *testing.T) {
		calls := 0
		replaceKill(t, func(int) error { calls++; return syscall.EPERM })
		start := time.Now()
		err := endGroup(&exec.Cmd{Process: proc})
		if !errors.Is(err, syscall.EPERM) || time.Since(start) < groupSettle || calls < 2 {
			t.Fatalf("endGroup = %v after %v and %d call(s), want EPERM after at least %v", err, time.Since(start), calls, groupSettle)
		}
	})
}

func replaceKill(t *testing.T, kill func(int) error) {
	t.Helper()
	old := killGroup
	killGroup = kill
	t.Cleanup(func() { killGroup = old })
}
