//go:build unix

package runs_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/runs"
)

// TestADirectoryAnotherUserOwnsIsRefused: a runs directory is the operator's
// word on which runs exist, so one another account owns, reached by a link or
// otherwise, is refused by both handles, whatever it holds.
func TestADirectoryAnotherUserOwnsIsRefused(t *testing.T) {
	dir := newDir(t)
	a := openAdmin(t, dir)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	restore := runs.SetEffectiveUID(func() int { return os.Geteuid() + 1 })
	defer restore()
	if _, err := runs.OpenPlane(dir); !errors.Is(err, runs.ErrOwner) {
		t.Errorf("OpenPlane on another user's directory = %v, want ErrOwner", err)
	}
	if _, err := runs.OpenAdmin(context.Background(), dir); !errors.Is(err, runs.ErrOwner) {
		t.Errorf("OpenAdmin on another user's directory = %v, want ErrOwner", err)
	}
	restore()
	if p, err := runs.OpenPlane(dir); err != nil {
		t.Errorf("OpenPlane as the owner = %v", err)
	} else if err := p.Close(); err != nil {
		t.Error(err)
	}
}

// TestALockFileReplacedDuringARaiseWritesNothing: a raise that finds its lock
// file replaced while it held it fails, and the state stays as it was, since
// a second writer locking the new file would not have been kept out.
func TestALockFileReplacedDuringARaiseWritesNothing(t *testing.T) {
	dir, a, p := setup(t)
	rec, _ := openRoot(t, a)
	before, err := p.State(context.Background(), rec.Root)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, rec.Root+".lock")
	err = p.Raise(context.Background(), rec.Root, func(s runs.State) runs.State {
		if err := os.Remove(lock); err != nil {
			t.Fatal(err)
		}
		writeFile(t, lock, nil)
		s.Untrusted = true
		return s
	})
	if !errors.Is(err, runs.ErrLockChanged) {
		t.Fatalf("Raise across a replaced lock file = %v, want ErrLockChanged", err)
	}
	if after, err := p.State(context.Background(), rec.Root); err != nil || after != before {
		t.Errorf("the state after a refused raise = %+v, %v; want %+v", after, err, before)
	}
}

// TestAMalformedTokenIsNeverRepeated: whatever stands where the run id
// belongs, a secret pasted there included, the refusal does not repeat it.
func TestAMalformedTokenIsNeverRepeated(t *testing.T) {
	_, a, p := setup(t)
	_, token := openRoot(t, a)
	_, secret, _ := strings.Cut(token, ".")
	for _, bad := range []string{secret + ".x", secret + "." + secret, "run-" + secret + "." + secret, secret} {
		_, err := p.Resolve(context.Background(), bad, alice, opened)
		if causeOf(t, err) != runs.CauseMalformed {
			t.Errorf("%d characters: cause %v, want malformed", len(bad), err)
		}
		if strings.Contains(err.Error(), secret[:12]) {
			t.Errorf("the refusal repeats the secret: %v", err)
		}
	}
}
