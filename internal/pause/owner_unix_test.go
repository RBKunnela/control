//go:build unix

package pause

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// actAs makes this package judge ownership as the accounts uids name, one per
// check in the order the checks are made, the last repeating.
func actAs(t *testing.T, uids ...int) {
	t.Helper()
	var n atomic.Int64
	effectiveUID = func() int {
		i := int(n.Add(1)) - 1
		return uids[min(i, len(uids)-1)]
	}
	t.Cleanup(func() { effectiveUID = os.Geteuid })
}

// ownPauseFile writes a pause file holding one global entry in a fresh
// directory of mode 0700, both owned by the account running the test.
func ownPauseFile(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pause")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pause.json")
	body := `{"schema_version":"2","entries":[{"id":"g","scope":{"kind":"global"},"created_at":"2026-09-24T10:00:00Z","reason":""}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAPauseFileOwnedByAnotherAccountIsUnknown: the directory, then the file,
// each owned by an account other than the one the plane runs as, while
// everything else about them reads. The same file read as its owner is the
// control: it pauses.
func TestAPauseFileOwnedByAnotherAccountIsUnknown(t *testing.T) {
	me, other := os.Geteuid(), os.Geteuid()+1
	path := ownPauseFile(t)
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	if s := Read(path, now, time.Second); s.State() != Paused {
		t.Fatalf("the file read as its owner: %s, %q: %s", s.State(), s.Cause(), s.Detail())
	}
	for _, c := range []struct {
		name  string
		uids  []int
		cause Cause
		err   Error
	}{
		{"the directory", []int{other}, CauseDirOwner, ErrDirOwner},
		{"the file", []int{me, other}, CauseFileOwner, ErrFileOwner},
	} {
		t.Run(c.name, func(t *testing.T) {
			actAs(t, c.uids...)
			if s := Read(path, now, time.Second); s.State() != Unknown || s.Cause() != c.cause {
				t.Errorf("Read = %s, %q (%s); want unknown, %q", s.State(), s.Cause(), s.Detail(), c.cause)
			}
			actAs(t, c.uids...)
			if _, err := List(path); !errors.Is(err, c.err) {
				t.Errorf("List = %v, want %v", err, c.err)
			}
		})
	}
}

// TestTheWriterRefusesADirectoryAnotherAccountOwns: a file written there
// would be refused by a plane running as this account.
func TestTheWriterRefusesADirectoryAnotherAccountOwns(t *testing.T) {
	ctx := context.Background()
	path := ownPauseFile(t)
	actAs(t, os.Geteuid()+1)
	if err := Init(ctx, filepath.Join(filepath.Dir(path), "other.json")); !errors.Is(err, ErrDirOwner) {
		t.Errorf("Init = %v, want ErrDirOwner", err)
	}
	if err := Remove(ctx, path, "g"); !errors.Is(err, ErrDirOwner) {
		t.Errorf("Remove = %v, want ErrDirOwner", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "other.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Init wrote a file all the same: %v", err)
	}
	actAs(t, os.Geteuid())
	if err := Remove(ctx, path, "g"); err != nil {
		t.Errorf("Remove as the owner: %v", err)
	}
}
