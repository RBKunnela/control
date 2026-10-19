package hookbridge_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/hookbridge"
)

// publishOne publishes one entry and returns its file's path.
func publishOne(t *testing.T, s *hookbridge.Store, dir, call string, expires time.Time) string {
	t.Helper()
	before := names(t, dir)
	if err := s.Publish("tok", "s", call, hookbridge.Entry{Handle: "h-" + call, ExpiresAt: expires}); err != nil {
		t.Fatal(err)
	}
	for _, n := range names(t, dir) {
		if !slices.Contains(before, n) {
			return filepath.Join(dir, n)
		}
	}
	t.Fatal("no new entry")
	return ""
}

func TestAClaimReadsOnlyAnEntryThisStoreWrote(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(path string) error
	}{
		{"a member it does not write", func(p string) error {
			return os.WriteFile(p, []byte(`{"version":"1.0","handle":"h","expires_at":"2030-01-02T03:04:05Z","arguments":"x"}`), 0o600)
		}},
		{"another major version", func(p string) error {
			return os.WriteFile(p, []byte(`{"version":"2.0","handle":"h","expires_at":"2030-01-02T03:04:05Z"}`), 0o600)
		}},
		{"a handle named twice", func(p string) error {
			return os.WriteFile(p, []byte(`{"version":"1.0","handle":"h","handle":"g","expires_at":"2030-01-02T03:04:05Z"}`), 0o600)
		}},
		{"an empty handle", func(p string) error {
			return os.WriteFile(p, []byte(`{"version":"1.0","handle":"","expires_at":"2030-01-02T03:04:05Z"}`), 0o600)
		}},
		{"a time it cannot read", func(p string) error {
			return os.WriteFile(p, []byte(`{"version":"1.0","handle":"h","expires_at":"soon"}`), 0o600)
		}},
		{"a body over 4 KiB", func(p string) error {
			body := `{"version":"1.0","handle":"h","expires_at":"2030-01-02T03:04:05Z"}`
			return os.WriteFile(p, append([]byte(body), slices.Repeat([]byte(" "), 4<<10-len(body)+1)...), 0o600)
		}},
		{"a mode others may read", func(p string) error { return os.Chmod(p, 0o604) }},    //nolint:gosec // G302: the mode under test
		{"a mode the group may read", func(p string) error { return os.Chmod(p, 0o640) }}, //nolint:gosec // G302: the mode under test
		{"a directory", func(p string) error { return errors.Join(os.Remove(p), os.Mkdir(p, 0o700)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := storeDir(t)
			s := openStore(t, dir)
			if err := tc.spoil(publishOne(t, s, dir, "c", later)); err != nil {
				t.Fatal(err)
			}
			if c, err := s.Claim("tok", "s", "c"); !errors.Is(err, hookbridge.ErrEntry) {
				t.Fatalf("Claim = %+v, %v; want ErrEntry", c, err)
			}
			if left := names(t, dir); len(left) != 0 {
				t.Fatalf("the entry it could not read was left as %v", left)
			}
		})
	}
}

// The body just under the entry bound is read: white space after the object
// fills it to exactly 4 KiB.
func TestAnEntryOfExactly4KiBIsRead(t *testing.T) {
	dir := storeDir(t)
	s := openStore(t, dir)
	body := `{"version":"1.0","handle":"h","expires_at":"2030-01-02T03:04:05Z"}`
	padded := body + string(slices.Repeat([]byte(" "), 4<<10-len(body)))
	if err := os.WriteFile(publishOne(t, s, dir, "c", later), []byte(padded), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := s.Claim("tok", "s", "c"); err != nil || c.Handle != "h" {
		t.Fatalf("Claim = %+v, %v", c, err)
	}
}

// fillStore publishes twenty entries that expire at at, two an hour later,
// claims one of the first twenty, and adds a file that is no entry.
func fillStore(t *testing.T, s *hookbridge.Store, dir string, at time.Time) {
	t.Helper()
	for i := range 20 {
		publishOne(t, s, dir, fmt.Sprintf("old-%d", i), at)
	}
	for i := range 2 {
		publishOne(t, s, dir, fmt.Sprintf("new-%d", i), at.Add(time.Hour))
	}
	if _, err := s.Claim("tok", "s", "old-0"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unrelated"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestASweepRemovesOnlyExpiredEntriesAndABoundedNumber(t *testing.T) {
	dir := storeDir(t)
	s := openStore(t, dir)
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	fillStore(t, s, dir, at)
	if n, err := s.Sweep(at.Add(-time.Nanosecond)); n != 0 || err != nil {
		t.Fatalf("a sweep before any expiry removed %d: %v", n, err)
	}
	for _, want := range []int{16, 4, 0} {
		if n, err := s.Sweep(at); n != want || err != nil {
			t.Fatalf("Sweep = %d, %v; want %d", n, err, want)
		}
	}
	if got := len(names(t, dir)); got != 3 {
		t.Fatalf("%d names left, want the two unexpired entries and the unrelated file: %v", got, names(t, dir))
	}
	if n, err := s.Sweep(at.Add(time.Hour)); n != 2 || err != nil {
		t.Fatalf("Sweep at the later expiry = %d, %v", n, err)
	}
}
