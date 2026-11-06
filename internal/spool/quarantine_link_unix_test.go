//go:build unix

package spool

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// outsideSize is the length of the file a planted link leads to, longer than
// anything the spool cuts back to in these tests.
const outsideSize = 4096

// swapForLink moves the file at path out of its directory and puts a symbolic
// link at path to a file of outsideSize bytes, whose path it returns.
func swapForLink(t *testing.T, path string) string {
	t.Helper()
	outside := t.TempDir()
	if err := os.Rename(path, filepath.Join(outside, "moved")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, bytes.Repeat([]byte("x"), outsideSize), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	return target
}

func quarantineOne(t *testing.T, r *Reader, n int) error {
	t.Helper()
	_, err := r.Quarantine([]*controlv1.Event{sample(n)})
	return err
}

// quarantined is a spool under dir with two records delivered and the first
// of them quarantined, so the quarantine file exists.
func quarantined(t *testing.T, dir string, failOn func() error) (*Spool, *Reader, string) {
	t.Helper()
	s, r := spoolWithDelivered(t, dir, 2, failOn)
	if err := quarantineOne(t, r, 0); err != nil {
		t.Fatal(err)
	}
	return s, r, filepath.Join(dir, quarantineName)
}

// TestAHardLinkAtTheQuarantineIsNeverAppendedTo.
func TestAHardLinkAtTheQuarantineIsNeverAppendedTo(t *testing.T) {
	_, r, path := quarantined(t, t.TempDir(), nil)
	before := sizeOf(t, path)
	other := filepath.Join(t.TempDir(), "other")
	if err := os.Link(path, other); err != nil {
		t.Fatal(err)
	}
	if err := quarantineOne(t, r, 1); !errors.Is(err, ErrForeignFile) {
		t.Errorf("Quarantine = %v, want ErrForeignFile", err)
	}
	if got := sizeOf(t, other); got != before {
		t.Errorf("the linked file holds %d bytes, held %d", got, before)
	}
}

// TestASymbolicLinkAtTheQuarantineIsNeverAppendedTo: whether the quarantine
// existed or not, a link at its name is refused and its target untouched.
func TestASymbolicLinkAtTheQuarantineIsNeverAppendedTo(t *testing.T) {
	t.Run("existing", func(t *testing.T) {
		_, r, path := quarantined(t, t.TempDir(), nil)
		target := swapForLink(t, path)
		if err := quarantineOne(t, r, 1); err == nil {
			t.Error("Quarantine appended through a link")
		}
		if got := sizeOf(t, target); got != outsideSize {
			t.Errorf("the link's target holds %d bytes, held %d", got, outsideSize)
		}
	})
	t.Run("new", func(t *testing.T) {
		dir := t.TempDir()
		_, r := spoolWithDelivered(t, dir, 2, nil)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Symlink(target, filepath.Join(dir, quarantineName)); err != nil {
			t.Fatal(err)
		}
		if err := quarantineOne(t, r, 0); err == nil {
			t.Error("Quarantine created its file through a link")
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the link's target exists: %v", err)
		}
	})
}

// TestAQuarantinePlantedAfterTheListingIsRefused: a file put at the
// quarantine's name after Open found none is refused by the create, and left
// as it was.
func TestAQuarantinePlantedAfterTheListingIsRefused(t *testing.T) {
	dir := t.TempDir()
	_, r := spoolWithDelivered(t, dir, 2, nil)
	planted := filepath.Join(dir, quarantineName)
	if err := os.WriteFile(planted, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := quarantineOne(t, r, 0); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Quarantine = %v, want ErrCorrupt", err)
	}
	if body, err := os.ReadFile(planted); err != nil || string(body) != "planted" { //nolint:gosec // G304: the test's own file
		t.Errorf("the planted file holds %q: %v", body, err)
	}
}

// TestAnotherQuarantineSwappedInIsRefused: a regular file with one name and
// the same bytes, renamed over the quarantine, is not the file the spool
// created.
func TestAnotherQuarantineSwappedInIsRefused(t *testing.T) {
	_, r, path := quarantined(t, t.TempDir(), nil)
	body, err := os.ReadFile(path) //nolint:gosec // G304: the test's own spool
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "copy")
	if err := os.WriteFile(copied, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(copied, path); err != nil {
		t.Fatal(err)
	}
	if err := quarantineOne(t, r, 1); !errors.Is(err, ErrForeignFile) {
		t.Errorf("Quarantine = %v, want ErrForeignFile", err)
	}
	if got := sizeOf(t, path); got != int64(len(body)) {
		t.Errorf("the swapped file holds %d bytes, held %d", got, len(body))
	}
}

// TestAQuarantineWithASecondNameIsNotOpened: Open refuses a quarantine given a
// second name while the spool was closed.
func TestAQuarantineWithASecondNameIsNotOpened(t *testing.T) {
	dir := t.TempDir()
	s, _, path := quarantined(t, dir, nil)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(t.TempDir(), "other")); err != nil {
		t.Fatal(err)
	}
	if again, err := openIn(dir); !errors.Is(err, ErrForeignFile) {
		if err == nil {
			_ = again.Close()
		}
		t.Errorf("Open = %v, want ErrForeignFile", err)
	}
}

// TestASymbolicLinkAtTheQuarantineIsNotOpened.
func TestASymbolicLinkAtTheQuarantineIsNotOpened(t *testing.T) {
	dir := t.TempDir()
	s, _, path := quarantined(t, dir, nil)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	target := swapForLink(t, path)
	if again, err := openIn(dir); !errors.Is(err, ErrForeignFile) {
		if err == nil {
			_ = again.Close()
		}
		t.Errorf("Open = %v, want ErrForeignFile", err)
	}
	if got := sizeOf(t, target); got != outsideSize {
		t.Errorf("the link's target holds %d bytes, held %d", got, outsideSize)
	}
}

// TestACutBackNeverTruncatesThroughALink: a link swapped in at a segment or
// at the quarantine while a write to it fails is not followed by the cut that
// repairs the write.
func TestACutBackNeverTruncatesThroughALink(t *testing.T) {
	boom := errors.New("disk gone")
	armed := func(swap func() string, target *string) (func() error, *atomic.Bool) {
		var on atomic.Bool
		return func() error {
			if !on.Load() {
				return nil
			}
			on.Store(false)
			*target = swap()
			return boom
		}, &on
	}
	t.Run("segment", func(t *testing.T) {
		dir := t.TempDir()
		var target string
		failOn, on := armed(func() string { return swapForLink(t, firstSegmentPath(dir)) }, &target)
		s, _ := spoolWithDelivered(t, dir, 1, failOn)
		on.Store(true)
		if err := s.Append(context.Background(), sample(9)); !errors.Is(err, boom) {
			t.Fatalf("Append = %v, want the failure", err)
		}
		if got := sizeOf(t, target); got != outsideSize {
			t.Errorf("the link's target holds %d bytes, held %d", got, outsideSize)
		}
	})
	t.Run("quarantine", func(t *testing.T) {
		dir := t.TempDir()
		var target string
		failOn, on := armed(func() string { return swapForLink(t, filepath.Join(dir, quarantineName)) }, &target)
		_, r, _ := quarantined(t, dir, failOn)
		on.Store(true)
		if err := quarantineOne(t, r, 1); !errors.Is(err, boom) {
			t.Fatalf("Quarantine = %v, want the failure", err)
		}
		if got := sizeOf(t, target); got != outsideSize {
			t.Errorf("the link's target holds %d bytes, held %d", got, outsideSize)
		}
	})
}

// TestOpenNeverCutsATornTailThroughALink: a link swapped in at the last
// segment or at the quarantine once Open has opened it to cut a torn tail is
// not followed by the cut.
func TestOpenNeverCutsATornTailThroughALink(t *testing.T) {
	for name, file := range map[string]func(dir string) string{
		"segment":    func(dir string) string { return firstSegmentPath(dir) },
		"quarantine": func(dir string) string { return filepath.Join(dir, quarantineName) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, _, _ := quarantined(t, dir, nil)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			path := file(dir)
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: the test's own spool
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte("torn")); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			var target string
			again, err := Open(Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16, openFile: func(root *os.Root, n string, flag int) (segmentFile, error) {
				f, err := openOSFile(root, n, flag)
				if err == nil && filepath.Join(dir, n) == path && target == "" {
					target = swapForLink(t, path)
				}
				return f, err
			}})
			if err == nil {
				_ = again.Close()
			}
			if target == "" {
				t.Fatalf("Open = %v and never opened %s to cut it", err, name)
			}
			if got := sizeOf(t, target); got != outsideSize {
				t.Errorf("the link's target holds %d bytes, held %d", got, outsideSize)
			}
		})
	}
}
