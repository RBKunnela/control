//go:build unix

package spool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestADirectorySwappedUnderTheSpoolReceivesNothing: the spool keeps writing
// to the directory it locked and checked, not to whatever its name names
// later.
func TestADirectorySwappedUnderTheSpoolReceivesNothing(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "ev")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := twoSegments(t, dir)
	held := filepath.Join(parent, "ev.held")
	if err := os.Rename(dir, held); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(context.Background(), sample(3)); err != nil {
		t.Fatalf("Append into the held directory: %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the replacement holds %d entries: %v", len(entries), err)
	}
	if _, err := os.Lstat(filepath.Join(held, "00000000000000000003.seg")); err != nil {
		t.Errorf("the third segment is not in the held directory: %v", err)
	}
}

// TestASecondNameIsReportedWhereItCanBeFound: the refusal names the device,
// the inode and the count of names, so the operator can find the other name.
func TestASecondNameIsReportedWhereItCanBeFound(t *testing.T) {
	dir := t.TempDir()
	s := twoSegments(t, dir)
	other := filepath.Join(t.TempDir(), "other")
	if err := os.Link(firstSegmentPath(dir), other); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(other)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	_, err = nextNow(t, s)
	if !errors.Is(err, ErrForeignFile) {
		t.Fatalf("Next = %v, want ErrForeignFile", err)
	}
	for _, want := range []string{fmt.Sprintf("device %d,", st.Dev), fmt.Sprintf("inode %d,", st.Ino), "2 names"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}
}

// TestOpenRefusesAFileSwappedInBetweenTheListingAndTheScan: the file a scan
// opens has to be the one the listing found, for a segment and for the
// quarantine.
func TestOpenRefusesAFileSwappedInBetweenTheListingAndTheScan(t *testing.T) {
	for _, name := range []string{segmentFileName(1), quarantineName} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, _, _ := quarantined(t, dir, nil)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			swapped := false
			again, err := Open(Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16, openRead: func(root *os.Root, n string, flag int) (*os.File, error) {
				if n == name && !swapped {
					swapped = true
					copyOver(t, filepath.Join(dir, n))
				}
				return root.OpenFile(n, flag, 0)
			}})
			if err == nil {
				_ = again.Close()
			}
			if !swapped {
				t.Fatalf("Open = %v and never read %s", err, name)
			}
			if !errors.Is(err, ErrForeignFile) {
				t.Errorf("Open = %v, want ErrForeignFile", err)
			}
		})
	}
}

// copyOver renames a copy of the file at path over it: the same bytes, one
// name, another file.
func copyOver(t *testing.T, path string) {
	t.Helper()
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
}
