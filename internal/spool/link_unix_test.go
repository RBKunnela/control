//go:build unix

package spool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// twoSegments opens a spool in dir whose every record rolls to a segment of
// its own, and appends two of them.
func twoSegments(t *testing.T, dir string) *Spool {
	t.Helper()
	s, err := Open(Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i := 1; i <= 2; i++ {
		if err := s.Append(context.Background(), sample(i)); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// nextNow is Next on a fresh reader, bounded so that a refusal is told apart
// from a reader left waiting.
func nextNow(t *testing.T, s *Spool) (*controlv1.Event, error) {
	t.Helper()
	r, err := s.Reader(Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	event, _, err := r.Next(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Next waited instead of answering")
	}
	return event, err
}

func sizeOf(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// TestAHardLinkAtTheLastSegmentIsNeverAppendedTo: a second name given to the
// last segment after Open listed it is refused when an append reopens it, and
// the file behind both names keeps its bytes.
func TestAHardLinkAtTheLastSegmentIsNeverAppendedTo(t *testing.T) {
	dir := t.TempDir()
	seg, body := oneSegment(t, dir)
	s, err := openIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the assertions are below
	other := filepath.Join(t.TempDir(), "other")
	if err := os.Link(seg, other); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(context.Background(), sample(2)); !errors.Is(err, ErrForeignFile) {
		t.Errorf("Append = %v, want ErrForeignFile", err)
	}
	if got := sizeOf(t, other); got != int64(len(body)) {
		t.Errorf("the linked file holds %d bytes, held %d", got, len(body))
	}
}

// TestASegmentWithASecondNameIsNotOpened: Open refuses a segment given a
// second name while the spool was closed.
func TestASegmentWithASecondNameIsNotOpened(t *testing.T) {
	dir := t.TempDir()
	seg, _ := oneSegment(t, dir)
	if err := os.Link(seg, filepath.Join(t.TempDir(), "other")); err != nil {
		t.Fatal(err)
	}
	s, err := openIn(dir)
	if err == nil {
		_ = s.Close()
	}
	if !errors.Is(err, ErrForeignFile) {
		t.Errorf("Open = %v, want ErrForeignFile", err)
	}
}

// TestAHardLinkAtASealedSegmentIsNotRead: a reader refuses a sealed segment
// with a second name and stays where it is, so it delivers the segment's
// record once the second name is gone.
func TestAHardLinkAtASealedSegmentIsNotRead(t *testing.T) {
	dir := t.TempDir()
	s := twoSegments(t, dir)
	other := filepath.Join(t.TempDir(), "other")
	if err := os.Link(firstSegmentPath(dir), other); err != nil {
		t.Fatal(err)
	}
	r, err := s.Reader(Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck // read only
	if _, _, err := r.Next(context.Background()); !errors.Is(err, ErrForeignFile) {
		t.Fatalf("Next = %v, want ErrForeignFile", err)
	}
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	event, _, err := r.Next(context.Background())
	if err != nil || event.GetEventId() != "evt-1" {
		t.Errorf("Next after the second name went = %q, %v; want evt-1", event.GetEventId(), err)
	}
}

// TestAnAckThatReadsASegmentWithASecondNameIsRefused: an Ack inside a segment
// reads the record there, and refuses when the segment has a second name.
func TestAnAckThatReadsASegmentWithASecondNameIsRefused(t *testing.T) {
	dir := t.TempDir()
	s, err := openIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the assertion is below
	for i := 1; i <= 2; i++ {
		if err := s.Append(context.Background(), sample(i)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Reader(Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck // read only
	_, mid, err := r.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(firstSegmentPath(dir), filepath.Join(t.TempDir(), "other")); err != nil {
		t.Fatal(err)
	}
	if err := r.Ack(mid); !errors.Is(err, ErrForeignFile) {
		t.Errorf("Ack = %v, want ErrForeignFile", err)
	}
}

// TestALinkSwappedInAfterTheListingIsNotRead: the segment moved away and a
// symbolic link to it put at its name is refused, although the link leads to
// the very file the listing saw, whether it leaves the directory or not.
func TestALinkSwappedInAfterTheListingIsNotRead(t *testing.T) {
	for name, moveTo := range map[string]func(t *testing.T, dir string) (moved, link string){
		"outside": func(t *testing.T, _ string) (string, string) {
			moved := filepath.Join(t.TempDir(), "moved")
			return moved, moved
		},
		"inside": func(_ *testing.T, dir string) (string, string) {
			return filepath.Join(dir, "moved"), "moved"
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s := twoSegments(t, dir)
			moved, link := moveTo(t, dir)
			if err := os.Rename(firstSegmentPath(dir), moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(link, firstSegmentPath(dir)); err != nil {
				t.Fatal(err)
			}
			if event, err := nextNow(t, s); err == nil {
				t.Errorf("Next read %q through a link", event.GetEventId())
			}
		})
	}
}

// TestAnotherFileSwappedInAfterTheListingIsRefused: a regular file with one
// name and the same bytes, renamed over a segment, is not the file the spool
// listed or created, for a reader or for an append.
func TestAnotherFileSwappedInAfterTheListingIsRefused(t *testing.T) {
	swap := func(t *testing.T, path string) {
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
	t.Run("read", func(t *testing.T) {
		dir := t.TempDir()
		s := twoSegments(t, dir)
		swap(t, firstSegmentPath(dir))
		if event, err := nextNow(t, s); !errors.Is(err, ErrForeignFile) {
			t.Errorf("Next = %q, %v; want ErrForeignFile", event.GetEventId(), err)
		}
	})
	t.Run("append", func(t *testing.T) {
		dir := t.TempDir()
		seg, body := oneSegment(t, dir)
		s, err := openIn(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close() //nolint:errcheck // the assertions are below
		swap(t, seg)
		if err := s.Append(context.Background(), sample(2)); !errors.Is(err, ErrForeignFile) {
			t.Errorf("Append = %v, want ErrForeignFile", err)
		}
		if got := sizeOf(t, seg); got != int64(len(body)) {
			t.Errorf("the swapped file holds %d bytes, held %d", got, len(body))
		}
	})
}

// TestANewSegmentWhoseNameIsTakenIsRefused: a file put where the next segment
// will be created, after Open listed the directory, is refused by the create
// itself and left as it was.
func TestANewSegmentWhoseNameIsTakenIsRefused(t *testing.T) {
	dir := t.TempDir()
	s, err := openIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the assertions are below
	planted := firstSegmentPath(dir)
	if err := os.WriteFile(planted, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(context.Background(), sample(1)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Append = %v, want ErrCorrupt", err)
	}
	if body, err := os.ReadFile(planted); err != nil || string(body) != "planted" { //nolint:gosec // G304: the test's own file
		t.Errorf("the planted file holds %q: %v", body, err)
	}
}

// TestANewSegmentGivenASecondNameIsRemoved: a segment the spool just created
// and found with a second name is refused and its own name removed, so the
// next append creates it afresh rather than finding the name taken.
func TestANewSegmentGivenASecondNameIsRemoved(t *testing.T) {
	dir, other := t.TempDir(), filepath.Join(t.TempDir(), "other")
	linkOnce := true
	s, err := Open(Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16, openFile: func(root *os.Root, name string, flag int) (segmentFile, error) {
		f, err := openOSFile(root, name, flag)
		if err != nil || !linkOnce {
			return f, err
		}
		linkOnce = false
		if err := os.Link(filepath.Join(dir, name), other); err != nil {
			return nil, errors.Join(err, f.Close())
		}
		return f, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the assertions are below
	if err := s.Append(context.Background(), sample(1)); !errors.Is(err, ErrForeignFile) {
		t.Fatalf("Append = %v, want ErrForeignFile", err)
	}
	if _, err := os.Lstat(firstSegmentPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused segment's name is left: %v", err)
	}
	if err := s.Append(context.Background(), sample(1)); err != nil {
		t.Errorf("the append after the refusal: %v", err)
	}
}
