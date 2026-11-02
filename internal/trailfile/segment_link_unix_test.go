//go:build unix

package trailfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/coverage"
	"github.com/guardana/control/internal/segmentlog"
)

// TestASegmentReachedThroughALinkIsRefused: a sealed segment or the live
// file named through a link outside the log's directory is refused by the
// export and by the read, as the file itself is, so coverage gets no export
// it could take as whole; a link to a trail file outside any log still
// exports and reads.
func TestASegmentReachedThroughALinkIsRefused(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3), event(4))
	appendTo(t, l, event(5))
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"segment-00000002.jsonl", segmentlog.LiveName} {
		linkIsRefused(t, filepath.Join(dir, name), filepath.Join(base, "trail-"+name))
	}
	if _, err := ReadPath(filepath.Join(dir, "segment-00000002.jsonl"), DefaultMaxLines); !errors.Is(err, ErrSegmentFile) {
		t.Errorf("read of a segment by its path: %v, want ErrSegmentFile", err)
	}
	linkToATrailFileReads(t, filepath.Join(base, "trail.jsonl"))
}

// linkIsRefused checks a link at link to the segment file at target is
// refused by the export, writing nothing coverage reads, and by the read.
func linkIsRefused(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, err := ExportPath(link, Query{Limit: 1000}, &out)
	if !errors.Is(err, ErrSegmentFile) || out.Len() != 0 || !strings.Contains(err.Error(), "trail export") {
		t.Errorf("export of a link to %s: %v and %d bytes, want ErrSegmentFile naming trail export and nothing", target, err, out.Len())
	}
	if _, err := coverage.ReadExport(bytes.NewReader(out.Bytes())); err == nil {
		t.Errorf("coverage read what the refused export of a link to %s wrote", target)
	}
	if _, err := ReadPath(link, DefaultMaxLines); !errors.Is(err, ErrSegmentFile) {
		t.Errorf("read of a link to %s: %v, want ErrSegmentFile", target, err)
	}
}

// linkToATrailFileReads checks a link at link to a trail file outside any
// log exports as a whole trail and reads.
func linkToATrailFileReads(t *testing.T, link string) {
	t.Helper()
	alone := filepath.Join(t.TempDir(), "trail.jsonl")
	writeFile(t, alone, lines(t, event(1), event(2)))
	if err := os.Symlink(alone, link); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := ExportPath(link, Query{Limit: 1000}, &out); err != nil {
		t.Fatalf("export of a link to a trail file outside a log: %v", err)
	}
	if x, err := coverage.ReadExport(bytes.NewReader(out.Bytes())); err != nil || !x.Whole {
		t.Errorf("coverage of a link to a trail file outside a log: %v, whole %v", err, x != nil && x.Whole)
	}
	if rep, err := ReadPath(link, DefaultMaxLines); err != nil || len(rep.Trails) != 2 {
		t.Errorf("read of a link to a trail file outside a log: %v, %d trails, want 2", err, len(rep.Trails))
	}
}
