package trailfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/coverage"
	"github.com/guardana/control/internal/segmentlog"
)

// exportOf is the export of the log in dir from its start, framed and as
// coverage reads it.
func exportOf(t *testing.T, dir string) (record, *coverage.Export) {
	t.Helper()
	var out bytes.Buffer
	if _, err := ExportLog(dir, Query{Limit: 1000}, &out); err != nil {
		t.Fatal(err)
	}
	header, _, _ := frame(t, out.String())
	x, err := coverage.ReadExport(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("coverage refuses the export: %v", err)
	}
	return header, x
}

// TestAnExportAfterAPruneCountsWhatIsGone: the export of the first segment
// left after a prune, read to the log's end, names in its header the segments
// pruned before it, and coverage does not take it as whole; the same log before the prune, exported
// to its end, names none and is whole.
func TestAnExportAfterAPruneCountsWhatIsGone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3))
	if err := l.rl.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	h, x := exportOf(t, dir)
	if h.Version != "1.1" || h.Pruned == nil || *h.Pruned != 1 || filepath.Base(h.File) != "segment-00000002.jsonl" {
		t.Fatalf("after pruning one segment the header is %+v", h)
	}
	if x.Whole || !strings.Contains(x.NotWhole, "pruned") {
		t.Errorf("coverage takes the export after a prune as whole %v (%q)", x.Whole, x.NotWhole)
	}

	whole := filepath.Join(t.TempDir(), "log")
	w := openTestLog(t, logConfig(whole))
	appendTo(t, w, event(1), event(2))
	h, x = exportOf(t, whole)
	if h.Pruned == nil || *h.Pruned != 0 || !x.Whole {
		t.Errorf("a log with nothing pruned: pruned_before %v, whole %v (%q); want 0 and whole", h.Pruned, x.Whole, x.NotWhole)
	}
}

// TestAFilesExportCountsNothingPruned: a single file's export names 0.
func TestAFilesExportCountsNothingPruned(t *testing.T) {
	e := runExport(t, file(lineE1, lineE2), false, query())
	if e.header.Version != "1.1" || e.header.Pruned == nil || *e.header.Pruned != 0 {
		t.Errorf("a file's header is %+v, want version 1.1 and pruned_before 0", e.header)
	}
}

// dropTombstones edits the manifest of the closed log in dir as seals at the
// cap leave it once they dropped its first n entries, each a tombstone.
func dropTombstones(t *testing.T, dir string, n int) {
	t.Helper()
	path := filepath.Join(dir, segmentlog.ManifestName)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	m := string(raw)
	first, next := strings.Index(m, `{"seq":1,`), strings.Index(m, fmt.Sprintf(`{"seq":%d,`, n+1))
	if first < 0 || next < first || strings.Contains(m[first:next], `"state":"sealed"`) || !strings.Contains(m, `"dropped":0,`) {
		t.Fatalf("the manifest does not begin with %d tombstones: %s", n, m)
	}
	m = strings.Replace(m[:first]+m[next:], `"dropped":0,`, fmt.Sprintf(`"dropped":%d,`, n), 1)
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAnExportPastDroppedTombstonesCountsThem: the export of the first
// segment left after two were pruned and their tombstones dropped, which the
// manifest then names only by its count, counts both in pruned_before, and
// coverage does not take it as whole.
func TestAnExportPastDroppedTombstonesCountsThem(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3), event(4))
	appendTo(t, l, event(5))
	if err := l.rl.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(l.Prune(2), l.Close()); err != nil {
		t.Fatal(err)
	}
	dropTombstones(t, dir, 2)
	h, x := exportOf(t, dir)
	if h.Pruned == nil || *h.Pruned != 2 || filepath.Base(h.File) != "segment-00000003.jsonl" {
		t.Fatalf("past two dropped tombstones the header is %+v, want pruned_before 2 of segment 3", h)
	}
	if x.Whole {
		t.Errorf("coverage takes the export past dropped tombstones as whole")
	}
}

// TestASegmentFileIsNotExportedAsATrailFile: a sealed or the live segment
// exported by its file's path is refused, naming the directory to export, so
// coverage gets no export to take as whole; the same bytes outside a log are
// a trail file, whose export coverage takes as whole.
func TestASegmentFileIsNotExportedAsATrailFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3), event(4))
	appendTo(t, l, event(5))
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	segment := filepath.Join(dir, "segment-00000002.jsonl")
	for _, path := range []string{segment, filepath.Join(dir, segmentlog.LiveName)} {
		var out bytes.Buffer
		_, err := ExportPath(path, Query{Limit: 1000}, &out)
		if !errors.Is(err, ErrSegmentFile) || out.Len() != 0 || !strings.Contains(err.Error(), "trail export") {
			t.Errorf("%s exported by its path: %v and %d bytes, want ErrSegmentFile naming trail export and nothing", path, err, out.Len())
		}
		if _, err := coverage.ReadExport(bytes.NewReader(out.Bytes())); err == nil {
			t.Errorf("coverage read what the refused export of %s wrote", path)
		}
	}
	exportsWholeAlone(t, segment)
}

// exportsWholeAlone checks the bytes of the file at path, copied outside any
// log, export as a trail file coverage takes as whole.
func exportsWholeAlone(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	alone := filepath.Join(t.TempDir(), "trail.jsonl")
	if err := os.WriteFile(alone, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := ExportPath(alone, Query{Limit: 1000}, &out); err != nil {
		t.Fatalf("the same bytes outside a log: %v", err)
	}
	if x, err := coverage.ReadExport(bytes.NewReader(out.Bytes())); err != nil || !x.Whole {
		t.Errorf("coverage of the same bytes outside a log: %v, whole %v", err, x != nil && x.Whole)
	}
}
