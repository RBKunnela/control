package segmentlog

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// snapshot is every name in dir with its bytes, mode and modification time.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range dirNames(t, dir) {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = info.Mode().String() + " " + info.ModTime().Format(time.RFC3339Nano) + " " + fileText(t, filepath.Join(dir, name))
	}
	return out
}

// TestAViewChangesNothingAndAnswersAsTheLog: an inspection of a log a writer
// holds, a torn last line in its live segment included, leaves every name as
// it was, and locates each segment as the writer does.
func TestAViewChangesNothingAndAnswersAsTheLog(t *testing.T) {
	cfg := config(logDir(t), 8, 64)
	l := openLog(t, cfg)
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc", "ddd")
	mustAppend(t, l, "eee")
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(cfg.Dir, LiveName), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("ff"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	before := snapshot(t, cfg.Dir)
	v, err := Inspect(cfg.Dir, cfg.MaxLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	answersAsTheLog(t, v, l)
	if after := snapshot(t, cfg.Dir); !mapsEqual(before, after) {
		t.Errorf("the view changed the directory:\n%v\nwas\n%v", after, before)
	}
}

// locatesAsTheLog checks the view of l locates each of its segments as l
// does, and one it does not have as Unknown.
func locatesAsTheLog(t *testing.T, v *View, l *segments) {
	t.Helper()
	for seq, line := range map[int]string{1: "aaa", 2: "ccc", 3: "eee", 4: "zzz"} {
		got, want := v.Locate(key(seq, line)).State(), l.Locate(key(seq, line)).State()
		if got != want || (got == StateUnknown) != (seq == 4) {
			t.Errorf("the view locates %s of %d as %v, the log as %v", line, seq, got, want)
		}
	}
}

// answersAsTheLog checks the view of l locates, counts and opens as l does.
func answersAsTheLog(t *testing.T, v *View, l *segments) {
	t.Helper()
	if held, err := v.Held(); err != nil || !held {
		t.Errorf("Held = %v, %v while the writer holds the directory", held, err)
	}
	locatesAsTheLog(t, v, l)
	if m := v.Manifest(); m.Retained != 12 || m.Live.Lines != 1 || v.Tail() != 2 {
		t.Errorf("the view: %+v, tail %d", m, v.Tail())
	}
	sealed := v.Locate(key(2, "ccc")).Segment()
	sf, size, err := v.Open(sealed)
	if err != nil || size != 8 {
		t.Fatalf("opening the sealed segment: %d, %v", size, err)
	}
	_ = sf.Close()
	if _, _, err := v.Open(v.Locate(key(1, "aaa")).Segment()); !errors.Is(err, ErrPrune) {
		t.Errorf("opening a pruned segment: %v", err)
	}
}

// TestASealedSegmentChangedInPlaceIsRefusedToAReader: a sealed segment
// whose bytes changed at its own length opens for no reader.
func TestASealedSegmentChangedInPlaceIsRefusedToAReader(t *testing.T) {
	cfg := sealedLog(t)
	v, err := Inspect(cfg.Dir, cfg.MaxLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	sealed := v.Locate(key(1, "aaa")).Segment()
	f, _, err := v.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	writeIn(t, cfg.Dir, "segment-00000001.jsonl", "aaa\nbbc\n")
	if _, _, err := v.Open(sealed); !errors.Is(err, ErrManifest) {
		t.Errorf("a sealed segment changed in place opened as %v, want ErrManifest", err)
	}
}

// TestAViewNeedsAManifest: a directory that is not there, and one with no
// manifest, are no log to inspect.
func TestAViewNeedsAManifest(t *testing.T) {
	if _, err := Inspect(filepath.Join(t.TempDir(), "absent"), 64); err == nil {
		t.Error("a directory that is not there was inspected")
	}
	if _, err := Inspect(t.TempDir(), 64); !errors.Is(err, ErrManifest) {
		t.Errorf("a directory with no manifest: %v", err)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestASegmentSealedOrPrunedUnderAReaderIsReadFromItsDescriptor: a segment a
// reader opened is read whole after a seal renames it and after a prune
// unlinks it; a view taken before the seal opens the live segment as moved.
func TestASegmentSealedOrPrunedUnderAReaderIsReadFromItsDescriptor(t *testing.T) {
	cfg := config(logDir(t), 8, 64)
	l := openLog(t, cfg)
	mustAppend(t, l, "aaa", "bbb")
	v, err := Inspect(cfg.Dir, cfg.MaxLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	live := v.Manifest().Live
	f, size, err := v.Open(live)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := l.Seal(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Open(live); !errors.Is(err, ErrMoved) {
		t.Errorf("the live segment a seal renamed opened as %v, want ErrMoved", err)
	}
	mustAppend(t, l, "ccc")
	if _, _, err := v.Open(live); !errors.Is(err, ErrMoved) {
		t.Errorf("a new live segment opened under the old one's view: %v, want ErrMoved", err)
	}
	mustAppend(t, l, "ddd", "eee")
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.NewSectionReader(f, 0, size))
	if err != nil || string(raw) != "aaa\nbbb\n" {
		t.Errorf("read through the descriptor after a seal and a prune: %q, %v", raw, err)
	}
	if got := dirNames(t, cfg.Dir); slices.Contains(got, "segment-00000001.jsonl") {
		t.Errorf("the pruned segment is still named: %v", got)
	}
}

// TestALiveSegmentSealedAtTheCapUnderAViewIsMoved: a seal at the cap drops
// one entry and adds one, so the manifest names as many entries as the view
// did; the live segment opened after it, beginning with the line the view's
// began with, is still moved. Before the seal the view opens it.
func TestALiveSegmentSealedAtTheCapUnderAViewIsMoved(t *testing.T) {
	cfg := config(logDir(t), 8, 64)
	l := openLog(t, cfg)
	l.most = 3
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc", "ddd")
	mustAppend(t, l, "eee", "fff")
	mustAppend(t, l, "ggg", "hhh")
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	v, err := Inspect(cfg.Dir, cfg.MaxLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	live := v.Manifest().Live
	f, _, err := v.Open(live)
	if err != nil {
		t.Fatalf("the live segment under its own view: %v", err)
	}
	_ = f.Close()
	mustAppend(t, l, "ggg")
	if m := l.Manifest(); m.Dropped != 1 || len(m.Segments) != 3 || m.Live.First != sum("ggg") {
		t.Fatalf("want a seal at the cap and a live segment beginning with ggg, got %+v", m)
	}
	if _, _, err := v.Open(live); !errors.Is(err, ErrMoved) {
		t.Errorf("the live segment after a seal at the cap opened under the old view: %v, want ErrMoved", err)
	}
}

// TestALiveFileBetweenASealsManifestAndItsRenameIsMoved: once a seal named
// the live segment sealed and before it renamed the file, live.jsonl holds
// the sealed segment's bytes. A view read then still reads the manifest, as a
// prune that completes the seal must, but its live file opens as moved rather
// than as the next live segment; so does that of a view read before the seal.
// The log opened again completes the seal.
func TestALiveFileBetweenASealsManifestAndItsRenameIsMoved(t *testing.T) {
	cfg := config(logDir(t), 64, 256)
	l, _ := crashOpen(t, cfg, 1<<30)
	mustAppend(t, l, "aaa", "bbb")
	before, err := Inspect(cfg.Dir, cfg.MaxLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	c := &crashing{at: 2}
	l.ops = c.ops()
	if err := l.Seal(); !errors.Is(err, errCrash) {
		t.Fatalf("a seal stopped at its rename: %v", err)
	}
	during, err := Inspect(cfg.Dir, cfg.MaxLineBytes)
	if err != nil {
		t.Fatalf("a view of the manifest between the manifest and the rename: %v", err)
	}
	if m := during.Manifest(); len(m.Segments) != 1 || m.Segments[0].State != StateSealed {
		t.Errorf("the view between the manifest and the rename names %+v, want segment 1 sealed", m)
	}
	if _, _, err := during.Open(during.Manifest().Live); !errors.Is(err, ErrMoved) {
		t.Errorf("its live file opened: %v, want ErrMoved", err)
	}
	if _, _, err := before.Open(before.Manifest().Live); !errors.Is(err, ErrMoved) {
		t.Errorf("the live segment of a view read before the seal, opened in its window: %v, want ErrMoved", err)
	}
	_ = l.release()
	_, l = recovered(t, cfg)
	_ = l.Close()
	v, err := Inspect(cfg.Dir, cfg.MaxLineBytes)
	if err != nil || len(v.Manifest().Segments) != 1 || v.Manifest().Live.Lines != 0 {
		t.Errorf("after the seal was completed the view is %v, %v; want one sealed segment and none live", err, v)
	}
}
