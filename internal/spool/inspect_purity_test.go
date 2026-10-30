//go:build unix

package spool_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/spool"
)

// pinnedTime is what every name under an inspected directory is dated before
// the inspection, so a write in the same clock tick as the fixture still
// moves a time.
var pinnedTime = time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)

// stateOf describes the directory and every name in it as the kernel does:
// type and permissions, size, modification time, link count and contents.
func stateOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"."}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("%s: the platform gives no link count", path)
		}
		line := fmt.Sprintf("%v size %d mtime %d links %d", info.Mode(), info.Size(), info.ModTime().UnixNano(), st.Nlink)
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's temp dir
			if err != nil {
				t.Fatal(err)
			}
			line += fmt.Sprintf(" sha256 %x", sha256.Sum256(raw))
		}
		out[name] = line
	}
	return out
}

// changes lists every name whose description differs between two states.
func changes(before, after map[string]string) []string {
	var out []string
	for name, was := range before {
		if now, ok := after[name]; !ok {
			out = append(out, fmt.Sprintf("%s: removed (was %s)", name, was))
		} else if now != was {
			out = append(out, fmt.Sprintf("%s: %s -> %s", name, was, now))
		}
	}
	for name, now := range after {
		if _, ok := before[name]; !ok {
			out = append(out, fmt.Sprintf("%s: created (%s)", name, now))
		}
	}
	slices.Sort(out)
	return out
}

// pinTimes dates the directory and every name in it at pinnedTime.
func pinTimes(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Chtimes(filepath.Join(dir, e.Name()), pinnedTime, pinnedTime); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(dir, pinnedTime, pinnedTime); err != nil {
		t.Fatal(err)
	}
}

// inspectUnchanged runs Inspect over opts.Dir and fails, printing what moved,
// unless the directory is as it was.
func inspectUnchanged(t *testing.T, opts spool.Options) (spool.Inspection, error) {
	t.Helper()
	pinTimes(t, opts.Dir)
	before := stateOf(t, opts.Dir)
	found, err := spool.Inspect(opts)
	if moved := changes(before, stateOf(t, opts.Dir)); len(moved) > 0 {
		t.Errorf("Inspect changed the directory it read:\n%s", joinLines(moved))
	}
	return found, err
}

func joinLines(lines []string) string {
	var out string
	for _, l := range lines {
		out += "  " + l + "\n"
	}
	return out
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: a file under the test's temp dir
	if err == nil {
		_, err = f.WriteString(s)
		err = errors.Join(err, f.Close())
	}
	if err != nil {
		t.Fatal(err)
	}
}

// TestInspectNamesTheTornTailsAndCutsNeither: a segment ending in five bytes
// no record holds and a quarantine ending in three are named, eight bytes in
// all, and left on disk; Open then cuts the same eight bytes, which the
// description of the directory shows, so the description can tell a cut.
func TestInspectNamesTheTornTailsAndCutsNeither(t *testing.T) {
	opts, events, raw := writeQuarantined(t, 2)
	segments := segmentNames(t, opts.Dir)
	if len(segments) != 1 {
		t.Fatalf("the fixture holds segments %v, want one", segments)
	}
	appendTo(t, filepath.Join(opts.Dir, segments[0]), "torn!")
	appendTo(t, filepath.Join(opts.Dir, quarantineFile), "tor")

	found, err := inspectUnchanged(t, opts)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	want := spool.Inspection{
		Segments:           1,
		Unacknowledged:     recordSize(t, events[0]) + recordSize(t, events[1]),
		QuarantinedRecords: 2,
		QuarantinedBytes:   int64(len(raw)),
		Torn:               8,
	}
	if found != want {
		t.Errorf("Inspect = %+v, want %+v", found, want)
	}

	before := stateOf(t, opts.Dir)
	s := open(t, opts)
	if got := stats(t, s).Truncated; got != 8 {
		t.Errorf("Open cut %d byte(s), want the 8 Inspect named", got)
	}
	if len(changes(before, stateOf(t, opts.Dir))) == 0 {
		t.Error("Open cut two tails and the description of the directory did not change")
	}
}

// TestInspectCountsALastSegmentWithNoRecordAsTorn: a last segment holding two
// bytes and no record is what Open removes; Inspect counts it out of the
// segments and its bytes as torn, and the file stays.
func TestInspectCountsALastSegmentWithNoRecordAsTorn(t *testing.T) {
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1}
	s, err := spool.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	first := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	second := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 2)
	mustAppend(t, s, first)
	mustAppend(t, s, second)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "00000000000000000003.seg")
	if err := os.WriteFile(empty, []byte("xx"), 0o600); err != nil {
		t.Fatal(err)
	}

	found, err := inspectUnchanged(t, opts)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	want := spool.Inspection{Segments: 2, Unacknowledged: recordSize(t, first) + recordSize(t, second), Torn: 2}
	if found != want {
		t.Errorf("Inspect = %+v, want %+v", found, want)
	}
	if _, err := os.Lstat(empty); err != nil {
		t.Errorf("the segment with no record is gone after Inspect: %v", err)
	}
}

// TestInspectWhileASpoolHoldsTheDirectory: a spool that holds the directory
// has an append in flight past its last record. Inspect says the directory is
// held, reads none of it, refuses nothing and changes nothing; once the
// holder closes, it reads the in-flight bytes as a torn tail.
func TestInspectWhileASpoolHoldsTheDirectory(t *testing.T) {
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16}
	s, err := spool.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1))
	segments := segmentNames(t, dir)
	appendTo(t, filepath.Join(dir, segments[0]), "in flight")

	found, err := inspectUnchanged(t, opts)
	if err != nil {
		t.Fatalf("Inspect of a held spool: %v", err)
	}
	if found != (spool.Inspection{Held: true}) {
		t.Errorf("Inspect of a held spool = %+v, want it held and read no further", found)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	found, err = inspectUnchanged(t, opts)
	if err != nil {
		t.Fatalf("Inspect after the holder closed: %v", err)
	}
	if found.Held || found.Torn != int64(len("in flight")) {
		t.Errorf("Inspect after the holder closed = %+v, want it free with %d torn byte(s)", found, len("in flight"))
	}
}

// TestInspectRefusesWhatOpenRefuses: options that make no log, a file that is
// not the spool's and a segment before the last that does not check are
// refused as Open refuses them, and nothing is changed.
func TestInspectRefusesWhatOpenRefuses(t *testing.T) {
	t.Run("options", func(t *testing.T) {
		opts := spool.Options{Dir: t.TempDir(), MaxBytes: 0, SegmentBytes: 1}
		if _, err := inspectUnchanged(t, opts); !errors.Is(err, spool.ErrInvalidOptions) {
			t.Errorf("Inspect = %v, want ErrInvalidOptions", err)
		}
	})
	t.Run("a foreign file", func(t *testing.T) {
		opts := spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1}
		writeFile(t, opts.Dir, "notes.txt", "not a segment")
		if _, err := inspectUnchanged(t, opts); !errors.Is(err, spool.ErrForeignFile) {
			t.Errorf("Inspect = %v, want ErrForeignFile", err)
		}
	})
	t.Run("damage before the last segment", func(t *testing.T) {
		dir := t.TempDir()
		opts := spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1}
		s, err := spool.Open(opts)
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1))
		mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 2))
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		appendTo(t, filepath.Join(dir, segmentNames(t, dir)[0]), "torn!")
		if _, err := inspectUnchanged(t, opts); !errors.Is(err, spool.ErrCorrupt) {
			t.Errorf("Inspect = %v, want ErrCorrupt", err)
		}
	})
}

// TestInspectRefusesATornTailItsOwnerMayNotWrite: a start cuts a torn tail
// through a descriptor opened to write, so a torn segment or quarantine its
// owner may not write is refused as the start would refuse it, and nothing is
// changed; the same file whole, with nothing to cut, is read.
func TestInspectRefusesATornTailItsOwnerMayNotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a file whatever its mode, so a start would cut it")
	}
	for _, name := range []string{"segment", "quarantine"} {
		t.Run(name, func(t *testing.T) {
			opts, _, _ := writeQuarantined(t, 1)
			path := filepath.Join(opts.Dir, quarantineFile)
			if name == "segment" {
				path = filepath.Join(opts.Dir, segmentNames(t, opts.Dir)[0])
			}
			if err := os.Chmod(path, 0o400); err != nil {
				t.Fatal(err)
			}
			if _, err := inspectUnchanged(t, opts); err != nil {
				t.Fatalf("Inspect of a whole %s its owner may not write: %v", name, err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			appendTo(t, path, "torn!")
			if err := os.Chmod(path, 0o400); err != nil {
				t.Fatal(err)
			}
			if _, err := inspectUnchanged(t, opts); !errors.Is(err, fs.ErrPermission) {
				t.Errorf("Inspect of a torn %s its owner may not write = %v, want fs.ErrPermission", name, err)
			}
			if s, err := spool.Open(opts); err == nil {
				_ = s.Close()
				t.Errorf("Open cut a torn %s its owner may not write, so the case is not one a start refuses", name)
			}
		})
	}
}
