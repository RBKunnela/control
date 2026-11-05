package pause_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/guardana/control/internal/pause"
)

const interval = time.Second

func at() time.Time { return time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC) }

// dirWith makes a directory of mode 0700 holding the pause file with body at
// mode perm, and returns the file's path.
func dirWith(t *testing.T, body string, perm os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pause")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pause.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadServesWhatTheFileSays(t *testing.T) {
	empty := pause.Read(dirWith(t, docJSON(), 0o600), at(), interval)
	if empty.State() != pause.Clear || empty.Cause() != "" || len(empty.Entries()) != 0 {
		t.Errorf("an empty list: state %s, cause %q, entries %v; want clear", empty.State(), empty.Cause(), empty.Entries())
	}
	paused := pause.Read(dirWith(t, docJSON(entryJSON("a", toolScope, "")), 0o644), at(), interval)
	if paused.State() != pause.Paused || len(paused.Entries()) != 1 || !paused.ReadAt().Equal(at()) {
		t.Fatalf("one entry: state %s, entries %v, read at %v", paused.State(), paused.Entries(), paused.ReadAt())
	}
	if !paused.Covers("tool", "orders", "refund", pause.Vouched{}) || paused.Covers("tool", "orders", "list", pause.Vouched{}) {
		t.Errorf("a tool pause covers the wrong calls")
	}
	// Entries is a copy: nothing a caller does to it reaches the snapshot.
	paused.Entries()[0].Scope = pause.Scope{Kind: "global"}
	if paused.Covers("tool", "orders", "list", pause.Vouched{}) {
		t.Errorf("a change to the copy Entries returned widened the snapshot")
	}
}

// TestEveryUnreadableFileIsUnknownWithItsCause: one case per cause. Each file
// differs from one that reads as clear in the one respect its case names.
func TestEveryUnreadableFileIsUnknownWithItsCause(t *testing.T) {
	valid := docJSON(entryJSON("a", globalScope, ""))
	cases := []struct {
		name  string
		path  func(t *testing.T) string
		cause pause.Cause
	}{
		{"missing", func(t *testing.T) string { return filepath.Join(t.TempDir(), "none.json") }, pause.CauseMissing},
		{"missing directory", func(t *testing.T) string { return filepath.Join(t.TempDir(), "no", "pause.json") }, pause.CauseMissing},
		{"group writable 0620", func(t *testing.T) string { return dirWith(t, valid, 0o620) }, pause.CauseFileMode},
		{"others writable 0602", func(t *testing.T) string { return dirWith(t, valid, 0o602) }, pause.CauseFileMode},
		{"a link", func(t *testing.T) string {
			path := dirWith(t, valid, 0o600)
			link := filepath.Join(filepath.Dir(path), "link.json")
			if err := os.Symlink(path, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, pause.CauseLink},
		{"a directory 0770", func(t *testing.T) string {
			path := dirWith(t, valid, 0o600)
			if err := os.Chmod(filepath.Dir(path), 0o770); err != nil { //nolint:gosec // G302: the mode under test
				t.Fatal(err)
			}
			return path
		}, pause.CauseDirMode},
		{"a directory 0702", func(t *testing.T) string {
			path := dirWith(t, valid, 0o600)
			if err := os.Chmod(filepath.Dir(path), 0o702); err != nil { //nolint:gosec // G302: the mode under test
				t.Fatal(err)
			}
			return path
		}, pause.CauseDirMode},
		{"not a regular file", func(t *testing.T) string {
			dir := filepath.Join(t.TempDir(), "d")
			if err := os.MkdirAll(filepath.Join(dir, "pause.json"), 0o700); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "pause.json")
		}, pause.CauseUnreadable},
		{"one byte over the bound", func(t *testing.T) string {
			return dirWith(t, valid+strings.Repeat(" ", 163840-len(valid)+1), 0o600)
		}, pause.CauseTooLarge},
		{"malformed", func(t *testing.T) string { return dirWith(t, valid[:len(valid)-1], 0o600) }, pause.CauseMalformed},
		{"an unknown version", func(t *testing.T) string { return dirWith(t, strings.Replace(valid, `"2"`, `"3"`, 1), 0o600) }, pause.CauseVersion},
		{"a version 0 file", func(t *testing.T) string { return dirWith(t, strings.Replace(valid, `"2"`, `"0"`, 1), 0o600) }, pause.CauseVersion},
		{"an unknown member", func(t *testing.T) string {
			return dirWith(t, strings.Replace(valid, `"entries"`, `"extra":0,"entries"`, 1), 0o600)
		}, pause.CauseMalformed},
		{"an unknown scope", func(t *testing.T) string {
			return dirWith(t, docJSON(entryJSON("a", `{"kind":"tenant","id":"t"}`, "")), 0o600)
		}, pause.CauseMalformed},
		{"a resource scope with a name", func(t *testing.T) string {
			return dirWith(t, docJSON(entryJSON("a", `{"kind":"action","action":"resource","provider":"files","name":"file:///x"}`, "")), 0o600)
		}, pause.CauseMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := pause.Read(c.path(t), at(), interval)
			if s.State() != pause.Unknown || s.Cause() != c.cause {
				t.Errorf("state %s, cause %q, detail %q; want unknown, %q", s.State(), s.Cause(), s.Detail(), c.cause)
			}
			if s.Covers("tool", "orders", "refund", pause.Vouched{}) || len(s.Entries()) != 0 {
				t.Errorf("an unknown snapshot holds entries")
			}
		})
	}
	// The same file at the bound and within every mode rule reads.
	if s := pause.Read(dirWith(t, valid+strings.Repeat(" ", 163840-len(valid)), 0o644), at(), interval); s.State() != pause.Paused {
		t.Errorf("a file of exactly the bound: state %s, cause %q", s.State(), s.Cause())
	}
}

// TestASnapshotAnswersForThreeIntervals: at three intervals it stands, one
// tick later it is stale, and one read after the clock is dated ahead.
func TestASnapshotAnswersForThreeIntervals(t *testing.T) {
	s := pause.Read(dirWith(t, docJSON(entryJSON("a", globalScope, "")), 0o600), at(), interval)
	cases := []struct {
		now   time.Time
		state pause.State
		cause pause.Cause
	}{
		{at(), pause.Paused, ""},
		{at().Add(3 * time.Second), pause.Paused, ""},
		{at().Add(3*time.Second + time.Nanosecond), pause.Unknown, pause.CauseStale},
		{at().Add(-time.Nanosecond), pause.Unknown, pause.CauseAhead},
	}
	for _, c := range cases {
		got := s.At(c.now)
		if got.State() != c.state || got.Cause() != c.cause {
			t.Errorf("At(%v): state %s, cause %q; want %s, %q", c.now, got.State(), got.Cause(), c.state, c.cause)
		}
		if got.State() == pause.Unknown && got.Covers("tool", "orders", "refund", pause.Vouched{}) {
			t.Errorf("At(%v): a stale snapshot still covers a call", c.now)
		}
	}
	empty := pause.Read(dirWith(t, docJSON(), 0o600), at(), interval)
	if got := empty.At(at().Add(time.Hour)); got.State() != pause.Unknown || got.Cause() != pause.CauseStale {
		t.Errorf("a clear snapshot an hour old: %s, %q; want unknown, stale", got.State(), got.Cause())
	}
	if got := pause.DisabledSnapshot().At(at().Add(time.Hour)); got.State() != pause.Disabled {
		t.Errorf("a disabled plane went %s with age", got.State())
	}
}

// TestTheZeroSnapshotIsUnknown: a snapshot nobody read is not a clear one.
func TestTheZeroSnapshotIsUnknown(t *testing.T) {
	var s pause.Snapshot
	if s.State() != pause.Unknown || s.Cause() != pause.CauseNeverRead {
		t.Errorf("the zero snapshot: %s, %q; want unknown, never read", s.State(), s.Cause())
	}
	if got := s.At(at()); got.State() != pause.Unknown {
		t.Errorf("the zero snapshot at a time: %s", got.State())
	}
	var p *pause.Poller
	if got := p.Current(); got.State() != pause.Unknown {
		t.Errorf("a nil poller serves %s", got.State())
	}
	for state, name := range map[pause.State]string{pause.Unknown: "unknown", pause.Disabled: "disabled", pause.Clear: "clear", pause.Paused: "paused"} {
		if state.String() != name {
			t.Errorf("state %d prints %q, want %q", state, state.String(), name)
		}
	}
}

// TestADetailIsBounded: whatever the refusal says, the snapshot quotes at
// most 256 bytes of it, cut at a character boundary.
func TestADetailIsBounded(t *testing.T) {
	for _, fill := range []string{"v", "é"} {
		version := strings.Repeat(fill, 30<<10)
		s := pause.Read(dirWith(t, `{"schema_version":"`+version+`","entries":[]}`, 0o600), at(), interval)
		if s.State() != pause.Unknown || s.Cause() != pause.CauseVersion {
			t.Fatalf("state %s, cause %q", s.State(), s.Cause())
		}
		if d := s.Detail(); len(d) > 256+len("...") || !utf8.ValidString(d) || !strings.HasSuffix(d, "...") {
			t.Errorf("the detail is %d bytes, valid %v: %q", len(d), utf8.ValidString(d), d)
		}
	}
}
