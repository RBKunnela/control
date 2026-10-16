package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const freshState = `{"schema_version":"1.1","dedup_scope":"consumer-window","cursor":"","source":"","alerts_bytes":0,` +
	`"tail_gap":null,"pending":[],"open":[],"window":[],"closed":[]}` + "\n"

// TestStateInit: -init makes the directory 0700 with a state that has read
// nothing and an empty alert log, both 0600, and -cursor prints an empty
// line until an export is read.
func TestStateInit(t *testing.T) {
	dir := newState(t)
	for name, want := range map[string]fs.FileMode{".": 0o700, "state.json": 0o600, "alerts.jsonl": 0o600, "lock": 0o600} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s has mode %04o, want %04o", name, info.Mode().Perm(), want)
		}
	}
	if got := stateOf(t, dir); got != freshState {
		t.Errorf("state.json after -init:\n%s\nwant:\n%s", got, freshState)
	}
	if got := alertLog(t, dir); got != "" {
		t.Errorf("alerts.jsonl after -init holds %q", got)
	}
	if got := report(t, "", "-state", dir, "-cursor"); got.code != 0 || got.stdout != "\n" || got.stderr != "" {
		t.Errorf("-cursor before any export: exit %d, stdout %q, stderr %q; want 0 and an empty line", got.code, got.stdout, got.stderr)
	}
	consume(t, dir, fixture(t, "repeat.jsonl"))
	if got := report(t, "", "-state", dir, "-cursor"); got.code != 0 || got.stdout != trailerOf(t, "repeat.jsonl")+"\n" {
		t.Errorf("-cursor after an export: exit %d, stdout %q; want the trailer's next_cursor", got.code, got.stdout)
	}
}

// TestStateInitRefuses: -init takes a directory that is absent or empty and
// no other, and leaves one it refused as it was.
func TestStateInitRefuses(t *testing.T) {
	dir := newState(t)
	before := stateOf(t, dir)
	if got := report(t, "", "-state", dir, "-init"); got.code != 2 || !strings.Contains(got.stderr, "not empty") {
		t.Errorf("-init over a state: exit %d, stderr %q; want 2, not empty", got.code, got.stderr)
	}
	if stateOf(t, dir) != before {
		t.Error("-init over a state changed it")
	}
	empty := filepath.Join(t.TempDir(), "e")
	if err := os.Mkdir(empty, 0o750); err != nil {
		t.Fatal(err)
	}
	if got := report(t, "", "-state", empty, "-init"); got.code != 0 {
		t.Errorf("-init in an empty directory: exit %d, stderr %q", got.code, got.stderr)
	}
	if info, err := os.Stat(empty); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("-init left an empty directory it took at %v (%v), want 0700", info.Mode().Perm(), err)
	}
	open := filepath.Join(t.TempDir(), "w")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	setMode(t, open, 0o770)
	if got := report(t, "", "-state", open, "-init"); got.code != 2 || !strings.Contains(got.stderr, "writable") {
		t.Errorf("-init in a group-writable directory: exit %d, stderr %q; want 2, writable", got.code, got.stderr)
	}
}

func TestStateUsage(t *testing.T) {
	dir := newState(t)
	for _, args := range [][]string{
		{"-init"}, {"-cursor"}, {"-state", ""}, {"-state", dir, "-init", "-cursor"}, {"-state", dir, "export.jsonl"}, {"-state"}, {"-follow"},
	} {
		got := report(t, fixture(t, "repeat.jsonl"), args...)
		if got.code != 2 || got.stdout != "" || !strings.Contains(got.stderr, "usage") {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want 2, nothing, a usage line", args, got.code, got.stdout, got.stderr)
		}
	}
	if stateOf(t, dir) != freshState {
		t.Error("a usage error changed the state")
	}
}

// refusal is a state and an input the state mode refuses, leaving the state
// directory's files as they were.
type refusal struct {
	name string
	// prepare brings the state to where the input meets it.
	prepare func(t *testing.T, dir string)
	in      func(t *testing.T) string
	stderr  string
}

func consumed(exports ...string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		for _, e := range exports {
			if got := consume(t, dir, fixture(t, e)); got.code == 2 {
				t.Fatalf("%s: exit 2: %s", e, got.stderr)
			}
		}
	}
}

func input(export string) func(*testing.T) string {
	return func(t *testing.T) string { t.Helper(); return fixture(t, export) }
}

// edited is the export with old replaced by with once, where it must be.
func edited(export, old, with string) func(*testing.T) string {
	return func(t *testing.T) string {
		t.Helper()
		in := fixture(t, export)
		if !strings.Contains(in, old) {
			t.Fatalf("%s holds no %q", export, old)
		}
		return strings.Replace(in, old, with, 1)
	}
}

// inTurn prepares a state with each of prepares in turn.
func inTurn(prepares ...func(*testing.T, string)) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		for _, p := range prepares {
			p(t, dir)
		}
	}
}

func editState(old, with string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		s := stateOf(t, dir)
		if !strings.Contains(s, old) {
			t.Fatalf("state.json holds no %q:\n%s", old, s)
		}
		writeIn(t, dir, "state.json", strings.Replace(s, old, with, 1))
	}
}

const (
	outageSource   = "0f31fcdcef01fd4eadcfc3afc5296240223172c978aa93a412205c25db73d1ec"
	conflictSource = "3cd4f852726ed6aa0ee7d0110a62da7f29c7ff501c8817107150332dfec020ab"
)

// ofAnotherFile is the committed export with its source and every cursor
// but query.after naming another file, so the export holds together and only
// the state can tell it is not the state's file.
func ofAnotherFile(export string) func(*testing.T) string {
	return func(t *testing.T) string {
		t.Helper()
		in := fixture(t, export)
		for _, member := range []string{`"source":"`, `"cursor":"v1:`, `"next_cursor":"v1:`} {
			if !strings.Contains(in, member+outageSource) {
				t.Fatalf("%s holds no %s of the outage source", export, member)
			}
			in = strings.ReplaceAll(in, member+outageSource, member+conflictSource)
		}
		return in
	}
}

func exportRefusals() []refusal {
	return []refusal{
		{name: "an empty stdin", in: func(*testing.T) string { return "" }, stderr: "the input is empty"},
		{name: "a cut export", in: func(t *testing.T) string {
			t.Helper()
			in := fixture(t, "repeat.jsonl")
			return in[:strings.LastIndex(strings.TrimSuffix(in, "\n"), "\n")+1]
		}, stderr: "no trailer"},
		{name: "the same export twice", prepare: consumed("repeat.jsonl"), in: input("repeat.jsonl"), stderr: "query.after"},
		{name: "an export after another cursor", prepare: consumed("outage-1.jsonl"), in: input("outage-3.jsonl"), stderr: "query.after"},
		{name: "a first export after a cursor", in: input("outage-2.jsonl"), stderr: "query.after"},
		{name: "another source", prepare: consumed("outage-1.jsonl"), in: ofAnotherFile("outage-2.jsonl"), stderr: "its source is not the state's"},
		{name: "a next cursor of another source", in: edited("outage-1.jsonl", `"next_cursor":"v1:`+outageSource, `"next_cursor":"v1:`+conflictSource),
			stderr: "next_cursor"},
		{name: "a filter", in: edited("outage-1.jsonl", `"query":{"limit":1000}`, `"query":{"limit":1000,"request":["A"]}`), stderr: "filter"},
		{name: "a kind filter", in: edited("outage-1.jsonl", `"query":{"limit":1000}`, `"query":{"limit":1000,"kind":["EVENT_KIND_ACTION_PROPOSED"]}`),
			stderr: "filter"},
		{name: "a refused record", in: edited("outage-1.jsonl", `{"type":"event","offset":305,`, `{"type":"event","extra":1,"offset":305,`),
			stderr: "refused"},
		{name: "another export format major", in: edited("outage-1.jsonl", `"version":"1.0"`, `"version":"2.0"`), stderr: "major"},
		{name: "a trailer naming no next cursor after events", in: func(t *testing.T) string {
			t.Helper()
			in := fixture(t, "outage-1.jsonl")
			cursor := `"next_cursor":"` + trailerOf(t, "outage-1.jsonl") + `",`
			if !strings.Contains(in, cursor) {
				t.Fatal("outage-1.jsonl's trailer names no next cursor")
			}
			return strings.Replace(in, cursor, "", 1)
		}, stderr: "next_cursor"},
		{name: "a next cursor behind the cursor the export starts after", prepare: consumed("outage-1.jsonl"), in: func(t *testing.T) string {
			t.Helper()
			return edited("outage-2.jsonl", `"next_cursor":"`+trailerOf(t, "outage-2.jsonl"), `"next_cursor":"`+cursorOf(t, "outage-1.jsonl", 305))(t)
		}, stderr: "behind"},
	}
}

func stateRefusals() []refusal {
	return []refusal{
		{name: "a state of another major", prepare: editState(`"schema_version":"1.1"`, `"schema_version":"2.0"`), in: input("outage-1.jsonl"),
			stderr: "schema_version"},
		{name: "a 1.1 state with a closed request of no mode member", prepare: inTurn(consumed("repeat.jsonl"),
			editState(`,"mode":"ENFORCEMENT_MODE_ENFORCE"`, ``)), in: input("outage-1.jsonl"), stderr: `member "mode" is missing`},
		{name: "a closed request of a mode this program does not write", prepare: inTurn(consumed("repeat.jsonl"),
			editState(`"mode":"ENFORCEMENT_MODE_ENFORCE"`, `"mode":"ENFORCEMENT_MODE_BOGUS"`)), in: input("outage-1.jsonl"),
			stderr: "a mode this program does not write"},
		{name: "a state with a member it does not name", prepare: editState(`"cursor":`, `"extra":1,"cursor":`), in: input("outage-1.jsonl"),
			stderr: "does not name"},
		{name: "a state without a member", prepare: editState(`"dedup_scope":"consumer-window",`, ``), in: input("outage-1.jsonl"),
			stderr: "dedup_scope"},
		{name: "a state with a member twice", prepare: editState(`"cursor":"",`, `"cursor":"","cursor":"",`), in: input("outage-1.jsonl"),
			stderr: "twice"},
		{name: "a state in another case", prepare: editState(`"cursor":`, `"Cursor":`), in: input("outage-1.jsonl"), stderr: "case"},
		{name: "a state of another dedup scope", prepare: editState(`"consumer-window"`, `"export"`), in: input("outage-1.jsonl"),
			stderr: "dedup_scope"},
		{name: "a nested member it does not name", prepare: chain2(consumed("outage-1.jsonl"), editState(`"walk":{`, `"walk":{"extra":1,`)),
			in: input("outage-2.jsonl"), stderr: "does not name"},
		{name: "a cursor of another source", prepare: chain2(consumed("outage-1.jsonl"), editState(`"source":"`+outageSource, `"source":"`+conflictSource)),
			in: input("outage-2.jsonl"), stderr: "source"},
		{name: "an alert log shorter than the state says", prepare: chain2(consumed("gaps.jsonl"), func(t *testing.T, dir string) {
			t.Helper()
			l := alertLog(t, dir)
			writeIn(t, dir, "alerts.jsonl", l[:len(l)-1])
		}), in: input("outage-1.jsonl"), stderr: "shorter"},
		{name: "an alert log line it cannot read past the checkpoint", prepare: func(t *testing.T, dir string) {
			t.Helper()
			writeIn(t, dir, "alerts.jsonl", `{"v":2,"alert":"evidence_gap","offset":1}`+"\n")
		}, in: input("outage-1.jsonl"), stderr: "alerts.jsonl"},
		{name: "a missing state", prepare: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Remove(filepath.Join(dir, "state.json")); err != nil {
				t.Fatal(err)
			}
		}, in: input("outage-1.jsonl"), stderr: "state.json"},
		{name: "a state that is a link", prepare: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Rename(filepath.Join(dir, "state.json"), filepath.Join(dir, "real.json")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real.json", filepath.Join(dir, "state.json")); err != nil {
				t.Fatal(err)
			}
		}, in: input("outage-1.jsonl"), stderr: "regular"},
		{name: "a group-writable directory", prepare: chmod(0o720), in: input("outage-1.jsonl"), stderr: "writable"},
		{name: "a world-writable directory", prepare: chmod(0o702), in: input("outage-1.jsonl"), stderr: "writable"},
		{name: "a group-readable directory", prepare: chmod(0o750), in: input("outage-1.jsonl"), stderr: "readable"},
		{name: "a world-readable directory", prepare: chmod(0o705), in: input("outage-1.jsonl"), stderr: "readable"},
		{name: "a group-writable state", prepare: fileMode("state.json", 0o620), in: input("outage-1.jsonl"), stderr: "writable"},
		{name: "a group-readable state", prepare: fileMode("state.json", 0o640), in: input("outage-1.jsonl"), stderr: "readable"},
		{name: "a world-readable alert log", prepare: fileMode("alerts.jsonl", 0o604), in: input("outage-1.jsonl"), stderr: "readable"},
		{name: "a missing lock file", prepare: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Remove(filepath.Join(dir, "lock")); err != nil {
				t.Fatal(err)
			}
		}, in: input("outage-1.jsonl"), stderr: "lock"},
		{name: "an ended request whose last event is not in the window",
			prepare: chain2(consumed("outage-1.jsonl"), editState(`"tail":"B3"`, `"tail":"B9"`)), in: input("outage-2.jsonl"), stderr: "window"},
	}
}

func fileMode(name string, mode fs.FileMode) func(*testing.T, string) {
	return func(t *testing.T, dir string) { t.Helper(); setMode(t, filepath.Join(dir, name), mode) }
}

func chain2(a, b func(*testing.T, string)) func(*testing.T, string) {
	return func(t *testing.T, dir string) { t.Helper(); a(t, dir); b(t, dir) }
}

func chmod(mode fs.FileMode) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		setMode(t, dir, mode)
		t.Cleanup(func() { setMode(t, dir, 0o700) })
	}
}

// setMode gives path a mode another user may write through, or the
// directory's own back, which the state mode has to refuse or take.
func setMode(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestStateRefusals: every refusal exits 2, prints no report and leaves the
// state and the alert log as they were.
func TestStateRefusals(t *testing.T) {
	for _, tc := range append(exportRefusals(), stateRefusals()...) {
		t.Run(tc.name, func(t *testing.T) {
			dir := newState(t)
			if tc.prepare != nil {
				tc.prepare(t, dir)
			}
			before := snapshot(t, dir)
			got := consume(t, dir, tc.in(t))
			if got.code != 2 || got.stdout != "" || !strings.Contains(got.stderr, tc.stderr) {
				t.Errorf("exit %d, stdout %q, stderr %q; want 2, nothing, %q", got.code, got.stdout, got.stderr, tc.stderr)
			}
			if after := snapshot(t, dir); after != before {
				t.Errorf("the refusal changed the state directory:\n%s\nwas:\n%s", after, before)
			}
		})
	}
}

// snapshot is every file of the state directory, its name, mode and bytes.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		body := ""
		if info.Mode().IsRegular() {
			body = readIn(t, dir, e.Name())
		}
		b.WriteString(e.Name() + " " + info.Mode().String() + "\n" + body + "\n")
	}
	return b.String()
}

// TestStateDirectoryOwner: a directory or file another user owns is refused,
// whatever its mode.
func TestStateDirectoryOwner(t *testing.T) {
	dir := newState(t)
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := judge(dir, info, true, os.Getuid()); err != nil {
		t.Fatalf("the test's own state directory is refused: %v", err)
	}
	err = judge(dir, info, true, os.Getuid()+1)
	if err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("a directory of another uid: %v, want refused as owned by another", err)
	}
}
