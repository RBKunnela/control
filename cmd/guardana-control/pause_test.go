package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/pause"
)

// pauseDir is an empty directory of the pause file's own, and the path the
// file will take in it.
func pauseDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pause")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "pause.json")
}

// initialized is a pause file the init command made.
func initialized(t *testing.T) string {
	t.Helper()
	path := pauseDir(t)
	if code, _, stderr := invoke(t, "pause", "init", path); code != exitOK {
		t.Fatalf("pause init answered %d: %s", code, stderr)
	}
	return path
}

// fileBytes is the pause file as it stands, so a refusal can be shown to
// have written nothing.
func fileBytes(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// drawnID is what a drawn id looks like: rand.Text, 26 characters of the
// base32 alphabet.
var drawnID = regexp.MustCompile(`^[A-Z2-7]{26}$`)

// TestPauseCommandsWriteWhatTheyPrint: init makes a file that pauses nothing,
// add prints the id it drew and the file holds that entry under it with the
// scope the flags named, list prints every entry, and remove takes the id add
// printed.
func TestPauseCommandsWriteWhatTheyPrint(t *testing.T) {
	path := initialized(t)
	if code, stdout, _ := invoke(t, "pause", "list", path); code != exitOK || stdout != "no entries\n" {
		t.Fatalf("list of a new file answered %d: %q", code, stdout)
	}
	if doc, err := pause.List(path); err != nil || len(doc.Entries) != 0 {
		t.Fatalf("init wrote %+v, %v; want a readable file with no entry", doc, err)
	}

	for _, c := range []struct {
		args []string
		want pause.Scope
		list string
	}{
		{[]string{"--global"}, pause.Scope{Kind: "global"}, "global"},
		{[]string{"--provider", "orders"}, pause.Scope{Kind: "provider", Provider: "orders"}, "provider orders"},
		{[]string{"--action", "tool", "--provider", "orders", "--name", "refund"},
			pause.Scope{Kind: "action", Action: "tool", Provider: "orders", Name: "refund"}, "tool orders/refund"},
		{[]string{"--action", "prompt", "--provider", "orders"},
			pause.Scope{Kind: "action", Action: "prompt", Provider: "orders"}, "prompt orders"},
		{[]string{"--action", "resource", "--provider", "files"},
			pause.Scope{Kind: "action", Action: "resource", Provider: "files"}, "resource files"},
		{[]string{"--run", "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, pause.Scope{Kind: "run", ID: "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "run run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{[]string{"--agent", "orders-assistant"}, pause.Scope{Kind: "agent", ID: "orders-assistant"}, "agent orders-assistant"},
		{[]string{"--principal", "agent-runner"}, pause.Scope{Kind: "principal", ID: "agent-runner"}, "principal agent-runner"},
	} {
		expectAdded(t, path, c.args, c.want, c.list)
	}
	expectRemoved(t, path)
}

// expectAdded adds one entry with a reason and holds the id add printed to
// the entry the file then ends with and to the line list prints for it.
func expectAdded(t *testing.T, path string, flags []string, want pause.Scope, listed string) {
	t.Helper()
	args := append(append([]string{"pause", "add"}, flags...), "--reason", "deletes misbehave", path)
	code, stdout, stderr := invoke(t, args...)
	id := strings.TrimSuffix(stdout, "\n")
	if code != exitOK || !drawnID.MatchString(id) || stderr != "" {
		t.Fatalf("add %v answered %d with %q and %q; want the drawn id alone", flags, code, stdout, stderr)
	}
	doc, err := pause.List(path)
	if err != nil {
		t.Fatal(err)
	}
	last := doc.Entries[len(doc.Entries)-1]
	if last.ID != id || last.Scope != want || last.Reason != "deletes misbehave" {
		t.Errorf("add %v wrote %+v under %s, want %+v", flags, last, id, want)
	}
	_, list, _ := invoke(t, "pause", "list", path)
	if line := id + " " + listed + " created "; !strings.Contains(list, line) || !strings.Contains(list, `reason "deletes misbehave"`) {
		t.Errorf("list does not print %q with its reason:\n%s", line, list)
	}
}

// expectRemoved removes the file's first entry by the id add printed for it,
// and holds the file to every other entry, in order.
func expectRemoved(t *testing.T, path string) {
	t.Helper()
	doc, err := pause.List(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Entries[0].ID == doc.Entries[1].ID {
		t.Fatalf("two adds drew one id: %s", doc.Entries[0].ID)
	}
	code, stdout, stderr := invoke(t, "pause", "remove", path, doc.Entries[0].ID)
	if code != exitOK || stdout != "removed "+doc.Entries[0].ID+"\n" {
		t.Fatalf("remove answered %d with %q and %q", code, stdout, stderr)
	}
	after, err := pause.List(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(after.Entries, doc.Entries[1:], func(a, b pause.Entry) bool { return a.ID == b.ID }) {
		t.Errorf("remove left %+v, want every entry but the first", after.Entries)
	}
}

// TestPauseAddTakesExactlyOneScope: each line is refused as a usage error
// that writes nothing, beside the smallest change that is accepted, so a
// refusal that is not there, or one that refuses too much, shows.
func TestPauseAddTakesExactlyOneScope(t *testing.T) {
	for _, c := range []struct {
		name     string
		refused  []string
		accepted []string
	}{
		{"no scope", nil, []string{"--global"}},
		{"global and a provider", []string{"--global", "--provider", "orders"}, []string{"--provider", "orders"}},
		{"global and an action", []string{"--global", "--action", "tool", "--provider", "o", "--name", "n"}, []string{"--action", "tool", "--provider", "o", "--name", "n"}},
		{"global and a name", []string{"--global", "--name", "refund"}, []string{"--global"}},
		{"an action with no provider", []string{"--action", "resource"}, []string{"--action", "resource", "--provider", "files"}},
		{"a name with no action", []string{"--provider", "orders", "--name", "refund"}, []string{"--provider", "orders", "--action", "tool", "--name", "refund"}},
		{"a name alone", []string{"--name", "refund"}, []string{"--provider", "orders", "--action", "tool", "--name", "refund"}},
		{"an empty provider", []string{"--provider", ""}, []string{"--provider", "orders"}},
		{"a run and global", []string{"--run", "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--global"}, []string{"--run", "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{"an agent and a provider", []string{"--agent", "a", "--provider", "orders"}, []string{"--agent", "a"}},
		{"a principal and an action", []string{"--principal", "u", "--action", "tool", "--provider", "o", "--name", "n"}, []string{"--principal", "u"}},
		{"a run and a name", []string{"--run", "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--name", "refund"}, []string{"--run", "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{"a run and an agent", []string{"--run", "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--agent", "a"}, []string{"--agent", "a"}},
		{"an agent and a principal", []string{"--agent", "a", "--principal", "u"}, []string{"--principal", "u"}},
		{"an empty run", []string{"--run", ""}, []string{"--run", "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := initialized(t)
			before := fileBytes(t, path)
			code, stdout, stderr := invoke(t, append(append([]string{"pause", "add"}, c.refused...), path)...)
			line := oneStderrLine(t, stderr)
			if code != exitUsage || stdout != "" || !strings.HasPrefix(line, brand.CLI+": pause add: ") {
				t.Errorf("%v answered %d with %q on stdout and %q", c.refused, code, stdout, line)
			}
			if fileBytes(t, path) != before {
				t.Errorf("%v changed the pause file", c.refused)
			}
			if code, _, stderr := invoke(t, append(append([]string{"pause", "add"}, c.accepted...), path)...); code != exitOK {
				t.Errorf("%v answered %d: %s", c.accepted, code, stderr)
			}
		})
	}
}

// TestPauseAddCarriesEveryRefusalOfTheEntry: a scope or a reason the pause
// file cannot hold is refused as the input it is, on one line that never
// repeats the value, and writes nothing. Each sits beside the input the
// command takes.
func TestPauseAddCarriesEveryRefusalOfTheEntry(t *testing.T) {
	for _, c := range []struct {
		name     string
		refused  []string
		says     string
		accepted []string
	}{
		{"a tool with no name", []string{"--action", "tool", "--provider", "orders"}, "scope.name: empty",
			[]string{"--action", "tool", "--provider", "orders", "--name", "refund"}},
		{"a resource with a name", []string{"--action", "resource", "--provider", "files", "--name", "file:///etc"}, "resource is paused by its provider only",
			[]string{"--action", "resource", "--provider", "files"}},
		{"a prompt with a name", []string{"--action", "prompt", "--provider", "orders", "--name", "draft"}, "prompt is paused by its provider only",
			[]string{"--action", "prompt", "--provider", "orders"}},
		{"a kind that is none", []string{"--action", "method", "--provider", "orders", "--name", "x"}, "scope.action",
			[]string{"--action", "tool", "--provider", "orders", "--name", "x"}},
		{"a reason with a bidirectional override", []string{"--global", "--reason", "secret\u202esecond line"}, "control or format character",
			[]string{"--global", "--reason", "secret second line"}},
		{"a reason one byte over its bound", []string{"--global", "--reason", strings.Repeat("r", 513)}, "the bound is 512",
			[]string{"--global", "--reason", strings.Repeat("r", 512)}},
		{"a provider one byte over its bound", []string{"--provider", strings.Repeat("p", 257)}, "the bound is 256",
			[]string{"--provider", strings.Repeat("p", 256)}},
		{"a provider led by a space", []string{"--provider", " orders"}, "scope.provider",
			[]string{"--provider", "orders"}},
		{"a run id in upper case", []string{"--run", "RUN-" + strings.Repeat("A", 32)}, "a run is named by run- and 32 lower-case hex digits",
			[]string{"--run", "run-" + strings.Repeat("a", 32)}},
		{"a run led by a space", []string{"--run", " run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "scope.id",
			[]string{"--run", "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{"an agent one byte over its bound", []string{"--agent", strings.Repeat("a", 257)}, "the bound is 256",
			[]string{"--agent", strings.Repeat("a", 256)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := initialized(t)
			before := fileBytes(t, path)
			code, stdout, stderr := invoke(t, append(append([]string{"pause", "add"}, c.refused...), path)...)
			line := oneStderrLine(t, stderr)
			if code != exitFail || stdout != "" || !strings.HasPrefix(line, brand.CLI+": pause add: the entry: ") || !strings.Contains(line, c.says) {
				t.Errorf("%s answered %d with %q on stdout and %q; want 1 and a line saying %q", c.name, code, stdout, line, c.says)
			}
			if strings.Contains(line, "secret") || strings.Contains(line, "file:///etc") {
				t.Errorf("the refusal repeats the value it refused: %q", line)
			}
			if fileBytes(t, path) != before {
				t.Errorf("%s changed the pause file", c.name)
			}
			if code, _, stderr := invoke(t, append(append([]string{"pause", "add"}, c.accepted...), path)...); code != exitOK {
				t.Errorf("the accepted neighbour answered %d: %s", code, stderr)
			}
		})
	}
}

// TestPauseCommandsCarryEveryRefusalOfTheFile: what internal/pause refuses
// about the file reaches the operator as one line under the command's name,
// with the failure status, and a refused write changes nothing.
func TestPauseCommandsCarryEveryRefusalOfTheFile(t *testing.T) {
	t.Run("init over a file that exists", func(t *testing.T) {
		path := initialized(t)
		expectRefusal(t, "pause init", "exists already", "pause", "init", path)
	})
	t.Run("init in a directory others may write", func(t *testing.T) {
		path := pauseDir(t)
		if err := os.Chmod(filepath.Dir(path), 0o770); err != nil { //nolint:gosec // G302: the directory mode init must refuse
			t.Fatal(err)
		}
		expectRefusal(t, "pause init", "directory", "pause", "init", path)
		if err := os.Chmod(filepath.Dir(path), 0o700); err != nil { //nolint:gosec // G302: a directory's owner-only mode, which init takes
			t.Fatal(err)
		}
		if code, _, stderr := invoke(t, "pause", "init", path); code != exitOK {
			t.Errorf("init in a directory only its owner writes answered %d: %s", code, stderr)
		}
	})
	t.Run("add to a file nobody made", func(t *testing.T) {
		expectRefusal(t, "pause add", "does not exist", "pause", "add", "--global", pauseDir(t))
	})
	t.Run("add to a file others may write", func(t *testing.T) {
		path := initialized(t)
		if err := os.Chmod(path, 0o602); err != nil { //nolint:gosec // G302: the file mode add must refuse
			t.Fatal(err)
		}
		before := fileBytes(t, path)
		expectRefusal(t, "pause add", "group or others may write", "pause", "add", "--global", path)
		if fileBytes(t, path) != before {
			t.Error("a refused add rewrote the file")
		}
	})
	t.Run("remove an id the file does not hold", func(t *testing.T) {
		path := initialized(t)
		_, stdout, _ := invoke(t, "pause", "add", "--global", path)
		before := fileBytes(t, path)
		expectRefusal(t, "pause remove", "no entry with this id", "pause", "remove", path, "NOT"+strings.TrimSuffix(stdout, "\n"))
		if fileBytes(t, path) != before {
			t.Error("a refused remove rewrote the file")
		}
	})
	t.Run("list a malformed file", func(t *testing.T) {
		path := initialized(t)
		if err := os.WriteFile(path, []byte(`{"schema_version":"1","entries":[],"x":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		expectRefusal(t, "pause list", "a plane reading this file blocks every call", "pause", "list", path)
	})
}

func expectRefusal(t *testing.T, command, says string, args ...string) {
	t.Helper()
	code, stdout, stderr := invoke(t, args...)
	line := oneStderrLine(t, stderr)
	if code != exitFail || stdout != "" || !strings.HasPrefix(line, brand.CLI+": "+command+": ") || !strings.Contains(line, says) {
		t.Errorf("%v answered %d with %q on stdout and %q; want 1 and a line saying %q", args, code, stdout, line, says)
	}
}

// TestPauseRemoveTakesTwoArguments: the file and the id, no more and no fewer.
func TestPauseRemoveTakesTwoArguments(t *testing.T) {
	path := initialized(t)
	for _, args := range [][]string{{path}, {path, "P1", "P2"}, {"--id", "P1", path}} {
		code, stdout, stderr := invoke(t, append([]string{"pause", "remove"}, args...)...)
		if code != exitUsage || stdout != "" || stderr == "" {
			t.Errorf("remove %v answered %d with %q and %q; want the usage status", args, code, stdout, stderr)
		}
	}
}
