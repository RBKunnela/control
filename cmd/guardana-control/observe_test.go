package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// observeTree is a descriptor, a log directory and an input, each as an
// operator would leave them.
type observeTree struct{ source, log, input string }

func newObserveTree(t *testing.T) observeTree {
	t.Helper()
	dir := t.TempDir()
	tr := observeTree{source: filepath.Join(dir, "source.json"), log: filepath.Join(dir, "log"), input: filepath.Join(dir, "spans.jsonl")}
	copyFixture(t, "testdata/observe/descriptor.json", tr.source, 0o600)
	copyFixture(t, "testdata/observe/mixed_service.jsonl", tr.input, 0o600)
	if err := os.Mkdir(tr.log, 0o700); err != nil {
		t.Fatal(err)
	}
	return tr
}

func copyFixture(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	raw, err := os.ReadFile(from) //nolint:gosec // G304: a fixture under testdata
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, raw, mode); err != nil {
		t.Fatal(err)
	}
}

func (tr observeTree) importArgs() []string {
	return []string{"observe", "import", "--source", tr.source, "--log", tr.log, tr.input}
}

// counted reads one "name: n" line of import's output.
func counted(t *testing.T, stdout, name string) int {
	t.Helper()
	for _, line := range strings.Split(stdout, "\n") {
		if v, ok := strings.CutPrefix(line, name+": "); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			return n
		}
	}
	t.Fatalf("no %s line in %q", name, stdout)
	return 0
}

// TestObserveImportTwiceWritesOnce: an import writes the source's
// observations, and the same input again writes none and counts each as a
// duplicate; both exit 0.
func TestObserveImportTwiceWritesOnce(t *testing.T) {
	tr := newObserveTree(t)
	code, first, stderr := invoke(t, tr.importArgs()...)
	if code != exitOK || stderr != "" {
		t.Fatalf("first import: exit %d, stderr %q", code, stderr)
	}
	written := counted(t, first, "written")
	if written == 0 || written != counted(t, first, "observed") || counted(t, first, "duplicate") != 0 {
		t.Fatalf("first import printed %q", first)
	}
	if counted(t, first, "other_resource") == 0 {
		t.Errorf("the mixed-service input imported every resource: %q", first)
	}
	code, second, stderr := invoke(t, tr.importArgs()...)
	if code != exitOK || stderr != "" {
		t.Fatalf("second import: exit %d, stderr %q", code, stderr)
	}
	if counted(t, second, "written") != 0 || counted(t, second, "duplicate") != written {
		t.Errorf("second import printed %q, want %d duplicates and nothing written", second, written)
	}
}

// TestObserveExportReadsTheLog: the export of the log holds each written
// observation and both reports, and exits 0.
func TestObserveExportReadsTheLog(t *testing.T) {
	tr := newObserveTree(t)
	for range 2 {
		if code, _, stderr := invoke(t, tr.importArgs()...); code != exitOK {
			t.Fatalf("import: exit %d, stderr %q", code, stderr)
		}
	}
	_, first, _ := invoke(t, "observe", "import", "--source", tr.source, "--log", tr.log, tr.input)
	code, out, stderr := invoke(t, "observe", "export", filepath.Join(tr.log, "observations.jsonl"))
	if code != exitOK || stderr != "" {
		t.Fatalf("export: exit %d, stderr %q", code, stderr)
	}
	observations := strings.Count(out, `{"type":"observation",`)
	reports := strings.Count(out, `{"type":"import_report",`)
	if observations != counted(t, first, "duplicate") || reports != 3 {
		t.Errorf("export holds %d observations and %d reports, want %d and 3:\n%s", observations, reports, counted(t, first, "duplicate"), out)
	}
}

// TestObserveImportOfARefusedLineExitsOne: a line with a member OTLP does not
// name is refused, counted, and makes the import exit 1.
func TestObserveImportOfARefusedLineExitsOne(t *testing.T) {
	tr := newObserveTree(t)
	copyFixture(t, "testdata/observe/unknown_member.jsonl", tr.input, 0o600)
	code, out, stderr := invoke(t, tr.importArgs()...)
	if code != exitFail || counted(t, out, "refused") == 0 || !strings.Contains(stderr, "refused") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
}

// TestObserveImportOfAConflictExitsOne: a span already in the log with other
// content is not written, is counted as a conflict, and makes the import exit
// 1.
func TestObserveImportOfAConflictExitsOne(t *testing.T) {
	tr := newObserveTree(t)
	if code, _, stderr := invoke(t, tr.importArgs()...); code != exitOK {
		t.Fatalf("first import: exit %d, stderr %q", code, stderr)
	}
	raw, err := os.ReadFile(tr.input)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(raw), `"read_file"`, `"delete_file"`, 1)
	if changed == string(raw) {
		t.Fatal("the fixture names no read_file to change")
	}
	if err := os.WriteFile(tr.input, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := invoke(t, tr.importArgs()...)
	if code != exitFail || counted(t, out, "conflict") != 1 || !strings.Contains(stderr, "1 observation(s) conflicting") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
}

// TestObserveImportRefusesWhatItCannotTrust: a descriptor another account
// may write, a log directory others can reach, and a missing argument each
// exit 2 and write nothing.
func TestObserveImportRefusesWhatItCannotTrust(t *testing.T) {
	for name, spoil := range map[string]func(tr *observeTree) []string{
		"a group-writable descriptor": func(tr *observeTree) []string {
			chmod(t, tr.source, 0o620)
			return tr.importArgs()
		},
		"a log directory others can search": func(tr *observeTree) []string {
			chmod(t, tr.log, 0o711)
			return tr.importArgs()
		},
		"no --log": func(tr *observeTree) []string {
			return []string{"observe", "import", "--source", tr.source, tr.input}
		},
	} {
		tr := newObserveTree(t)
		code, out, stderr := invoke(t, spoil(&tr)...)
		if code != exitUsage || out != "" || stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, out, stderr)
		}
		if _, err := os.Stat(filepath.Join(tr.log, "observations.jsonl")); err == nil {
			t.Errorf("%s: the log was written", name)
		}
	}
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
