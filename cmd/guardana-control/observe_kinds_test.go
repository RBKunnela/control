package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The egress importer's own fixtures: an Envoy forward proxy's access log of
// four lines, three connections, one of them a plain HTTP request whose
// authority names no port, and one line whose port its authority
// contradicts, and its independent descriptor.
const (
	envoyLog        = "../../internal/ingest/egresslog/testdata/envoy.jsonl"
	envoyDescriptor = "../../internal/ingest/egresslog/testdata/envoy.descriptor.json"
)

// TestObserveImportOfSpansPrintsWhatItDid: the OTel import's lines are the
// ones it printed before imports were dispatched by kind.
func TestObserveImportOfSpansPrintsWhatItDid(t *testing.T) {
	tr := newObserveTree(t)
	code, stdout, stderr := invoke(t, tr.importArgs()...)
	const want = "spans_read: 10\nobserved: 4\nwritten: 4\nduplicate: 0\nconflict: 0\nother_resource: 3\nrefused: 0\n" +
		"content_attributes_dropped: 4\nreasoning_parts_dropped: 0\ncontent_unparsed: 0\nrun_ids_dropped: 0\nstrings_dropped: 0\nskipped: 3\n"
	if code != exitOK || stderr != "" || stdout != want {
		t.Fatalf("exit %d, stderr %q, stdout\n%s\nwant 0 and\n%s", code, stderr, stdout, want)
	}
}

// egressTree is newObserveTree with the Envoy descriptor, its trust set to
// trust, and the Envoy log at mode: the input already exists, and the umask
// would narrow a new file's mode, so the mode is set after the copy.
func egressTree(t *testing.T, trust string, mode os.FileMode) observeTree {
	t.Helper()
	tr := newObserveTree(t)
	raw, err := os.ReadFile(envoyDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, tr.source, strings.Replace(string(raw), `"TRUST_INDEPENDENT"`, `"`+trust+`"`, 1))
	copyFixture(t, envoyLog, tr.input, mode)
	chmod(t, tr.input, mode)
	return tr
}

// TestObserveImportOfAnEgressLogPrintsItsLabels: an egress access log is
// imported by its kind's importer, which counts lines, and the line it
// refuses makes the import exit 1.
func TestObserveImportOfAnEgressLogPrintsItsLabels(t *testing.T) {
	tr := egressTree(t, "TRUST_INDEPENDENT", 0o600)
	code, stdout, stderr := invoke(t, tr.importArgs()...)
	const want = "lines_read: 4\nobserved: 3\nwritten: 3\nduplicate: 0\nconflict: 0\nrefused: 1\nstrings_dropped: 0\ncallers_dropped: 0\n"
	if code != exitFail || stdout != want || !strings.Contains(stderr, "1 span(s) or line(s) refused") {
		t.Fatalf("exit %d, stderr %q, stdout\n%s\nwant 1 and\n%s", code, stderr, stdout, want)
	}
}

// TestObserveImportRefusesAnIndependentInputOthersCanWrite: independent
// trust states that the agent cannot write the log, so an input group or
// others can write is refused and nothing is written; the same input under
// platform trust, or owner-only under independent, is imported.
func TestObserveImportRefusesAnIndependentInputOthersCanWrite(t *testing.T) {
	for _, mode := range []os.FileMode{0o620, 0o602} {
		tr := egressTree(t, "TRUST_INDEPENDENT", mode)
		code, stdout, stderr := invoke(t, tr.importArgs()...)
		want := fmt.Sprintf("input %s: files: the mode gives access the caller forbids: mode %04o", strconv.Quote(tr.input), mode)
		if code != exitUsage || stdout != "" || !strings.Contains(stderr, want) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want 2 saying %q", mode, code, stdout, stderr, want)
		}
		if _, err := os.Stat(filepath.Join(tr.log, "observations.jsonl")); err == nil {
			t.Errorf("%v: the log was written", mode)
		}
	}
	for name, c := range map[string]struct {
		trust string
		mode  os.FileMode
	}{"platform, group-writable": {"TRUST_PLATFORM", 0o620}, "independent, writable by its owner alone": {"TRUST_INDEPENDENT", 0o644}} {
		tr := egressTree(t, c.trust, c.mode)
		if code, stdout, stderr := invoke(t, tr.importArgs()...); code != exitFail || counted(t, stdout, "written") != 3 {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want 1 with three written", name, code, stdout, stderr)
		}
	}
}

// TestSuperviseRefusesASourceWhoseObservationsNameNoRun: an egress source's
// connections name no run, so supervise refuses it as an input, exit 2, and
// writes no finding.
func TestSuperviseRefusesASourceWhoseObservationsNameNoRun(t *testing.T) {
	tr := newSupTree(t)
	descriptor, log := tr.source(t)
	raw, err := os.ReadFile(envoyDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.NewReplacer(`"tenant-a"`, fmt.Sprintf("%q", who.TenantID), `"project-a"`, fmt.Sprintf("%q", supProject)).Replace(string(raw))
	writeFixture(t, descriptor, body)
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	tr.closeRun(t, tr.run)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...)
	const want = `source "egress-envoy" is of kind "egress-access-log", whose observations name no run; supervise reads none`
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, want) {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 2 saying %q", code, stdout, stderr, want)
	}
	entries, err := os.ReadDir(tr.findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			t.Errorf("the findings directory holds %s", e.Name())
		}
	}
}

var startTime = regexp.MustCompile(`"start_time":"[^"]*"`)

// importFreshEgress writes the Envoy descriptor and its log, every line
// dated within the last two seconds, into tr's directory and imports them.
// One of its lines is refused, so the import exits 1.
func importFreshEgress(t *testing.T, tr coverageTree) (descriptor, log string) {
	t.Helper()
	raw, err := os.ReadFile(envoyDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, log = filepath.Join(tr.dir, "egress.json"), filepath.Join(tr.dir, "egress-log")
	writeFixture(t, descriptor, string(raw))
	if err := os.Mkdir(log, 0o700); err != nil {
		t.Fatal(err)
	}
	logRaw, err := os.ReadFile(envoyLog)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-2 * time.Second).UTC()
	fresh := startTime.ReplaceAllStringFunc(string(logRaw), func(string) string {
		at = at.Add(100 * time.Millisecond)
		return `"start_time":"` + at.Format(time.RFC3339Nano) + `"`
	})
	input := filepath.Join(tr.dir, "egress.jsonl")
	writeFixture(t, input, fresh)
	if code, stdout, stderr := invoke(t, "observe", "import", "--source", descriptor, "--log", log, input); code != exitFail || counted(t, stdout, "written") != 3 {
		t.Fatalf("import: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	return descriptor, log
}

// lineStarting is the first line of lines that starts with prefix, or "".
func lineStarting(lines []string, prefix string) string {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

// TestCoverageOfAnImportedEgressLog: the Envoy log imported fresh, and an
// inventory that declares one host it reached and not the other two. The
// declared host is observed by the independent source and decided by no
// plane; each other is an undeclared row, and the line the import refused is
// a row of its own, either of which makes coverage exit 1.
func TestCoverageOfAnImportedEgressLog(t *testing.T) {
	tr := newCoverageTree(t, `, {"id":"egress.api","kind":"egress","host":"api.example.com","sources":[{"source_id":"egress-envoy","name":"api.example.com"}]}`)
	egress, egressLog := importFreshEgress(t, tr)
	tr.importFresh(t)
	code, stdout, stderr := invoke(t, tr.args("--source", egress, "--log", egressLog)...)
	if code != 1 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout\n%s", code, stderr, stdout)
	}
	lines := outputLines(stdout)
	if got, want := lineStarting(lines, "egress.api "), "egress.api observed, independent (unsigned descriptor): sources egress-envoy; no plane decides egress"; got != want {
		t.Errorf("declared line %q, want %q", got, want)
	}
	undeclared := lineStarting(lines, "undeclared egress 2001:db8::1: ")
	if !strings.HasPrefix(undeclared, "undeclared egress 2001:db8::1: observed by egress-envoy: independent (unsigned descriptor), last heard ") ||
		!strings.HasSuffix(undeclared, "; 1 connection, port 8443; no plane decides egress") {
		t.Errorf("undeclared row %q", undeclared)
	}
	if plain := lineStarting(lines, "undeclared egress registry.example.org: "); !strings.HasSuffix(plain, "; 1 connection, port 80; no plane decides egress") {
		t.Errorf("undeclared row %q", plain)
	}
	const refused = "refused egress by egress-envoy: 1 line refused, so their connections are unknown: port 1; no plane decides egress"
	if got := lineStarting(lines, "refused egress "); got != refused || lines[len(lines)-2] != refused {
		t.Errorf("refused row %q before the standing row %q, want %q", got, lines[len(lines)-2], refused)
	}
	if row := lineStarting(lines, "undeclared egress api.example.com"); row != "" {
		t.Errorf("a declared host has an undeclared row: %q", row)
	}
	if last := lines[len(lines)-1]; last != "undeclared paths: unknown" {
		t.Errorf("last line %q, want the standing row", last)
	}
}

// TestObserveImportRefusesAnotherKindUnderOneSource: an egress import under
// the OpenTelemetry source's id, into its log, would make its reports that
// source's liveness and doubt, so the second import of either kind is
// refused, exit 2, and writes nothing.
func TestObserveImportRefusesAnotherKindUnderOneSource(t *testing.T) {
	tr := newObserveTree(t)
	if code, stdout, stderr := invoke(t, tr.importArgs()...); code != exitOK {
		t.Fatalf("the spans: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	before, err := os.ReadFile(filepath.Join(tr.log, "observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(envoyDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	egress := filepath.Join(filepath.Dir(tr.source), "egress.json")
	writeFixture(t, egress, strings.Replace(string(raw), `"egress-envoy"`, `"agent-runtime"`, 1))
	input := filepath.Join(filepath.Dir(tr.source), "egress.jsonl")
	copyFixture(t, envoyLog, input, 0o600)
	code, stdout, stderr := invoke(t, "observe", "import", "--source", egress, "--log", tr.log, input)
	const want = `the log holds this source's records under another kind: source "agent-runtime" holds records of kind "otel-genai-traces", and this write is of kind "egress-access-log"`
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, want) {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 2 saying %q", code, stdout, stderr, want)
	}
	after, err := os.ReadFile(filepath.Join(tr.log, "observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("the refused import wrote to the log")
	}
}

// TestCoverageRefusesAnAbsentDescriptorOverConnections: a removed egress
// descriptor whose log holds connections would hide every host they reached,
// so coverage refuses it, exit 2, rather than read it as a removed source.
func TestCoverageRefusesAnAbsentDescriptorOverConnections(t *testing.T) {
	tr := newCoverageTree(t, "")
	egress, egressLog := importFreshEgress(t, tr)
	tr.importFresh(t)
	if err := os.Remove(egress); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := invoke(t, tr.args("--source", egress, "--log", egressLog)...)
	want := "--source " + strconv.Quote(egress) + ": absent, and its log holds records of kind \"egress-access-log\""
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, want) {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 2 saying %q", code, stdout, stderr, want)
	}
}
