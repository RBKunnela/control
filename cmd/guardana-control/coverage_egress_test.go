package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// otelDescriptorAs writes the OpenTelemetry fixture descriptor to path under
// source id.
func otelDescriptorAs(t *testing.T, path, id string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/observe/descriptor.json")
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, path, strings.Replace(string(raw), `"agent-runtime"`, strconv.Quote(id), 1))
}

// egressRefusal is the refusal of a --source whose log holds the Envoy
// source's records and no egress descriptor given with that log names them.
func egressRefusal(source string) string {
	return "--source " + strconv.Quote(source) + `: its log holds records of kind "egress-access-log" of source "egress-envoy"`
}

// TestCoverageRefusesEgressRecordsNoGivenDescriptorNames: a present
// descriptor that no longer names its log's egress source would hide every
// host it reached and every line refused, as an absent one would, so coverage
// refuses it, exit 2; the descriptor unchanged maps, exit 1.
func TestCoverageRefusesEgressRecordsNoGivenDescriptorNames(t *testing.T) {
	envoy, err := os.ReadFile(envoyDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	for name, rewrite := range map[string]func(t *testing.T, path string){
		"unchanged": nil,
		"an OpenTelemetry descriptor under its id":  func(t *testing.T, path string) { otelDescriptorAs(t, path, "egress-envoy") },
		"an OpenTelemetry descriptor of another id": func(t *testing.T, path string) { otelDescriptorAs(t, path, "other-runtime") },
		"its id renamed": func(t *testing.T, path string) {
			writeFixture(t, path, strings.Replace(string(envoy), `"egress-envoy"`, `"egress-renamed"`, 1))
		},
		"its tenant changed": func(t *testing.T, path string) {
			writeFixture(t, path, strings.Replace(string(envoy), `"tenant-a"`, `"tenant-b"`, 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newCoverageTree(t, "")
			egress, egressLog := importFreshEgress(t, tr)
			tr.importFresh(t)
			if rewrite != nil {
				rewrite(t, egress)
			}
			code, stdout, stderr := invoke(t, tr.args("--source", egress, "--log", egressLog)...)
			if rewrite == nil {
				if code != exitFail || stderr != "" || lineStarting(outputLines(stdout), "refused egress by egress-envoy: ") == "" {
					t.Fatalf("exit %d, stderr %q, stdout\n%s\nwant 1 with the refused row", code, stderr, stdout)
				}
				return
			}
			if want := egressRefusal(egress); code != exitUsage || stdout != "" || !strings.Contains(stderr, want) {
				t.Fatalf("exit %d, stdout %q, stderr %q; want 2 saying %q", code, stdout, stderr, want)
			}
		})
	}
}

// TestCoverageRefusesALogSharedWithEgressRecords: an OpenTelemetry source
// whose log directory also holds an egress source's records is refused unless
// that egress source's descriptor is given with the same directory; given
// with another, its records there are still unread.
func TestCoverageRefusesALogSharedWithEgressRecords(t *testing.T) {
	tr := newCoverageTree(t, "")
	tr.importFresh(t)
	egress, egressLog := importFreshEgress(t, tr)
	input := filepath.Join(tr.dir, "egress.jsonl")
	if code, stdout, stderr := invoke(t, "observe", "import", "--source", egress, "--log", tr.log, input); code != exitFail {
		t.Fatalf("import into the shared log: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	for name, args := range map[string][]string{
		"no egress descriptor":                 {},
		"the egress descriptor, another log":   {"--source", egress, "--log", egressLog},
		"the egress descriptor, a log of none": {"--source", egress, "--log", t.TempDir()},
	} {
		code, stdout, stderr := invoke(t, tr.args(args...)...)
		if want := egressRefusal(tr.source); code != exitUsage || stdout != "" || !strings.Contains(stderr, want) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want 2 saying %q", name, code, stdout, stderr, want)
		}
	}
	code, stdout, stderr := invoke(t, tr.args("--source", egress, "--log", filepath.Join(tr.dir, ".", "log"))...)
	if code != exitFail || stderr != "" || lineStarting(outputLines(stdout), "refused egress by egress-envoy: ") == "" {
		t.Errorf("the egress descriptor with the shared log: exit %d, stderr %q, stdout\n%s\nwant 1 with the refused row", code, stderr, stdout)
	}
}

// rowBeforeLast runs coverage and returns its exit and the line before the
// standing row, failing on anything on standard error.
func rowBeforeLast(t *testing.T, args []string) (int, string) {
	t.Helper()
	code, stdout, stderr := invoke(t, args...)
	lines := outputLines(stdout)
	if stderr != "" || len(lines) < 2 {
		t.Fatalf("exit %d, stderr %q, stdout\n%s", code, stderr, stdout)
	}
	return code, lines[len(lines)-2]
}

// TestCoverageRowsAnEgressSourceNotLive: an egress source no path names,
// beside a covered tool path, makes coverage exit 1 with a row of its own when
// it was never heard or is past its heartbeat, and adds none when it is live.
func TestCoverageRowsAnEgressSourceNotLive(t *testing.T) {
	tr := newCoverageTree(t, "")
	tr.importFresh(t)
	if code, stdout, _ := invoke(t, tr.args("--plane", tr.plane)...); code != exitOK {
		t.Fatalf("the tool path alone: exit %d, stdout\n%s", code, stdout)
	}
	raw, err := os.ReadFile(envoyDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	never, quiet := filepath.Join(tr.dir, "never.json"), filepath.Join(tr.dir, "never-log")
	writeFixture(t, never, string(raw))
	if err := os.Mkdir(quiet, 0o700); err != nil {
		t.Fatal(err)
	}
	const neverRow = "unseen egress by egress-envoy: never heard; connections since its last import are unseen; no plane decides egress"
	if code, row := rowBeforeLast(t, tr.args("--plane", tr.plane, "--source", never, "--log", quiet)); code != exitFail || row != neverRow {
		t.Errorf("never heard: exit %d, row %q; want 1 and %q", code, row, neverRow)
	}

	egress, egressLog := importFreshEgress(t, tr)
	code, stdout, _ := invoke(t, tr.args("--plane", tr.plane, "--source", egress, "--log", egressLog)...)
	if code != exitFail || lineStarting(outputLines(stdout), "unseen egress ") != "" {
		t.Errorf("live: exit %d, stdout\n%s\nwant 1 for its other rows and no unseen row", code, stdout)
	}
	writeFixture(t, egress, strings.Replace(string(raw), `"heartbeat_seconds": 300`, `"heartbeat_seconds": 1`, 1))
	code, row := rowBeforeLast(t, tr.args("--plane", tr.plane, "--source", egress, "--log", egressLog))
	if code != exitFail || !strings.HasPrefix(row, "unseen egress by egress-envoy: past its heartbeat: last heard ") ||
		!strings.HasSuffix(row, ", heartbeat 1 s; connections since its last import are unseen; no plane decides egress") {
		t.Errorf("lapsed: exit %d, row %q; want 1 and the unseen row", code, row)
	}
}
