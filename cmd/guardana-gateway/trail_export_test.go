package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/trailfile"
)

func exportCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return trailCommand(t, append([]string{"export"}, args...)...)
}

// exportTypes is the type of each line an export wrote, and fails on a line
// that is not one JSON object.
func exportTypes(t *testing.T, stdout string) []string {
	t.Helper()
	var types []string
	for _, line := range strings.Split(strings.TrimSuffix(stdout, "\n"), "\n") {
		if line == "" {
			continue
		}
		var r struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		types = append(types, r.Type)
	}
	return types
}

// TestTrailExportExitsAsTheRecordSays: 0 for an export with no gap, 1 for a
// whole export holding one, 2 for a refusal, with no trailer written; every
// refusal and every gap says so on one line of stderr.
func TestTrailExportExitsAsTheRecordSays(t *testing.T) {
	done := trailOf("a", kProposed, kDecided, kBlocked)
	later := trailOf("b", kProposed)
	later[0].SchemaVersion = "2.0"
	clean := trailFile(t, "", done...)
	gapped := trailFile(t, "", done[0], later[0], done[1])
	torn := trailFile(t, `{"eventId":"c-0",`, done...)
	dir := t.TempDir()
	type c struct {
		args    []string
		status  int
		types   string
		stderr  string
		trailer bool
	}
	usage := brand.Gateway + " trail export: "
	refused := brand.Gateway + ": trail export: "
	cases := map[string]c{
		"a clean file":              {[]string{clean}, exitOK, "header event event event trailer", "", true},
		"flags after the file":      {[]string{clean, "--limit", "1"}, exitOK, "header event trailer", "", true},
		"repeated filters":          {[]string{"--request", "x", "--request", "a", "--kind", "EVENT_KIND_POLICY_DECIDED", clean}, exitOK, "header event trailer", "", true},
		"an event of another major": {[]string{gapped}, exitFail, "header event gap event trailer", refused, true},
		"a tail no writer holds":    {[]string{torn}, exitFail, "header event event event gap trailer", refused, true},
		"a cursor of another file":  {[]string{"--after", "v1:" + strings.Repeat("0", 64) + ":1:" + strings.Repeat("0", 64), clean}, exitUsage, "", refused, false},
		"a malformed cursor":        {[]string{"--after", "somewhere", clean}, exitUsage, "", refused, false},
		"an unknown kind":           {[]string{"--kind", "EVENT_KIND_TELEPORTED", clean}, exitUsage, "", refused, false},
		"a limit of zero":           {[]string{"--limit", "0", clean}, exitUsage, "", refused, false},
		"a limit past the most":     {[]string{"--limit", "100001", clean}, exitUsage, "", refused, false},
		"a negative byte bound":     {[]string{"--max-bytes", "-1", clean}, exitUsage, "", refused, false},
		"a byte bound under a line": {[]string{"--max-bytes", "10", clean}, exitUsage, "", refused, false},
		"no file":                   {[]string{filepath.Join(dir, "none.jsonl")}, exitUsage, "", refused, false},
		"a directory":               {[]string{dir}, exitUsage, "", refused, false},
		"nothing to export":         {nil, exitUsage, "", usage, false},
		"two files":                 {[]string{clean, clean}, exitUsage, "", usage, false},
		"an unknown flag":           {[]string{"--since", "x", clean}, exitUsage, "", "flag provided but not defined", false},
	}
	for name, c := range cases {
		status, stdout, stderr := exportCommand(t, c.args...)
		types := strings.Join(exportTypes(t, stdout), " ")
		if status != c.status || types != c.types || !strings.Contains(stderr, c.stderr) {
			t.Errorf("%s: exit %d, %q, stderr %q; want %d, %q and %q", name, status, types, stderr, c.status, c.types, c.stderr)
		}
		if c.stderr != "" && c.status != exitUsage && strings.Count(stderr, "\n") != 1 {
			t.Errorf("%s: stderr %q is not one line", name, stderr)
		}
		if strings.Contains(stdout, `"type":"trailer"`) != c.trailer {
			t.Errorf("%s: trailer written is %v, want %v", name, !c.trailer, c.trailer)
		}
		if c.status == exitOK && stderr != "" {
			t.Errorf("%s: a clean export wrote %q to stderr", name, stderr)
		}
	}
}

// TestTrailExportTakesAHeldTailForALineInProgress: the tail a collector is
// still writing is no gap, and the export exits 0.
func TestTrailExportTakesAHeldTailForALineInProgress(t *testing.T) {
	path, _ := tornTrail(t)
	whole, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	w, err := trailfile.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err := os.WriteFile(path, whole, 0o600); err != nil {
		t.Fatal(err)
	}
	status, stdout, stderr := exportCommand(t, path)
	if status != exitOK || !strings.Contains(stdout, `"writer_held":true`) || strings.Contains(stdout, `"type":"gap"`) || stderr != "" {
		t.Errorf("held tail: exit %d with\n%s\nand %q", status, stdout, stderr)
	}
}

// TestTrailExportResumesFromItsCursor: the trailer's next_cursor given back
// as --after exports what followed it.
func TestTrailExportResumesFromItsCursor(t *testing.T) {
	path := trailFile(t, "", trailOf("a", kProposed, kDecided, kBlocked)...)
	status, stdout, _ := exportCommand(t, "--limit", "2", path)
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	var tr struct {
		Next string `json:"next_cursor"`
		End  bool   `json:"end_reached"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &tr); err != nil || status != exitOK || tr.End || tr.Next == "" {
		t.Fatalf("first export: exit %d, trailer %+v, %v", status, tr, err)
	}
	status, stdout, _ = exportCommand(t, "--after", tr.Next, path)
	if got := strings.Join(exportTypes(t, stdout), " "); status != exitOK || got != "header event trailer" ||
		!strings.Contains(stdout, `"eventId":"a-2"`) {
		t.Errorf("resumed export: exit %d, %q\n%s", status, got, stdout)
	}
}

// TestTrailExportFlagsBelongToExport: plain trail takes none of them, and
// refuses them as it refuses any flag.
func TestTrailExportFlagsBelongToExport(t *testing.T) {
	path := trailFile(t, "", trailOf("a", kProposed, kDecided, kBlocked)...)
	if status, stdout, _ := trailCommand(t, "--limit", "1", path); status != exitUsage || stdout != "" {
		t.Errorf("trail --limit: exit %d with %q, want %d and nothing", status, stdout, exitUsage)
	}
	if status, stdout, _ := trailCommand(t, path); status != exitOK || !strings.HasSuffix(stdout, shapeLine) {
		t.Errorf("trail: exit %d with %q", status, stdout)
	}
}

// TestTrailExportThatCannotWriteExitsTwo: output that never arrived is no
// export, and a reader missing its trailer knows it.
func TestTrailExportThatCannotWriteExitsTwo(t *testing.T) {
	path := trailFile(t, "", trailOf("a", kProposed, kDecided, kBlocked)...)
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"trail", "export", path}, failingWriter{}, &stderr)
	if status != exitUsage || !strings.HasPrefix(stderr.String(), brand.Gateway+": trail export: ") {
		t.Errorf("exit %d with %q", status, stderr.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }
