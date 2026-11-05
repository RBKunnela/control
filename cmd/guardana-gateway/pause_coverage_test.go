package main

import (
	"bytes"
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// openedRuns makes the tree's runs directory and opens in it, under the
// fixture's identity: a root, a child of it, a closed child, a closed root, a
// run of another project and one that expired. It returns their ids by those
// names, and a well-formed id of no run.
func openedRuns(t *testing.T, tr tree) map[string]string {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join(tr.dir, "runs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	admin, err := runs.InitAdmin(ctx, dir)
	if err != nil {
		t.Fatalf("making the runs directory: %v", err)
	}
	defer func() {
		if err := admin.Close(); err != nil {
			t.Error(err)
		}
	}()
	who := runs.Identity{ProjectID: "orders", TenantID: "acme", PrincipalType: "service", PrincipalID: "agent-runner", AgentID: "orders-assistant"}
	now := time.Now()
	open := func(who runs.Identity, parent string) string {
		return openAt(t, admin, who, parent, now)
	}
	ids := map[string]string{"root": open(who, "")}
	ids["child"] = open(who, ids["root"])
	ids["closed"] = open(who, ids["root"])
	ids["closed-root"] = open(who, "")
	elsewhere := who
	elsewhere.ProjectID = "billing"
	ids["elsewhere"] = open(elsewhere, "")
	ids["expired"] = openAt(t, admin, who, "", now.Add(-2*time.Hour))
	for _, name := range []string{"closed", "closed-root"} {
		if err := admin.CloseRun(ctx, ids[name], now); err != nil {
			t.Fatalf("closing a run: %v", err)
		}
	}
	ids["absent"] = "run-" + strings.Repeat("0", 32)
	setEnv(t, "runs.dir", dir)
	return ids
}

// openAt opens a run of an hour at now and returns its id.
func openAt(t *testing.T, admin *runs.Admin, who runs.Identity, parent string, now time.Time) string {
	t.Helper()
	rec, _, err := admin.Open(context.Background(), runs.OpenRequest{Who: who, Parent: parent, TTL: time.Hour, Now: now})
	if err != nil {
		t.Fatalf("opening a run: %v", err)
	}
	return rec.ID
}

// TestARunEntryCoversOnlyARunThePlaneServes: on a plane with runs.dir a run
// entry covers some calls while its run is open and the plane's project's;
// one naming no run, a closed child, an expired run or another project's run
// covers none,
// and /healthz and doctor say why. A closed root still covers the runs left
// open under it.
func TestARunEntryCoversOnlyARunThePlaneServes(t *testing.T) {
	tr := newTree(t)
	ids := openedRuns(t, tr)
	var entries []string
	for _, name := range []string{"root", "child", "closed", "closed-root", "elsewhere", "expired", "absent"} {
		entries = append(entries, pauseEntry(name, `{"kind":"run","id":"`+ids[name]+`"}`))
	}
	tr.withPauseFile(t, pauseDocument(append(entries, pauseEntry("ours", scopeOurAgent))...), time.Second)
	causes := map[string]any{"closed": "closed", "elsewhere": "another project's run", "expired": "expired", "absent": "no such run"}
	var stdout, stderr bytes.Buffer
	doctor(context.Background(), tr.config, &stdout, &stderr)
	out := stdout.String()
	if line := reportLine(out, "pause"); !strings.Contains(line, "8 entry(ies), 0 naming an upstream this configuration does not have; 1 covering all of this plane's calls, 3 some, 4 none") {
		t.Errorf("the pause line is %q", line)
	}
	for name, cause := range causes {
		if want := "       pause entry " + name + " names run " + ids[name] + ": " + cause.(string) + ", so it pauses no call this plane runs\n"; !strings.Contains(out, want) {
			t.Errorf("doctor does not say %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "       pause entry "); n != 4 {
		t.Errorf("doctor named %d entries, want 4:\n%s", n, out)
	}
	p := tr.plane(t)
	_, body := p.healthAt(p.poller.Current().ReadAt())
	member := pauseMember(t, body)
	want := map[string]any{"root": "some", "child": "some", "closed": "none", "closed-root": "some", "elsewhere": "none", "expired": "none", "absent": "none", "ours": "all"}
	if covers, ok := member["coverage"].(map[string]any); !ok || !maps.Equal(covers, want) {
		t.Errorf("pause.coverage = %v, want %v", member["coverage"], want)
	}
	if got, ok := member["coverage_causes"].(map[string]any); !ok || !maps.Equal(got, causes) {
		t.Errorf("pause.coverage_causes = %v, want %v", member["coverage_causes"], causes)
	}
}
