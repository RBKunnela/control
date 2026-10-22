//go:build unix

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/reaction"
)

// codeRunStopped is the plane's code for a call of a stopped run.
const codeRunStopped = "RUN_STOPPED"

// TestAStopRefusesItsRunsNextCallAndNoOthers runs the built plane with a
// route and two opened runs: once a stop of the first is written to the list,
// its next call is refused RUN_STOPPED within a few poll intervals, and the
// second run's call still runs.
func TestAStopRefusesItsRunsNextCallAndNoOthers(t *testing.T) {
	rp := newRunsPlane(t, "stateless_http")
	route := rp.withRoute()
	sp := rp.start()
	first, second := rp.open(), rp.open()
	agentA, agentB := agentUnder(t, sp.listen, first.token), agentUnder(t, sp.listen, second.token)
	expectRan(t, "the first run's call before the stop", callTool(t, agentA, toolReadTicket))

	appendStop(t, rp.dir, route, first.id)
	res, ran := rp.untilBlocked(agentA)
	codes, _ := planeFields(res.Meta)["reason_codes"].([]any)
	if !res.IsError || !slices.Contains(codes, any(codeRunStopped)) {
		t.Fatalf("the stopped run's call: isError %v, codes %v", res.IsError, codes)
	}
	if n := rp.up.count(toolReadTicket); n != ran {
		t.Errorf("the stopped call reached the upstream: %d runs, %d before it", n, ran)
	}
	expectRan(t, "the other run's call under the stop", callTool(t, agentB, toolReadTicket))
	if n := rp.up.count(toolReadTicket); n != ran+1 {
		t.Errorf("the other run's call ran the upstream %d times, want 1", n-ran)
	}

	state := stopsHealth(t, sp.health)
	if state.State != "stopped" || state.Active != 1 || len(state.Entries) != 1 || state.Entries[0].RunID != first.id || len(state.UnheldRuns) != 0 {
		t.Errorf("/healthz stops = %+v", state)
	}
}

// TestAChildsFindingStopsTheChildAndNotItsParentOrASibling runs the built
// plane with a root and two children opened under it: react, run as the
// operator runs it over a confirmed finding of the first child, writes a stop
// of that child, whose next call is refused RUN_STOPPED, while the root's and
// the sibling's calls still run.
func TestAChildsFindingStopsTheChildAndNotItsParentOrASibling(t *testing.T) {
	rp := newRunsPlane(t, "stateless_http")
	rp.withRoute()
	sp := rp.start()
	root := rp.open()
	child, sibling := rp.open("--parent", root.id, "--ttl", "30m"), rp.open("--parent", root.id, "--ttl", "30m")
	if child.root != root.id || sibling.root != root.id {
		t.Fatalf("runs open gave root %+v, children %+v and %+v", root, child, sibling)
	}
	agents := map[string]*sdk.ClientSession{}
	for name, run := range map[string]openedRun{"root": root, "child": child, "sibling": sibling} {
		agents[name] = agentUnder(t, sp.listen, run.token)
		expectRan(t, "the "+name+"'s call before the stop", callTool(t, agents[name], toolReadTicket))
	}

	rp.reactTo(child.id)
	res, ran := rp.untilBlocked(agents["child"])
	codes, _ := planeFields(res.Meta)["reason_codes"].([]any)
	if !res.IsError || !slices.Contains(codes, any(codeRunStopped)) {
		t.Fatalf("the stopped child's call: isError %v, codes %v", res.IsError, codes)
	}
	if n := rp.up.count(toolReadTicket); n != ran {
		t.Errorf("the stopped call reached the upstream: %d runs, %d before it", n, ran)
	}
	for _, name := range []string{"root", "sibling"} {
		expectRan(t, "the "+name+"'s call under the child's stop", callTool(t, agents[name], toolReadTicket))
	}
	if n := rp.up.count(toolReadTicket); n != ran+2 {
		t.Errorf("the root's and the sibling's calls ran the upstream %d times, want 2", n-ran)
	}
	state := stopsHealth(t, sp.health)
	if state.Active != 1 || len(state.Entries) != 1 || state.Entries[0].RunID != child.id {
		t.Errorf("/healthz stops = %+v, want the child's stop alone", state)
	}
}

// reactTo writes a confirmed finding about run into a findings log and runs
// the built react over it, failing unless it writes that run's stop.
func (rp *runsPlane) reactTo(run string) {
	rp.t.Helper()
	findings := filepath.Join(rp.dir, "findings")
	writeFinding(rp.t, findings, run)
	out, err := runBinary(rp.control, "react", "--findings", findings, "--runs", rp.runs,
		"--route", filepath.Join(rp.dir, "route.json"), "--public-key", filepath.Join(rp.dir, "route.pub"),
		"--stops", filepath.Join(rp.dir, "stops"))
	if err != nil || !strings.HasPrefix(out, "stop line 2 run "+run+" finding "+childFinding+" rule "+fixtureRule+" ") {
		rp.t.Fatalf("react: %v\n%s", err, out)
	}
}

// childFinding is a finding id as supervise spells one.
const childFinding = "fnd-0123456789abcdef0123456789abcdef"

// writeFinding writes, into a new owner-only findings log at dir, one
// deterministic, confirmed finding about run that the fixture's route names.
func writeFinding(t *testing.T, dir, run string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	log, err := findinglog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	proc := func() *findingv1alpha1.ProcedureRef {
		return &findingv1alpha1.ProcedureRef{ProcedureId: "refund", Version: "3", Digest: fixtureProcedure}
	}
	f := &findingv1alpha1.FindingRecord{
		SchemaVersion: "0.1", TenantId: runsTenant, ProjectId: "orders", Procedure: proc(),
		Escalation: findingv1alpha1.Escalation_ESCALATION_ALERT,
		Finding: &controlv1.Finding{FindingId: childFinding, RuleId: fixtureRule, RuleVersion: "1",
			Severity: controlv1.FindingSeverity_FINDING_SEVERITY_HIGH, RunId: run,
			Verdict: controlv1.FindingVerdict_FINDING_VERDICT_CONFIRMED, Source: controlv1.FindingSource_FINDING_SOURCE_DETERMINISTIC},
	}
	report := &findingv1alpha1.SuperviseReport{SchemaVersion: "0.1", TenantId: runsTenant, ProjectId: "orders",
		RunId: run, Procedure: proc(), Read: &findingv1alpha1.ReadCounts{EventsTaken: 1}}
	if _, err := log.Write([]*findingv1alpha1.FindingRecord{f}, report); err != nil {
		t.Fatal(err)
	}
}

// withRoute lays out a route, its floor and its stop list in the plane's
// directory and adds the reaction keys to its configuration, which names its
// runs directory already.
func (rp *runsPlane) withRoute() reaction.Route {
	rp.t.Helper()
	route := layOutReaction(rp.t, rp.dir)
	f, err := os.OpenFile(rp.config, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		rp.t.Fatal(err)
	}
	_, err = f.WriteString(strings.TrimPrefix(reactionKeys, "runs:\n  dir: runs\n"))
	if err = errors.Join(err, f.Close()); err != nil {
		rp.t.Fatalf("adding the route to the configuration: %v", err)
	}
	return route
}

// untilBlocked calls read_ticket under cs every tenth of a second until a
// call is refused or ten seconds pass, and returns the last answer and how
// often the upstream had run the tool before it.
func (rp *runsPlane) untilBlocked(cs *sdk.ClientSession) (*sdk.CallToolResult, int) {
	rp.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ran := rp.up.count(toolReadTicket)
		res := callTool(rp.t, cs, toolReadTicket)
		if res.IsError || !time.Now().Before(deadline) {
			return res, ran
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// stopsHealth reads /healthz's stops object.
func stopsHealth(t *testing.T, health string) stopsAnswer {
	t.Helper()
	resp, err := http.Get("http://" + health + "/healthz")
	if err != nil {
		t.Fatalf("reading /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var answer struct {
		Stops stopsAnswer `json:"stops"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		t.Fatalf("decoding /healthz: %v", err)
	}
	return answer.Stops
}
