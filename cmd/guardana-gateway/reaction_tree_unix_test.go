//go:build unix

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/supervise"
	"github.com/guardana/control/internal/trailfile"
)

// treeProcedure is the runs fixture's two tools as a 0.2 procedure that
// judges a root with its whole tree: no step required, no binding and no
// exception.
const treeProcedure = `{"schema_version":"0.2","procedure_id":"tickets","version":"1","bindings":{},` +
	`"steps":[{"id":"read","tool":"read_ticket","upstream":"orders","observed_as":[],"required":false,"binds":[]},` +
	`{"id":"mail","tool":"send_mail","upstream":"orders","observed_as":[],"required":false,"binds":[]}],` +
	`"order":{},"allow":[],"exceptions":[],"children":"inherit","max_denials":4,"rules":{` +
	`"REPEATED_DENIAL":{"severity":"high","escalation":"alert"},` +
	`"STEP_OUTSIDE_PROCEDURE":{"severity":"medium","escalation":"alert"},` +
	`"DEADLINE_EXCEEDED":{"severity":"low","escalation":"inform"},` +
	`"REQUIRED_STEP_SKIPPED":{"severity":"high","escalation":"alert"},` +
	`"STEP_OUT_OF_ORDER":{"severity":"medium","escalation":"inform"},` +
	`"CONTINUED_AFTER_FAILURE":{"severity":"critical","escalation":"alert"},` +
	`"RESOURCE_OUTSIDE_RUN":{"severity":"critical","escalation":"alert"},` +
	`"DENIED_ACTION_RETRIED_ARGUMENTS":{"severity":"high","escalation":"alert"},` +
	`"DENIED_ACTION_RETRIED_RESOURCE":{"severity":"high","escalation":"alert"},` +
	`"DENIED_ACTION_RETRIED_AROUND":{"severity":"low","escalation":"inform"},` +
	`"EXCEPTION_TAKEN":{"severity":"info","escalation":"inform"}}}`

const ruleRetriedArguments = "DENIED_ACTION_RETRIED_ARGUMENTS"

// TestAChildsRetryIsSupervisedOverTheTreeAndStopsTheChild runs the built
// plane with a root and a child opened under it. The child reads a ticket,
// is denied mail to a stranger and retries to another address; the trail
// the plane shipped is exported, supervised from the root under inherit and
// handed to react with a route naming the retry rule. The child's next call
// is then refused RUN_STOPPED while the root's still runs.
func TestAChildsRetryIsSupervisedOverTheTreeAndStopsTheChild(t *testing.T) {
	rp := newRunsPlane(t, "stateless_http")
	proc, err := supervise.ReadProcedure([]byte(treeProcedure))
	if err != nil {
		t.Fatal(err)
	}
	rp.withRouteDocument(routeOfRule(t, proc, ruleRetriedArguments))
	sp := rp.start()
	root := rp.open()
	child := rp.open("--parent", root.id, "--ttl", "30m")
	rootAgent, childAgent := agentUnder(t, sp.listen, root.token), agentUnder(t, sp.listen, child.token)
	expectRan(t, "the root's read", callTool(t, rootAgent, toolReadTicket))
	expectRan(t, "the child's read", callTool(t, childAgent, toolReadTicket))
	expectToxic(t, "the child's mail", mailTo(t, childAgent, "orders-backup@example.net"))
	expectToxic(t, "the child's mail to another address", mailTo(t, childAgent, "orders-copy@example.net"))

	rp.settled(4)
	finding := rp.superviseTree(root.id, child.id, rp.exportTrail())
	out, err := runBinary(rp.control, "react", "--findings", filepath.Join(rp.dir, "findings"), "--runs", rp.runs,
		"--route", filepath.Join(rp.dir, "route.json"), "--public-key", filepath.Join(rp.dir, "route.pub"),
		"--stops", filepath.Join(rp.dir, "stops"))
	if err != nil || !strings.HasPrefix(out, "stop line 2 run "+child.id+" finding "+finding+" rule "+ruleRetriedArguments+" ") {
		t.Fatalf("react: %v\n%s", err, out)
	}

	res, ran := rp.untilBlocked(childAgent)
	codes, _ := planeFields(res.Meta)["reason_codes"].([]any)
	if !res.IsError || !slices.Contains(codes, any(codeRunStopped)) {
		t.Fatalf("the stopped child's call: isError %v, codes %v", res.IsError, codes)
	}
	if n := rp.up.count(toolReadTicket); n != ran {
		t.Errorf("the stopped call reached the upstream: %d runs, %d before it", n, ran)
	}
	expectRan(t, "the root's read under the child's stop", callTool(t, rootAgent, toolReadTicket))
	if n := rp.up.count(toolReadTicket); n != ran+1 {
		t.Errorf("the root's read ran the upstream %d times, want 1", n-ran)
	}
}

// routeOfRule is a route of the listener's tenant at serial 1 whose one rule
// is rule of p, at rule version "1".
func routeOfRule(t *testing.T, p *supervise.Procedure, rule string) string {
	t.Helper()
	fixture := `"procedure_id":"refund","version":"3","digest":"` + fixtureProcedure + `"`
	doc := routeDocumentOf(runsTenant, 1, rule, "1")
	if !strings.Contains(doc, fixture) {
		t.Fatalf("the fixture's route names no %s", fixture)
	}
	return strings.Replace(doc, fixture, `"procedure_id":"`+p.ID()+`","version":"`+p.Version()+`","digest":"`+p.Digest()+`"`, 1)
}

// withRouteDocument lays out doc, signed with the route key, as layOutReaction
// lays out the fixture's route, with its floor, an empty stop list bound to
// it and the runs directory's admin lock, and adds the reaction keys to the
// configuration.
func (rp *runsPlane) withRouteDocument(doc string) {
	rp.t.Helper()
	route := readRouteDocument(rp.t, doc)
	writeRouteFile(rp.t, rp.dir, route, routeSigningKey(), routeSigningKey().Public().(ed25519.PublicKey))
	if err := policystate.InitRoute(context.Background(), filepath.Join(rp.dir, "routefloor"), fixtureRouteID); err != nil {
		rp.t.Fatalf("making the route floor: %v", err)
	}
	if err := os.Mkdir(filepath.Join(rp.dir, "stops"), 0o700); err != nil {
		rp.t.Fatal(err)
	}
	admin, err := runs.InitAdmin(context.Background(), rp.runs)
	if err == nil {
		err = admin.Close()
	}
	if err != nil {
		rp.t.Fatalf("taking the runs directory: %v", err)
	}
	if _, err := stopwrite.Init(context.Background(), filepath.Join(rp.dir, "stops"), route, time.Now()); err != nil {
		rp.t.Fatalf("starting the stop list: %v", err)
	}
	f, err := os.OpenFile(rp.config, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		rp.t.Fatal(err)
	}
	_, err = f.WriteString(strings.TrimPrefix(reactionKeys, "runs:\n  dir: runs\n"))
	if err = errors.Join(err, f.Close()); err != nil {
		rp.t.Fatalf("adding the route to the configuration: %v", err)
	}
}

// mailTo sends mail to address and fails the case on a protocol error.
func mailTo(t *testing.T, cs *sdk.ClientSession, address string) *sdk.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: toolSendMail, Arguments: map[string]any{"to": address}})
	if err != nil {
		t.Fatalf("mailing %s: %v", address, err)
	}
	return res
}

// exportTrail appends what the collector holds to a trail file of its own
// and writes the built binary's export of it, returning the export's path.
func (rp *runsPlane) exportTrail() string {
	rp.t.Helper()
	dir := filepath.Join(rp.dir, "trail")
	if err := os.Mkdir(dir, 0o700); err != nil {
		rp.t.Fatal(err)
	}
	trail := filepath.Join(dir, "plane.jsonl")
	w, err := trailfile.Open(trail)
	if err != nil {
		rp.t.Fatalf("opening the trail: %v", err)
	}
	err = w.Append(context.Background(), rp.collector.events(rp.t))
	if err = errors.Join(err, w.Close()); err != nil {
		rp.t.Fatalf("writing the trail: %v", err)
	}
	cmd := exec.Command(rp.gateway, "trail", "export", trail) //nolint:gosec // G204: the binary this test built
	cmd.Env = environ()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || stderr.Len() != 0 {
		rp.t.Fatalf("trail export: %v, %s", err, stderr.String())
	}
	export := filepath.Join(dir, "export.jsonl")
	if err := os.WriteFile(export, out, 0o600); err != nil {
		rp.t.Fatal(err)
	}
	return export
}

// retriedLine is the line supervise prints for a confirmed retry finding of
// run, with the finding's id as its group.
func retriedLine(run string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^finding ` + ruleRetriedArguments + ` confirmed alert (fnd-[0-9a-f]{32}) run ` +
		regexp.QuoteMeta(run) + ` `)
}

// superviseTree runs the built supervise over the export from root under
// treeProcedure, which must judge the tree and find the child's retry and
// nothing else confirmed, and returns that finding's id.
func (rp *runsPlane) superviseTree(root, child, export string) string {
	rp.t.Helper()
	procedure, findings := filepath.Join(rp.dir, "procedure.json"), filepath.Join(rp.dir, "findings")
	if err := os.WriteFile(procedure, []byte(treeProcedure), 0o600); err != nil {
		rp.t.Fatal(err)
	}
	if err := os.Mkdir(findings, 0o700); err != nil {
		rp.t.Fatal(err)
	}
	out, err := runBinary(rp.control, "supervise", "--procedure", procedure, "--runs", rp.runs, "--run", root,
		"--findings", findings, "--evidence", export)
	if exitOf(rp.t, err) != 1 {
		rp.t.Fatalf("supervise exited %v, want 1 for a finding:\n%s", err, out)
	}
	for _, want := range []string{"children: inherit, every run of the tree judged\n", "tree: " + root + "\n",
		"tree: " + child + " under " + root + "\n", "rule " + ruleRetriedArguments + " checked\n"} {
		if !strings.Contains(out, want) {
			rp.t.Errorf("supervise printed no %q:\n%s", want, out)
		}
	}
	match := retriedLine(child).FindStringSubmatch(out)
	if match == nil || strings.Count(out, " confirmed ") != 1 {
		rp.t.Fatalf("supervise printed no one confirmed retry naming the child:\n%s", out)
	}
	return match[1]
}
