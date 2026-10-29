//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// postCall sends one tools/call the way an agent's client does, with the
// headers given, and returns the status and the challenge it was answered
// with.
func postCall(t *testing.T, address string, header http.Header) (int, string) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_mail","arguments":{"to":"orders-backup@example.net"}}}`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address, strings.NewReader(body))
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("posting the call: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

// forge keeps a token's run id and changes its secret, which is what an agent
// that learned a run id but not its token presents.
func forge(token string) string {
	id, secret, _ := strings.Cut(token, ".")
	first := "A"
	if strings.HasPrefix(secret, "A") {
		first = "B"
	}
	return id + "." + first + secret[1:]
}

// TestARunsPlaneRefusesATokenThatDoesNotResolveAtTheRequest: no token, a
// forged one, another agent's and a closed run's are each answered 401 with
// the challenge before anything is decided, leave nothing in the trail, and
// are counted by cause; a call under an open run of this agent then runs.
func TestARunsPlaneRefusesATokenThatDoesNotResolveAtTheRequest(t *testing.T) {
	rp := newRunsPlane(t, "stateless_http")
	good := rp.open()
	other := rp.open("--agent", "billing-assistant")
	closed := rp.open()
	rp.closeRun(closed.id)
	plane := rp.start()

	refused := []struct {
		name   string
		header http.Header
	}{
		{"no token", http.Header{}},
		{"a forged token", http.Header{adaptermcp.RunTokenHeader: {forge(good.token)}}},
		{"another agent's token", http.Header{adaptermcp.RunTokenHeader: {other.token}}},
		{"a closed run's token", http.Header{adaptermcp.RunTokenHeader: {closed.token}}},
	}
	for _, c := range refused {
		status, challenge := postCall(t, plane.listen, c.header)
		if status != http.StatusUnauthorized || challenge != adaptermcp.RunTokenHeader {
			t.Errorf("%s: answered %d with WWW-Authenticate %q, want 401 with %q", c.name, status, challenge, adaptermcp.RunTokenHeader)
		}
	}

	runs, _ := runsHealth(t, plane.health)
	if runs["kind"] != "opened" {
		t.Errorf("runs.kind = %v, want opened", runs["kind"])
	}
	expectCounts(t, refusedAt(t, runs, "refused_at_request"),
		map[string]float64{"missing": 1, "malformed": 0, "unknown": 1, "identity": 1, "closed": 1, "expired": 0, "unreadable": 0})

	// The call that runs is the barrier: the exporter ships in order, one
	// batch in flight, so once its events arrived a refused call's would have.
	expectRan(t, "a call under an open run", callTool(t, agentUnder(t, plane.listen, good.token), toolSendMail))
	trails := rp.settled(1)
	for _, trail := range trails {
		for _, e := range trail {
			if e.GetRunId() != good.id {
				t.Errorf("the trail holds %s of run %q; only the call under %s was admitted", e.GetKind(), e.GetRunId(), good.id)
			}
		}
	}
	if len(trails) != 1 {
		t.Errorf("the trail holds %d request(s), want the one admitted call's", len(trails))
	}
	if ran := rp.up.count(toolSendMail); ran != 1 {
		t.Errorf("the upstream ran send_mail %d time(s), want 1", ran)
	}
}

// TestARunOfAnotherProjectIsRefusedOnASharedDirectory: planes of two
// projects share one runs directory and one listener identity. A token of
// one project's run is answered 401 on the other's plane, counted as another
// identity, and leaves nothing in that plane's trail; each plane runs a call
// under its own project's run.
func TestARunOfAnotherProjectIsRefusedOnASharedDirectory(t *testing.T) {
	orders := newRunsPlane(t, "stateless_http")
	billing := newRunsPlaneOver(t, "stateless_http", "billing", orders.runs)
	ordersRun, billingRun := orders.open(), billing.open()
	planes := map[*runsPlane]*servingPlane{orders: orders.start(), billing: billing.start()}

	for _, c := range []struct {
		name    string
		on      *runsPlane
		foreign openedRun
		own     openedRun
	}{
		{"an orders run on the billing plane", billing, ordersRun, billingRun},
		{"a billing run on the orders plane", orders, billingRun, ordersRun},
	} {
		plane := planes[c.on]
		status, challenge := postCall(t, plane.listen, http.Header{adaptermcp.RunTokenHeader: {c.foreign.token}})
		if status != http.StatusUnauthorized || challenge != adaptermcp.RunTokenHeader {
			t.Errorf("%s: answered %d with WWW-Authenticate %q, want 401 with %q", c.name, status, challenge, adaptermcp.RunTokenHeader)
		}
		runs, _ := runsHealth(t, plane.health)
		expectCounts(t, refusedAt(t, runs, "refused_at_request"),
			map[string]float64{"missing": 0, "malformed": 0, "unknown": 0, "identity": 1, "closed": 0, "expired": 0, "unreadable": 0})

		expectRan(t, c.name+": the plane's own run", callTool(t, agentUnder(t, plane.listen, c.own.token), toolSendMail))
		trails := c.on.settled(1)
		for _, trail := range trails {
			for _, e := range trail {
				if e.GetRunId() != c.own.id {
					t.Errorf("%s: the trail holds %s of run %q; only %s was admitted", c.name, e.GetKind(), e.GetRunId(), c.own.id)
				}
			}
		}
		if len(trails) != 1 {
			t.Errorf("%s: the trail holds %d request(s), want the own run's one", c.name, len(trails))
		}
		if ran := c.on.up.count(toolSendMail); ran != 1 {
			t.Errorf("%s: the upstream ran send_mail %d time(s), want the own run's one", c.name, ran)
		}
	}
}

// TestARecordOfMajorOneResolvesOnNoPlane: a run record of major 1, which
// names no project, is refused as unreadable at the request, and nothing of
// it reaches the trail or the upstream.
func TestARecordOfMajorOneResolvesOnNoPlane(t *testing.T) {
	rp := newRunsPlane(t, "stateless_http")
	old, good := rp.open(), rp.open()
	asMajorOne(t, rp.runs, old.id)
	plane := rp.start()

	status, challenge := postCall(t, plane.listen, http.Header{adaptermcp.RunTokenHeader: {old.token}})
	if status != http.StatusUnauthorized || challenge != adaptermcp.RunTokenHeader {
		t.Errorf("a major-1 run's token: answered %d with WWW-Authenticate %q, want 401 with %q", status, challenge, adaptermcp.RunTokenHeader)
	}
	runs, _ := runsHealth(t, plane.health)
	expectCounts(t, refusedAt(t, runs, "refused_at_request"),
		map[string]float64{"missing": 0, "malformed": 0, "unknown": 0, "identity": 0, "closed": 0, "expired": 0, "unreadable": 1})
	expectRan(t, "a call under a run of major 2", callTool(t, agentUnder(t, plane.listen, good.token), toolSendMail))
	for _, trail := range rp.settled(1) {
		for _, e := range trail {
			if e.GetRunId() != good.id {
				t.Errorf("the trail holds %s of run %q; only %s was admitted", e.GetKind(), e.GetRunId(), good.id)
			}
		}
	}
	if ran := rp.up.count(toolSendMail); ran != 1 {
		t.Errorf("the upstream ran send_mail %d time(s), want 1", ran)
	}
}

// asMajorOne rewrites a run's record as a release that wrote major 1 left
// it: no project, and that version.
func asMajorOne(t *testing.T, dir, id string) {
	t.Helper()
	path := filepath.Join(dir, id+".run.json")
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a record under the test's own directory
	if err != nil {
		t.Fatalf("reading the record: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decoding the record: %v", err)
	}
	if _, ok := m["project_id"]; !ok {
		t.Fatalf("the record holds no project_id to remove: %s", raw)
	}
	delete(m, "project_id")
	m["schema_version"] = json.RawMessage(`"1.0"`)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("writing the record: %v", err)
	}
}

// expectCounts fails unless got holds exactly the causes of want, each at its
// count.
func expectCounts(t *testing.T, got, want map[string]float64) {
	t.Helper()
	for cause, n := range want {
		if got[cause] != n {
			t.Errorf("runs.refused_at_request.%s = %v, want %v (all: %v)", cause, got[cause], n, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("runs.refused_at_request has causes %v, want exactly %v", got, want)
	}
}

// TestTwoRunsOfOneAgentKeepWhatTheyTookInApart: run A reads an untrusted,
// confidential ticket, and its mail to a stranger is denied by the flow rule;
// the same mail under run B of the same agent runs; a child opened under A
// shares A's root and is denied like A. Every event carries its run's id and
// each proposal names its root.
func TestTwoRunsOfOneAgentKeepWhatTheyTookInApart(t *testing.T) {
	rp := newRunsPlane(t, "stateless_http")
	a, b := rp.open(), rp.open()
	child := rp.open("--parent", a.id, "--ttl", "30m")
	if child.root != a.id || b.root != b.id || a.root != a.id {
		t.Fatalf("roots: a %s, b %s, child %s; want a and child under %s, b its own", a.root, b.root, child.root, a.id)
	}
	plane := rp.start()

	agentA := agentUnder(t, plane.listen, a.token)
	expectRan(t, "A's ticket read", callTool(t, agentA, toolReadTicket))
	expectToxic(t, "A's mail after the ticket", callTool(t, agentA, toolSendMail))
	expectRan(t, "B's mail", callTool(t, agentUnder(t, plane.listen, b.token), toolSendMail))
	expectToxic(t, "the child's mail", callTool(t, agentUnder(t, plane.listen, child.token), toolSendMail))
	if ran := rp.up.count(toolSendMail); ran != 1 {
		t.Errorf("the upstream ran send_mail %d time(s), want B's one", ran)
	}

	if ran := rp.up.count(toolReadTicket); ran != 1 {
		t.Errorf("the upstream ran read_ticket %d time(s), want A's one", ran)
	}
	expectProposals(t, rp.settled(4), map[string]map[string]proposal{
		a.id:     {toolReadTicket: {a.id, "false"}, toolSendMail: {a.id, "true"}},
		b.id:     {toolSendMail: {b.id, "false"}},
		child.id: {toolSendMail: {a.id, "true"}},
	})
}

// proposal is the root and the untrusted flag a proposed call's tags name.
type proposal struct{ root, untrusted string }

// expectProposals fails unless the trails are exactly the expected calls, by
// run and tool, each proposal tagged with its root and its flow state and
// every event of a trail carrying its run's id.
func expectProposals(t *testing.T, trails map[string][]*controlv1.Event, expect map[string]map[string]proposal) {
	t.Helper()
	seen := map[string]bool{}
	for request, trail := range trails {
		e := trail[0]
		w, ok := expect[e.GetRunId()][toolOf(e)]
		if e.GetKind() != controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED || !ok {
			t.Errorf("request %s opens with %s of %s under run %q, which made no such call", request, e.GetKind(), toolOf(e), e.GetRunId())
			continue
		}
		seen[e.GetRunId()+"/"+toolOf(e)] = true
		if !hasTag(e, "flow.v1.root="+w.root) || !hasTag(e, "flow.v1.untrusted="+w.untrusted) {
			t.Errorf("%s under %s carries tags %v, want flow.v1.root=%s and flow.v1.untrusted=%s",
				toolOf(e), e.GetRunId(), e.GetProposed().GetContext().GetTags(), w.root, w.untrusted)
		}
		for _, later := range trail[1:] {
			if later.GetRunId() != e.GetRunId() {
				t.Errorf("request %s: %s carries run %q, its proposal %q", request, later.GetKind(), later.GetRunId(), e.GetRunId())
			}
		}
	}
	if len(seen) != len(trails) || len(trails) != 4 {
		t.Errorf("the trails cover %v, want each of the four calls once", seen)
	}
}

// TestARestartedPlaneKeepsWhatARunTookIn: a plane stopped after run A took in
// the ticket and started again on the same runs directory still denies A's
// mail, and still lets the clean run B's through.
func TestARestartedPlaneKeepsWhatARunTookIn(t *testing.T) {
	rp := newRunsPlane(t, "stateless_http")
	a, b := rp.open(), rp.open()
	first := rp.start()
	agentA := agentUnder(t, first.listen, a.token)
	expectRan(t, "A's ticket read", callTool(t, agentA, toolReadTicket))
	expectToxic(t, "A's mail before the restart", callTool(t, agentA, toolSendMail))
	_ = agentA.Close()
	first.proc.stop(t)

	second := rp.start()
	expectToxic(t, "A's mail after the restart", callTool(t, agentUnder(t, second.listen, a.token), toolSendMail))
	expectRan(t, "B's mail after the restart", callTool(t, agentUnder(t, second.listen, b.token), toolSendMail))
}

// TestARunClosedUnderAnOpenSessionIsRefusedAtTheNextRequest: on a stateful
// listener, a session that made a call under a run makes none once the run
// is closed: the next request is refused before the library reads it, and
// nothing is admitted or sent.
func TestARunClosedUnderAnOpenSessionIsRefusedAtTheNextRequest(t *testing.T) {
	rp := newRunsPlane(t, "stateful_http")
	run := rp.open()
	plane := rp.start()
	agent := agentUnder(t, plane.listen, run.token)
	expectRan(t, "the call before the close", callTool(t, agent, toolSendMail))
	_, before := runsHealth(t, plane.health)

	rp.closeRun(run.id)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := agent.CallTool(ctx, &sdk.CallToolParams{Name: toolSendMail, Arguments: map[string]any{"to": "orders-backup@example.net"}})
	if err == nil {
		t.Errorf("the call after the close was answered %+v; want the request refused", res)
	}

	runs, after := runsHealth(t, plane.health)
	if got := refusedAt(t, runs, "refused_at_request")["closed"]; got < 1 {
		t.Errorf("runs.refused_at_request.closed = %v, want the refused request counted", got)
	}
	for cause, n := range refusedAt(t, runs, "refused_at_message") {
		if n != 0 {
			t.Errorf("runs.refused_at_message.%s = %v; a request refused at the listener never reaches a message", cause, n)
		}
	}
	for _, key := range []string{"admitted", "sent"} {
		if after[key] != before[key] {
			t.Errorf("pipeline.%s went from %v to %v across a refused request", key, before[key], after[key])
		}
	}
	if ran := rp.up.count(toolSendMail); ran != 1 {
		t.Errorf("the upstream ran send_mail %d time(s), want the one before the close", ran)
	}
}

// writeToken writes a token file with mode perm.
func writeToken(t *testing.T, dir, name, token string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("writing the token file: %v", err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("setting the token file's mode: %v", err)
	}
	return path
}

// startRefused runs the stdio plane with tokenFile and returns its exit and
// what it wrote, failing the case if it is still running past the bound.
func (rp *runsPlane) startRefused(tokenFile string) (int, string) {
	rp.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, rp.gateway, "run", "--config", rp.config, "--run-token-file", tokenFile) //nolint:gosec // G204: the binary this test built
	cmd.Env = environ()
	cmd.Stdin = bytes.NewReader(nil)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		rp.t.Fatalf("the plane was still running at the bound:\n%s", out)
	}
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		rp.t.Fatalf("the plane did not run: %v", err)
	}
	return exitOf(rp.t, err), string(out)
}

// TestAStdioPlaneServesTheRunItsTokenFileNames: a stdio plane serves the run
// whose token its file holds; a second process with the same token reaches
// the state the first left, while another run's process starts clean. Each
// process holds the spool alone, so one stops before the next starts. A
// token file another user could read, a closed run's token, a token of
// another project's run in the same directory and a record of major 1 each
// refuse the start.
func TestAStdioPlaneServesTheRunItsTokenFileNames(t *testing.T) {
	rp := newRunsPlane(t, "stdio")
	tainted, clean, closed, old := rp.open(), rp.open(), rp.open(), rp.open()
	rp.closeRun(closed.id)
	asMajorOne(t, rp.runs, old.id)
	foreign := rp.open("--project", "billing")
	tokens := t.TempDir()
	taintedFile := writeToken(t, tokens, "tainted.token", tainted.token, 0o600)

	first := rp.stdioAgent(taintedFile)
	expectRan(t, "the ticket read in the first process", callTool(t, first.cs, toolReadTicket))
	expectToxic(t, "the mail in the first process", callTool(t, first.cs, toolSendMail))
	first.stop(t)

	second := rp.stdioAgent(taintedFile)
	expectToxic(t, "the mail in a second process with the same token", callTool(t, second.cs, toolSendMail))
	second.stop(t)
	cleanAgent := rp.stdioAgent(writeToken(t, tokens, "clean.token", clean.token, 0o600))
	expectRan(t, "the mail of another run's process", callTool(t, cleanAgent.cs, toolSendMail))
	if ran := rp.up.count(toolSendMail); ran != 1 {
		t.Errorf("the upstream ran send_mail %d time(s), want the clean run's one", ran)
	}
	cleanAgent.stop(t)

	refusals := []struct{ name, file, says string }{
		{"a token file others can read", writeToken(t, tokens, "shared.token", clean.token, 0o644), "--run-token-file: files: the mode gives access the caller forbids"},
		{"a closed run's token", writeToken(t, tokens, "closed.token", closed.token, 0o600), "--run-token-file: run refused: closed"},
		{"another project's run", writeToken(t, tokens, "foreign.token", foreign.token, 0o600), "--run-token-file: run refused: identity"},
		{"a record of major 1", writeToken(t, tokens, "old.token", old.token, 0o600), "one of major 1 names no project: open the run again"},
	}
	for _, c := range refusals {
		status, out := rp.startRefused(c.file)
		if status != exitFail || !strings.Contains(out, c.says) {
			t.Errorf("%s: exit %d, output %q; want 1 naming %s", c.name, status, out, c.says)
		}
		if strings.Contains(out, clean.token) || strings.Contains(out, closed.token) || strings.Contains(out, foreign.token) || strings.Contains(out, old.token) {
			t.Errorf("%s: the refusal repeats the token: %q", c.name, out)
		}
	}
}

// TestDoctorSaysWhereRunsComeFrom: with runs.dir the runs line names the
// directory runs are opened in; without it, runs are local.
func TestDoctorSaysWhereRunsComeFrom(t *testing.T) {
	_, controlBin := builtBinaries(t)
	tr := newTree(t)
	var out bytes.Buffer
	doctor(context.Background(), tr.config, &out, &out)
	if line := runsLine(out.String()); !strings.HasPrefix(line, "ok      runs          local:") {
		t.Errorf("without runs.dir the runs line is %q, want local", line)
	}

	dir := filepath.Join(tr.dir, "runs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("making the runs directory: %v", err)
	}
	if raw, err := runBinary(controlBin, "runs", "open", "--project", "orders", "--tenant", "acme", "--principal-type", "service",
		"--principal", "agent-runner", "--agent", "orders-assistant", "--ttl", "1h", dir); err != nil {
		t.Fatalf("runs open: %v\n%s", err, raw)
	}
	setEnv(t, "runs.dir", dir)
	out.Reset()
	doctor(context.Background(), tr.config, &out, &out)
	want := "ok      runs          opened in " + filepath.ToSlash(dir) + ": "
	if line := runsLine(out.String()); !strings.HasPrefix(line, want) {
		t.Errorf("with runs.dir the runs line is %q, want it to start %q", line, want)
	}

	empty := filepath.Join(tr.dir, "empty-runs")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatalf("making an empty directory: %v", err)
	}
	setEnv(t, "runs.dir", empty)
	out.Reset()
	if status := doctor(context.Background(), tr.config, &out, &out); status != exitFail {
		t.Errorf("doctor on a directory no runs open made a runs directory exited %d, want %d", status, exitFail)
	}
	if line := runsLine(out.String()); !strings.HasPrefix(line, "fail    runs          runs.dir: ") {
		t.Errorf("on a directory that is not a runs directory the runs line is %q, want a failure", line)
	}
}

// runsLine is doctor's verdict line for runs.
func runsLine(out string) string {
	for _, line := range lines(out) {
		if fields := strings.Fields(line); len(fields) > 1 && fields[1] == "runs" {
			return line
		}
	}
	return ""
}
