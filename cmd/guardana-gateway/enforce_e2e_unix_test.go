//go:build unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/enforceclient"
)

const answering = "answering /healthz, /metrics and /brand on "

// servedPlane is a plane serve runs in this process until stop.
type servedPlane struct {
	health string
	out    *syncBuffer
	cancel context.CancelFunc
	done   chan int
}

func serveEnforce(t *testing.T, tr enforceTree) *servedPlane {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	sp := &servedPlane{out: &syncBuffer{}, cancel: cancel, done: make(chan int, 1)}
	go func() { sp.done <- serve(ctx, tr.config, "", sp.out, sp.out) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-sp.done:
		case <-time.After(30 * time.Second):
			t.Error("the plane did not stop")
		}
	})
	waitFor(t, sp.out, "listening for tools on "+tr.socket)
	sp.health = afterPrefix(waitFor(t, sp.out, answering), answering)
	return sp
}

// stop ends the plane and returns how run exited.
func (sp *servedPlane) stop(t *testing.T) int {
	t.Helper()
	sp.cancel()
	select {
	case status := <-sp.done:
		sp.done <- status
		return status
	case <-time.After(30 * time.Second):
		t.Fatal("the plane did not stop")
	}
	return -1
}

// enforceHealth reads /healthz.
func enforceHealth(t *testing.T, address string) map[string]any {
	t.Helper()
	resp, err := http.Get("http://" + address + "/healthz")
	if err != nil {
		t.Fatalf("reading /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var answer map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		t.Fatalf("decoding /healthz: %v", err)
	}
	return answer
}

// count reads a number at a path of /healthz's answer.
func healthCount(t *testing.T, answer map[string]any, section, key string) float64 {
	t.Helper()
	m, ok := answer[section].(map[string]any)
	if !ok {
		t.Fatalf("/healthz has no %s object: %v", section, answer)
	}
	n, ok := m[key].(float64)
	if !ok {
		t.Fatalf("/healthz %s.%s is %v", section, key, m[key])
	}
	return n
}

func metricsText(t *testing.T, address string) string {
	t.Helper()
	resp, err := http.Get("http://" + address + "/metrics")
	if err != nil {
		t.Fatalf("reading /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// trailOn waits until the collector holds a trail of a call on resource id
// whose last event is one of kinds, and returns it.
func trailOn(t *testing.T, c *acceptingCollector, id string, kinds ...controlv1.EventKind) []*controlv1.Event {
	t.Helper()
	var found []*controlv1.Event
	c.waitUntil(t, "the trail of "+id, func(events []*controlv1.Event) bool {
		for _, trail := range byRequest(events) {
			if trail[0].GetProposed().GetResource().GetId() != id {
				continue
			}
			for _, k := range kinds {
				if trail[len(trail)-1].GetKind() == k {
					found = trail
					return true
				}
			}
		}
		return false
	})
	return found
}

func hasKind(trail []*controlv1.Event, kind controlv1.EventKind) bool {
	for _, e := range trail {
		if e.GetKind() == kind {
			return true
		}
	}
	return false
}

// abandoned fails unless the trail closed as an execution nobody completed.
func abandoned(t *testing.T, what string, trail []*controlv1.Event) {
	t.Helper()
	last := trail[len(trail)-1]
	if last.GetKind() != controlv1.EventKind_EVENT_KIND_ACTION_FAILED ||
		last.GetResult().GetStatus() != controlv1.ResultStatus_RESULT_STATUS_UNKNOWN ||
		last.GetResult().GetToolProtocolStatus() != "EXECUTION_ABANDONED" {
		t.Errorf("%s closed as %v %v %q, want ACTION_FAILED UNKNOWN EXECUTION_ABANDONED", what, last.GetKind(),
			last.GetResult().GetStatus(), last.GetResult().GetToolProtocolStatus())
	}
}

const (
	kindBlocked   = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED
	kindCompleted = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
	kindFailed    = controlv1.EventKind_EVENT_KIND_ACTION_FAILED
	kindStarted   = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
)

// TestTheEnforcementAPIDecidesAndACooperatingClientEnforces is ADR-0051's
// end to end: one policy, one tool, a client that keeps the rules and one
// that does not. After a BLOCK the cooperating client never reaches the
// tool and the defecting one does, and neither trail shows ACTION_STARTED;
// an EXECUTE runs and completes with its trail closed; a handle nobody
// completes is abandoned by the sweep; a reported mismatch halts that run's
// material calls and no other run's; and the coverage map says decided, not
// enforced.
func TestTheEnforcementAPIDecidesAndACooperatingClientEnforces(t *testing.T) {
	collector := newAcceptingCollector(t)
	tr := newEnforceTree(t, "1s", collector.url)
	runA, runB := tr.openRun(t), tr.openRun(t)
	sp := serveEnforce(t, tr)
	tool := &toolFixture{}
	exec := func(_ context.Context, authorized []byte) (enforceclient.Result, error) {
		tool.run(authorized)
		return enforceclient.Result{Status: enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS}, nil
	}
	defecting := newRawClient(t, tr.socket, runA)
	blockBoth(t, collector, cooperatingClient(t, tr, runA), defecting, tool, exec)
	executeAndSweep(t, collector, sp, cooperatingClient(t, tr, runA), defecting, tool, exec)
	haltOneRun(t, sp, tr, tool, exec, defecting, runB)
	coverageSaysDecided(t, tr)
}

// blockBoth asks for a refund the policy denies through both clients: the
// cooperating one never reaches the tool, the defecting one does, and
// neither trail shows ACTION_STARTED.
func blockBoth(t *testing.T, collector *acceptingCollector, cooperating *enforceclient.Client, defecting *rawClient, tool *toolFixture, exec enforceclient.Exec) {
	t.Helper()
	ans, err := cooperating.Call(context.Background(), enforceRefund, []byte(`{"id":"ord-1"}`), exec)
	if !errors.Is(err, enforceclient.ErrBlocked) || ans.Ran || len(tool.ran) != 0 {
		t.Fatalf("the cooperating client's refund: %v, ran %t, tool ran %d time(s)", err, ans.Ran, len(tool.ran))
	}
	if resp := defecting.admit(enforceRefund, []byte(`{"id":"ord-2"}`)); resp.GetOutcome() != enforcev1alpha1.Outcome_OUTCOME_BLOCK {
		t.Fatalf("the defecting client's refund was answered %v", resp.GetOutcome())
	}
	tool.run([]byte(`{"id":"ord-2"}`))
	for _, id := range []string{"ord-1", "ord-2"} {
		trail := trailOn(t, collector, id, kindBlocked)
		if hasKind(trail, kindStarted) {
			t.Errorf("the trail of %s shows ACTION_STARTED", id)
		}
		if p := trail[0].GetProposed().GetAction().GetProtocol(); p != channel.ProtocolEnforce {
			t.Errorf("the enforcement API records protocol %q, the coverage join reads %q", p, channel.ProtocolEnforce)
		}
	}
	if len(tool.ran) != 1 || string(tool.ran[0]) != `{"id":"ord-2"}` {
		t.Fatalf("the tool ran with %q; want only the defecting client's call", tool.ran)
	}
}

// executeAndSweep runs an allowed read to its completion, then leaves one
// execution open past its lifetime for the sweep to abandon.
func executeAndSweep(t *testing.T, collector *acceptingCollector, sp *servedPlane, cooperating *enforceclient.Client, defecting *rawClient, tool *toolFixture, exec enforceclient.Exec) {
	t.Helper()
	ans, err := cooperating.Call(context.Background(), enforceRead, []byte(`{"id":"ord-3"}`), exec)
	if err != nil || !ans.Ran || ans.Ending != enforcev1alpha1.Ending_ENDING_RECORDED || string(tool.ran[1]) != `{"id":"ord-3"}` {
		t.Fatalf("the read: %v, ran %t, ending %v, tool ran with %q", err, ans.Ran, ans.Ending, tool.ran)
	}
	if trail := trailOn(t, collector, "ord-3", kindCompleted); !hasKind(trail, kindStarted) {
		t.Error("the read completed without ACTION_STARTED")
	}

	if resp := defecting.admit(enforceRead, []byte(`{"id":"ord-4"}`)); resp.GetOutcome() != enforcev1alpha1.Outcome_OUTCOME_EXECUTE {
		t.Fatalf("the read to abandon was answered %v", resp.GetOutcome())
	}
	abandoned(t, "the execution nobody completed", trailOn(t, collector, "ord-4", kindFailed, kindCompleted))
	if h := enforceHealth(t, sp.health); healthCount(t, h, "enforce", "abandoned") != 1 || healthCount(t, h, "enforce", "open_handles") != 0 ||
		healthCount(t, h, "pipeline", "abandoned") != 1 {
		t.Errorf("/healthz after the sweep: enforce %v, pipeline %v", h["enforce"], h["pipeline"])
	}
}

// haltOneRun reports other bytes than run A was authorized to send: run A's
// next material call is blocked, run B's runs, and both answers count it.
func haltOneRun(t *testing.T, sp *servedPlane, tr enforceTree, tool *toolFixture, exec enforceclient.Exec, defecting *rawClient, runB string) {
	t.Helper()
	resp := defecting.admit(enforceNote, []byte(`{"id":"ord-5"}`))
	if resp.GetOutcome() != enforcev1alpha1.Outcome_OUTCOME_EXECUTE {
		t.Fatalf("the note to misreport was answered %v", resp.GetOutcome())
	}
	if ending := defecting.complete(resp.GetExecution().GetHandle(), []byte(`{"id":"ord-6"}`)); ending != enforcev1alpha1.Ending_ENDING_RECORDED {
		t.Fatalf("the misreported note ended %v", ending)
	}
	before := len(tool.ran)
	if _, err := cooperatingClient(t, tr, defecting.token).Call(context.Background(), enforceNote, []byte(`{"id":"ord-7"}`), exec); !errors.Is(err, enforceclient.ErrBlocked) {
		t.Errorf("run A's note after its mismatch: %v, want blocked", err)
	}
	if ans, err := cooperatingClient(t, tr, runB).Call(context.Background(), enforceNote, []byte(`{"id":"ord-8"}`), exec); err != nil || !ans.Ran {
		t.Errorf("run B's note: %v, ran %t; another run's mismatch halted it", err, ans.Ran)
	}
	if len(tool.ran) != before+1 {
		t.Errorf("the tool ran %d time(s) for the two notes, want once", len(tool.ran)-before)
	}
	if h := enforceHealth(t, sp.health); healthCount(t, h, "pipeline", "runs_halted") != 1 || h["halted"] != false {
		t.Errorf("/healthz after one run's mismatch: halted %v, pipeline %v", h["halted"], h["pipeline"])
	}
	if text := metricsText(t, sp.health); !strings.Contains(text, "pipeline_runs_halted 1\n") {
		t.Errorf("/metrics does not count the halted run:\n%s", text)
	}
}

func cooperatingClient(t *testing.T, tr enforceTree, token string) *enforceclient.Client {
	t.Helper()
	c, err := enforceclient.New(enforceclient.Config{Socket: tr.socket, Token: token, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// coverageSaysDecided runs the built coverage command over the plane's own
// configuration: the tool is decided, not enforced, by a cooperating client.
func coverageSaysDecided(t *testing.T, tr enforceTree) {
	t.Helper()
	_, control := builtBinaries(t)
	inventory := filepath.Join(tr.dir, "inventory.json")
	if err := os.WriteFile(inventory, []byte(`{"schema_version":"0.1","paths":[{"id":"refund","kind":"enforce_tool","tool":"refund"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runBinary(control, "coverage", "--inventory", inventory, "--plane", tr.config)
	got := lines(out)
	if err != nil || len(got) < 2 || got[0] != "refund decided, not enforced: planes "+tr.config ||
		!strings.Contains(got[1], "ENFORCE; the tool table classifies it by name; a cooperating client enforces the decision") {
		t.Errorf("coverage: %v\n%s", err, out)
	}
}

// TestAStopAbandonsWhatIsOpen: a plane asked to stop closes every execution
// it handed out and nobody completed before its spool drains, and the next
// start ships that closing.
func TestAStopAbandonsWhatIsOpen(t *testing.T) {
	collector := newAcceptingCollector(t)
	tr := newEnforceTree(t, "1h", collector.url)
	token := tr.openRun(t)
	sp := serveEnforce(t, tr)
	defecting := newRawClient(t, tr.socket, token)
	if resp := defecting.admit(enforceRead, []byte(`{"id":"ord-9"}`)); resp.GetOutcome() != enforcev1alpha1.Outcome_OUTCOME_EXECUTE {
		t.Fatalf("the read to leave open was answered %v", resp.GetOutcome())
	}
	if h := enforceHealth(t, sp.health); healthCount(t, h, "enforce", "open_handles") != 1 {
		t.Errorf("/healthz with one execution open: %v", h["enforce"])
	}
	if text := metricsText(t, sp.health); !strings.Contains(text, "pipeline_open_executions 1\n") {
		t.Errorf("/metrics does not count the open execution")
	}
	if status := sp.stop(t); status != exitOK {
		t.Fatalf("run exited %d:\n%s", status, sp.out.String())
	}
	if _, err := os.Lstat(tr.socket); err == nil {
		t.Error("the socket outlived the plane")
	}
	serveEnforce(t, tr)
	abandoned(t, "the execution open at the stop", trailOn(t, collector, "ord-9", kindFailed, kindCompleted))
}
