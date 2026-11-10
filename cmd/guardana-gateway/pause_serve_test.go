package main

import (
	"context"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/pause"
)

// servePoll is the shortest interval the configuration takes, and
// biteMargin what a pause may take past it to bite on a loaded machine.
const (
	servePoll  = 100 * time.Millisecond
	biteMargin = 400 * time.Millisecond
)

// TestAPauseBitesOnAServingPlaneAndLifts is the command line's plane end to
// end: a pause written by the writer the pause command calls blocks the next
// call within one interval, its removal lets the call after through, the log
// names the entries that changed and never a reason, and every trail the
// collector took validates.
func TestAPauseBitesOnAServingPlaneAndLifts(t *testing.T) {
	tr := newTree(t)
	collector := newAcceptingCollector(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	exportTo(t, collector.url)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "")
	path := tr.withPauseFile(t, pauseClear, servePoll)
	agent, stderr := serveInProcess(t, tr)

	if res := callReadOrder(t, agent); res.IsError {
		t.Fatalf("a call under a clear pause file was refused: %+v", res.StructuredContent)
	}
	changes := strings.Count(stderr.String(), "pause state changed")

	scope := pause.Scope{Kind: pause.ScopeAction, Action: pause.ActionTool, Provider: "orders", Name: "read_order"}
	entry := pause.Entry{ID: "stop-read-order", Scope: scope, CreatedAt: time.Now(), Reason: "the reason is never logged"}
	if err := pause.Add(context.Background(), path, entry); err != nil {
		t.Fatalf("Add: %v", err)
	}
	waitForChange(t, stderr, changes+1, "added=[stop-read-order]")
	res := callReadOrder(t, agent)
	if codes, _ := planeFields(res.Meta)["reason_codes"].([]any); !res.IsError || len(codes) != 1 || codes[0] != "PAUSED" {
		t.Fatalf("a paused call came back as %+v", res)
	}

	if err := pause.Remove(context.Background(), path, entry.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	waitForChange(t, stderr, changes+2, "removed=[stop-read-order]")
	if res := callReadOrder(t, agent); res.IsError {
		t.Fatalf("the call after the lift was refused: %+v", res.StructuredContent)
	}
	if strings.Contains(stderr.String(), entry.Reason) {
		t.Errorf("the plane logged a pause's reason:\n%s", stderr.String())
	}
	expectOnePausedTrail(t, collector)
}

// serveInProcess runs the command's own serve over the tree until the test
// ends, and returns an agent connected to it and what it logs.
func serveInProcess(t *testing.T, tr tree) (*sdk.ClientSession, *syncBuffer) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	status := make(chan int, 1)
	go func() { status <- serve(ctx, tr.config, "", stdout, stderr) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-status:
		case <-time.After(15 * time.Second):
			t.Error("the plane did not stop within its bound")
		}
	})
	const says = "listening for agents on "
	line := waitFor(t, stdout, says)
	return connectAgent(t, strings.TrimSpace(line[strings.Index(line, says)+len(says):])), stderr
}

// expectOnePausedTrail waits for the three calls' trails to close at the
// collector, validates each, and holds the one that ends blocked to PAUSED.
func expectOnePausedTrail(t *testing.T, collector *acceptingCollector) {
	t.Helper()
	collector.waitUntil(t, "three closed trails", func(events []*controlv1.Event) bool {
		trails := byRequest(events)
		for _, trail := range trails {
			if !closedTrail(trail) {
				return false
			}
		}
		return len(trails) == 3
	})
	blocked := 0
	for id, trail := range byRequest(collector.events(t)) {
		if err := evidence.ValidateChain(trail); err != nil {
			t.Errorf("ValidateChain over the trail of %s: %v\n%s", id, err, kinds(trail))
		}
		if last := trail[len(trail)-1]; last.GetKind() == controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED {
			blocked++
			if codes := last.GetDecision().GetReasonCodes(); len(codes) == 0 || codes[0] != "PAUSED" {
				t.Errorf("the blocked trail's decision says %v, want PAUSED first", codes)
			}
		}
	}
	if blocked != 1 {
		t.Errorf("%d trail(s) end blocked, want the one paused call", blocked)
	}
}

// waitForChange waits until the plane has logged the snapshot's change count
// times and the latest names what, within one poll interval and a margin of
// the moment it was called: a pause bites within one interval of its write.
func waitForChange(t *testing.T, log *syncBuffer, count int, what string) {
	t.Helper()
	deadline := time.Now().Add(servePoll + biteMargin)
	for time.Now().Before(deadline) {
		out := log.String()
		if strings.Count(out, "pause state changed") >= count {
			lines := strings.Split(strings.TrimSpace(out), "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				if strings.Contains(lines[i], "pause state changed") {
					if !strings.Contains(lines[i], what) {
						t.Fatalf("the change logged is %q, which does not name %q", lines[i], what)
					}
					return
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("within %v of the write the plane logged no change naming %q:\n%s", servePoll+biteMargin, what, log.String())
}

// callReadOrder calls the fixture upstream's one tool.
func callReadOrder(t *testing.T, cs *sdk.ClientSession) *sdk.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "read_order", Arguments: map[string]any{"id": "ord-1"}})
	if err != nil {
		t.Fatalf("the plane answered an error instead of a result: %v", err)
	}
	return res
}

// closedTrail reports whether a trail ends in an event nothing follows.
func closedTrail(trail []*controlv1.Event) bool {
	switch trail[len(trail)-1].GetKind() {
	case controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED, controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED,
		controlv1.EventKind_EVENT_KIND_ACTION_FAILED:
		return true
	default:
		return false
	}
}
