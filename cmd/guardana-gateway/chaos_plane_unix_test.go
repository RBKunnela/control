//go:build unix

package main

import (
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// TestAPauseFileSpoiledWhileThePlaneRunsBlocksEveryCall runs the built gateway
// over a clear pause file and spoils the file under it three ways. Once the
// plane has read each, a call is blocked with PAUSE_STATE_UNAVAILABLE and the
// upstream never sees it; once the file is whole again, the next call runs.
func TestAPauseFileSpoiledWhileThePlaneRunsBlocksEveryCall(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a file without read permission is readable to root, so the unreadable case cannot be made here")
	}
	dir := t.TempDir()
	pauseDir := filepath.Join(dir, "pause")
	if err := os.Mkdir(pauseDir, 0o700); err != nil {
		t.Fatalf("making the pause directory: %v", err)
	}
	path := filepath.Join(pauseDir, "pause.json")
	writePauseFile(t, path, pauseClear)
	collector := newAcceptingCollector(t)
	orders := newHTTPUpstream(t, answerEvery, toolReadOrder)
	plane := startChaosPlane(t, dir, chaosSetup{
		document: chaosDocument, collector: collector.url,
		upstreams: []chaosUpstream{{name: "orders", endpoint: orders.url}},
		tools:     []classified{{"orders", toolReadOrder, "READ"}},
		extra:     "pause:\n  file: pause/pause.json\n  poll_interval: 1s\n",
	})
	agent := connectAgent(t, plane.listen)
	pauseState := func(want string) func(map[string]any) bool {
		return func(body map[string]any) bool { return member(body, "pause", "state") == want }
	}

	res, err := chaosCall(t, agent, toolReadOrder, "o-clear")
	ran(t, res, err, "a call under a clear pause file")
	for _, c := range []struct {
		name  string
		spoil func(t *testing.T)
	}{
		{"garbled", func(t *testing.T) { writePauseFile(t, path, `{"schema_version":"2","entries":[`) }},
		{"unreadable", func(t *testing.T) {
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
		}},
		{"removed", func(t *testing.T) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		c.spoil(t)
		plane.waitHealth(t, "the pause state is unknown after the file was "+c.name, pauseState("unknown"))
		before := orders.count(toolReadOrder.Name)
		res, err = chaosCall(t, agent, toolReadOrder, "o-"+c.name)
		blockedWith(t, res, err, "PAUSE_STATE_UNAVAILABLE", "a call under a pause file that was "+c.name)
		if got := orders.count(toolReadOrder.Name); got != before {
			t.Fatalf("a call under a pause file that was %s reached the upstream", c.name)
		}

		if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("making the pause file writable again: %v", err)
		}
		writePauseFile(t, path, pauseClear)
		plane.waitHealth(t, "the pause state is clear again after the file was "+c.name, pauseState("clear"))
		res, err = chaosCall(t, agent, toolReadOrder, "o-restored-"+c.name)
		ran(t, res, err, "the call after the "+c.name+" file was restored")
	}
	if got := orders.count(toolReadOrder.Name); got != 4 {
		t.Errorf("the upstream ran %d call(s), want the 4 made under a clear pause file", got)
	}
	collector.waitUntil(t, "seven closed trails", allClosed(7))
	events := collector.events(t)
	validChains(t, events)
	for _, name := range []string{"garbled", "unreadable", "removed"} {
		endedBlocked(t, events, toolReadOrder.Name, "o-"+name, "PAUSE_STATE_UNAVAILABLE")
	}
}

// TestAWrongOrAbsentDecisionPointBlocksOnARunningPlane runs the built gateway
// with a veto on reads. Every answer the plane cannot read as an allow or a
// deny, contradictory ones included, blocks the read with PDP_ANSWER_REFUSED;
// a plain allow then runs it; and a decision point that is gone blocks it with
// PDP_UNAVAILABLE. The upstream sees only the allowed call.
func TestAWrongOrAbsentDecisionPointBlocksOnARunningPlane(t *testing.T) {
	dp := &pdpDouble{answer: `{"decision":true}`, eval: evaluationPath, arrived: make(chan struct{}, 64)}
	ts := httptest.NewServer(dp)
	t.Cleanup(ts.Close)
	dp.url = ts.URL
	collector := newAcceptingCollector(t)
	orders := newHTTPUpstream(t, answerEvery, toolReadOrder)
	plane := startChaosPlane(t, t.TempDir(), chaosSetup{
		document: chaosVetoDocument, collector: collector.url,
		upstreams: []chaosUpstream{{name: "orders", endpoint: orders.url}},
		tools:     []classified{{"orders", toolReadOrder, "READ"}},
		extra:     "pdp:\n  identifier: " + dp.url + "\n  allow_plaintext: true\n  timeout: 20s\n",
	})
	agent := connectAgent(t, plane.listen)
	set := func(answer string) {
		dp.mu.Lock()
		dp.answer = answer
		dp.mu.Unlock()
	}

	refused := []string{
		`{"decision":false,"decision":true}`,
		`{"decision":true,"decision":true}`,
		`{"decision":"true"}`,
		`{"decision":true`,
		`{"decision":true}{"decision":true}`,
		`{"decision":true,"reason":"ok"}`,
		`{}`,
	}
	for i, answer := range refused {
		set(answer)
		res, err := chaosCall(t, agent, toolReadOrder, "o-"+strconv.Itoa(i))
		blockedWith(t, res, err, "PDP_ANSWER_REFUSED", "a read under the answer "+answer)
	}
	if got := orders.count(toolReadOrder.Name); got != 0 {
		t.Fatalf("the upstream ran %d read(s) that no answer allowed", got)
	}

	set(`{"decision":true}`)
	res, err := chaosCall(t, agent, toolReadOrder, "o-allowed")
	ran(t, res, err, "a read the decision point allows")

	ts.Close()
	res, err = chaosCall(t, agent, toolReadOrder, "o-gone")
	blockedWith(t, res, err, "PDP_UNAVAILABLE", "a read with the decision point gone")
	if got := orders.count(toolReadOrder.Name); got != 1 {
		t.Errorf("the upstream ran %d read(s), want the one allowed", got)
	}
	collector.waitUntil(t, "nine closed trails", allClosed(9))
	events := collector.events(t)
	validChains(t, events)
	for i := range refused {
		endedBlocked(t, events, toolReadOrder.Name, "o-"+strconv.Itoa(i), "PDP_ANSWER_REFUSED")
	}
	endedBlocked(t, events, toolReadOrder.Name, "o-gone", "PDP_UNAVAILABLE")
}

// TestACollectorThatIsGoneBlocksNoCallAndGetsEveryRecordBack runs the built
// gateway exporting to a socket nothing listens on. Calls run, the spool
// keeps their records and the exporter counts its failed sends; once a
// collector listens there, every record of every trail arrives.
func TestACollectorThatIsGoneBlocksNoCallAndGetsEveryRecordBack(t *testing.T) {
	socket := exportSocket(t)
	orders := newHTTPUpstream(t, answerEvery, toolReadOrder)
	plane := startChaosPlane(t, t.TempDir(), chaosSetup{
		document: chaosDocument, collector: "unix://" + socket,
		upstreams: []chaosUpstream{{name: "orders", endpoint: orders.url}},
		tools:     []classified{{"orders", toolReadOrder, "READ"}},
	})
	agent := connectAgent(t, plane.listen)

	const calls = 3
	for i := range calls {
		res, err := chaosCall(t, agent, toolReadOrder, "o-"+strconv.Itoa(i))
		ran(t, res, err, "a read with no collector listening")
	}
	plane.waitHealth(t, "the exporter failed to reach the collector", func(body map[string]any) bool {
		retried, _ := member(body, "exporter", "retried_transport").(float64)
		return retried > 0
	})
	body := plane.healthz(t)
	if unack, _ := member(body, "spool", "unacknowledged").(float64); unack <= 0 {
		t.Fatalf("the spool holds nothing unacknowledged with no collector: %v", member(body, "spool"))
	}
	if acked, ok := member(body, "exporter", "acknowledged").(float64); !ok || acked != 0 {
		t.Fatalf("the exporter reports %v acknowledged with no collector, want 0", member(body, "exporter", "acknowledged"))
	}

	collector := collectorBackAt(t, socket)
	collector.waitUntil(t, "every trail of the outage", allClosed(calls))
	events := collector.events(t)
	validChains(t, events)
	for _, trail := range byRequest(events) {
		if last := trail[len(trail)-1].GetKind(); last != controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED {
			t.Errorf("a trail of the outage ends %v, want ACTION_COMPLETED", last)
		}
	}
	plane.waitHealth(t, "the spool is drained", func(body map[string]any) bool {
		unack, ok := member(body, "spool", "unacknowledged").(float64)
		return ok && unack == 0
	})
}

// fillSpool makes writes until the first is blocked for the spool being full,
// holds the number that ran to the budget, and returns it.
func fillSpool(t *testing.T, plane *chaosPlane, agent *sdk.ClientSession) int {
	t.Helper()
	const fillBound = 200
	runs, before, trail := 0, spoolBytes(t, plane), int64(0)
	for ; runs < fillBound; runs++ {
		res, err := chaosCall(t, agent, toolPostEntry, "e-"+strconv.Itoa(runs))
		if err == nil && res.IsError {
			blockedWith(t, res, err, "EVIDENCE_UNAVAILABLE", "the write that found the spool full")
			break
		}
		ran(t, res, err, "a write while the spool has room")
		if runs == 0 {
			trail = spoolBytes(t, plane) - before
		}
	}
	if runs == 0 || runs == fillBound {
		t.Fatalf("%d write(s) ran before the first block; the budget should stop a handful short of %d", runs, fillBound)
	}
	checkFilledAtTheBudget(t, runs, before, trail, spoolBytes(t, plane))
	return runs
}

// The evidence budget the full-spool test configures, and how far one trail's
// size may stray from the first one's, its ids and times spelled longer.
const (
	fullBudget  = 32 << 10
	fullReserve = 4 << 10
	trailSlack  = 32
)

// checkFilledAtTheBudget holds the writes that ran before the first block to
// the configured budget: their trails fit in it, and one more trail with its
// closing reservation would not have, so a budget twice as large, or half,
// lets a different number run. before is the spool's size before the first
// write, and onDisk its size at the block.
func checkFilledAtTheBudget(t *testing.T, runs int, before, trail, onDisk int64) {
	t.Helper()
	if trail <= trailSlack {
		t.Fatalf("one write's trail measured %d bytes, which bounds nothing", trail)
	}
	n := int64(runs)
	if before+n*(trail-trailSlack) > fullBudget || onDisk > fullBudget {
		t.Errorf("%d write(s) of a %d-byte trail ran and the spool holds %d bytes, past the %d-byte budget", runs, trail, onDisk, fullBudget)
	}
	if before+(n+1)*(trail+trailSlack)+fullReserve <= fullBudget {
		t.Errorf("only %d write(s) of a %d-byte trail ran, and one more with its %d-byte reservation fits in the %d-byte budget",
			runs, trail, fullReserve, fullBudget)
	}
}

// spoolBytes is what the plane's spool holds on disk, as /healthz says.
func spoolBytes(t *testing.T, plane *chaosPlane) int64 {
	t.Helper()
	bytes, ok := member(plane.healthz(t), "spool", "bytes").(float64)
	if !ok {
		t.Fatal("/healthz names no spool bytes")
	}
	return int64(bytes)
}

// collectorBackAt starts a collector that accepts everything on the socket
// a plane was exporting to while nothing listened there.
func collectorBackAt(t *testing.T, socket string) *acceptingCollector {
	t.Helper()
	back, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("the collector's socket was taken while it was gone: %v", err)
	}
	collector := &acceptingCollector{url: "unix://" + socket}
	srv := &http.Server{Handler: http.HandlerFunc(collector.serve), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(back) }()
	t.Cleanup(func() { _ = srv.Close() })
	return collector
}

// TestAFullSpoolBlocksCallsUntilTheCollectorDrainsIt runs the built gateway
// with a small evidence budget and no collector listening. Material calls run
// until the spool is full; from then on a write and a read are each blocked
// with EVIDENCE_UNAVAILABLE and never reach the upstream. Once a collector
// listens and the spool drains, the next write runs.
func TestAFullSpoolBlocksCallsUntilTheCollectorDrainsIt(t *testing.T) {
	socket := exportSocket(t)
	ledger := newHTTPUpstream(t, answerEvery, toolPostEntry, toolReadOrder)
	plane := startChaosPlane(t, t.TempDir(), chaosSetup{
		document: chaosDocument, collector: "unix://" + socket,
		upstreams: []chaosUpstream{{name: "ledger", endpoint: ledger.url}},
		tools:     []classified{{"ledger", toolPostEntry, "WRITE"}, {"ledger", toolReadOrder, "READ"}},
		evidence:  "  max_bytes: 32KiB\n  segment_bytes: 8KiB\n  closing_reserve: 4KiB\n",
	})
	agent := connectAgent(t, plane.listen)

	runs := fillSpool(t, plane, agent)
	if got := ledger.count(toolPostEntry.Name); got != runs {
		t.Fatalf("the upstream ran %d write(s) and the agent saw %d run", got, runs)
	}
	res, err := chaosCall(t, agent, toolPostEntry, "e-again")
	blockedWith(t, res, err, "EVIDENCE_UNAVAILABLE", "a write on the full spool")
	res, err = chaosCall(t, agent, toolReadOrder, "o-full")
	blockedWith(t, res, err, "EVIDENCE_UNAVAILABLE", "a read on the full spool")
	if got := ledger.count(toolPostEntry.Name) + ledger.count(toolReadOrder.Name); got != runs {
		t.Fatalf("the upstream ran %d call(s) in all, want the %d before the spool filled", got, runs)
	}

	collector := collectorBackAt(t, socket)
	plane.waitHealth(t, "the spool is drained", func(body map[string]any) bool {
		unack, ok := member(body, "spool", "unacknowledged").(float64)
		return ok && unack == 0
	})
	res, err = chaosCall(t, agent, toolPostEntry, "e-after")
	ran(t, res, err, "a write once the collector drained the spool")
	collector.waitUntil(t, "the trail of the write after the drain", func(events []*controlv1.Event) bool {
		for _, trail := range byRequest(events) {
			if trail[0].GetProposed().GetResource().GetId() == "e-after" && closedTrail(trail) {
				return true
			}
		}
		return false
	})
	validChains(t, collector.events(t))
}
