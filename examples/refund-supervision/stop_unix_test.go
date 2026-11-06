//go:build unix

package refundsupervision

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// routeFlags names the signed route and the route key's public file, where
// plane.yaml's reaction keys name them, for the stops commands and react.
var routeFlags = []string{"--route", "state/route.signed.json", "--public-key", "state/route.pub"}

// makeRoute makes the route key and the lift key, fills the lift key into
// route.json, signs it, gives its id a route floor and starts an empty stop
// list, each where plane.yaml's reaction keys look. It returns the lift key's
// private file.
func (tr tree) makeRoute(t *testing.T) string {
	t.Helper()
	must(t, tr.root, tr.control, "policy", "keygen", "--out", "keys/route")
	lift := values(must(t, tr.root, tr.control, "policy", "keygen", "--out", "keys/lift"))
	doc := readFile(t, "route.json")
	if strings.Count(doc, liftPlaceholder) != 1 || lift["public_key"] == "" {
		t.Fatalf("route.json holds %s %d times, and keygen printed %q", liftPlaceholder, strings.Count(doc, liftPlaceholder), lift)
	}
	writeFile(t, tr.path("route.json"), strings.Replace(doc, liftPlaceholder, lift["public_key"], 1))
	signed := values(must(t, tr.root, tr.control, "route", "sign", "--key", "keys/route/signing.key",
		"--out", tr.path("state", "route.signed.json"), tr.path("route.json")))
	writeFile(t, tr.path("state", "route.pub"), readFile(t, filepath.Join(tr.root, "keys", "route", "signing.pub")))
	must(t, tr.dir, tr.control, "policy", "state", "init", "--kind", "route", "--route-id", "refunds", "state/routefloor")
	if err := os.Mkdir(tr.path("state", "stops"), 0o700); err != nil {
		t.Fatal(err)
	}
	list := values(must(t, tr.dir, tr.control, append(append([]string{"stops", "init"}, routeFlags...), "state/stops")...))
	if signed["route_id"] != "refunds" || signed["serial"] != "1" || list["route_id"] != "refunds" ||
		list["route_digest"] != signed["digest"] || list["list_id"] == "" {
		t.Fatalf("route sign printed %q and stops init %q, want one route, refunds at serial 1", signed, list)
	}
	return filepath.Join(tr.root, "keys", "lift", "signing.key")
}

// livePlane is a running plane's health address and the agents of the two
// runs it serves.
type livePlane struct {
	health        string
	first, second *refundAgent
}

// stopAndLift stops the first run on the supervision's REPEATED_DENIAL, then
// lifts the stop: once the plane reads the lift, the first run's call runs
// again. It returns the refused call's request id.
func (tr tree) stopAndLift(t *testing.T, pl livePlane, first openedRun, s supervision, liftKey string) string {
	t.Helper()
	refused := tr.stop(t, pl, first, s, "REPEATED_DENIAL", 1)
	lift := append(append([]string{"stops", "lift"}, routeFlags...), "--key", liftKey, "--run", first.id, "state/stops")
	if out := must(t, tr.dir, tr.control, lift...); out != "lift line 3 run "+first.id+" through line 2\n" {
		t.Fatalf("stops lift printed %q, want a lift of run %s through line 2", out, first.id)
	}
	if out := tr.stops(t); strings.Contains(out, "\nstop line ") || !strings.Contains(out, "\ncovered: 0, lifts: 1\n") {
		t.Fatalf("stops list printed %q after the lift, want no stop and one lift", out)
	}
	waitForStops(t, pl.health, "clear", 0)
	expectOwnOrder(t, "the first run's call after the lift", pl.first.call(t, newSpan(91), "read_order", map[string]string{"id": "ord-1"}))
	return refused
}

// stop turns the supervision's confirmed finding of rule into a stop of the
// first run while the plane serves both runs: once the plane reads the stop,
// the first run's next call is refused RUN_STOPPED and the second run's call
// runs. It returns the refused call's request id.
func (tr tree) stop(t *testing.T, pl livePlane, first openedRun, s supervision, rule string, notStopping int) string {
	t.Helper()
	tr.react(t, first, s, rule, notStopping)
	waitForStops(t, pl.health, "stopped", 1)
	refused := pl.first.call(t, newSpan(90), "read_order", map[string]string{"id": "ord-1"})
	if !refused.Result.IsError || refused.codes() != `["RUN_STOPPED"]` || refused.meta("request_id") == "" {
		t.Fatalf("the stopped run's call answered %+v, want a block by RUN_STOPPED", refused)
	}
	expectOwnOrder(t, "the other run's call under the stop", pl.second.call(t, newSpan(1), "read_order", map[string]string{"id": "ord-1"}))
	return refused.meta("request_id")
}

// react runs react over the supervision's findings twice: the first writes
// one stop of the first run, for the confirmed finding of rule and none of
// the notStopping others, lasting as long as the run, and the second writes
// nothing. stops list then shows the stop active.
func (tr tree) react(t *testing.T, first openedRun, s supervision, rule string, notStopping int) {
	t.Helper()
	react := append([]string{"react", "--findings", s.dir, "--runs", "state/runs", "--stops", "state/stops"}, routeFlags...)
	expires, err := time.Parse(time.RFC3339Nano, first.expiresAt)
	if err != nil {
		t.Fatalf("runs open printed expires_at %q: %v", first.expiresAt, err)
	}
	// A stop lasts through the run's last instant: its expiry rounded up to
	// the whole second a line spells.
	if expires.Nanosecond() != 0 {
		expires = expires.Truncate(time.Second).Add(time.Second)
	}
	until := expires.UTC().Format("2006-01-02T15:04:05Z")
	finding := s.finding(rule).GetFinding().GetFindingId()
	stop := "stop line 2 run " + first.id + " finding " + finding + " rule " + rule
	if out := must(t, tr.dir, tr.control, react...); out != stop+" expires_at "+until+"\n"+
		fmt.Sprintf("stops 1, covered 0, already named 0, not stopping %d, not written 0\n", notStopping) {
		t.Fatalf("react printed %q, want one stop of run %s until %s", out, first.id, until)
	}
	if out := must(t, tr.dir, tr.control, react...); out != fmt.Sprintf("stops 0, covered 0, already named 1, not stopping %d, not written 0\n", notStopping) {
		t.Fatalf("react run again printed %q, want nothing written", out)
	}
	if out := tr.stops(t); !strings.Contains(out, "\n"+stop+" created_at ") ||
		!strings.Contains(out, " expires_at "+until+" active\n") || !strings.Contains(out, "\ncovered: 0, lifts: 0\n") {
		t.Fatalf("stops list printed %q, want the stop active", out)
	}
}

func (tr tree) stops(t *testing.T) string {
	t.Helper()
	return must(t, tr.dir, tr.control, append(append([]string{"stops", "list"}, routeFlags...), "state/stops")...)
}

func expectOwnOrder(t *testing.T, what string, a answer) {
	t.Helper()
	if a.Result.IsError || !strings.HasPrefix(a.text(), "order ord-1: ") {
		t.Fatalf("%s answered %+v, want the order", what, a)
	}
}

// waitForStops reads the plane's /healthz until its stop state is state with
// active stops of runs the runs directory holds, within ten seconds. /healthz
// names no run; the calls that follow show which run is stopped.
func waitForStops(t *testing.T, health, state string, active int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := stopsHealth(t, health)
		if got.State == state && got.Active == active && got.Unheld == 0 && got.Unread == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("/healthz said stops %+v within 10s, want %q with %d active", got, state, active)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type stopsState struct {
	State  string `json:"state"`
	Active int    `json:"active"`
	Unheld int    `json:"unheld"`
	Unread int    `json:"unread"`
}

func stopsHealth(t *testing.T, health string) stopsState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+health+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("reading /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var answer struct {
		Stops stopsState `json:"stops"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		t.Fatalf("decoding /healthz: %v", err)
	}
	return answer.Stops
}

// expectStoppedTrail exports the trail of the refused request: the plane
// proposed and decided it as the first run's, blocked it RUN_STOPPED, and
// never started it.
func (tr tree) expectStoppedTrail(t *testing.T, request, run string) {
	t.Helper()
	var kinds, blocked []string
	lines := bufio.NewScanner(strings.NewReader(must(t, tr.dir, tr.gateway, "trail", "export", "--request", request, trailDir)))
	for lines.Scan() {
		var record struct {
			Type  string          `json:"type"`
			Event json.RawMessage `json:"event"`
		}
		if err := json.Unmarshal(lines.Bytes(), &record); err != nil {
			t.Fatalf("the export line %q: %v", lines.Text(), err)
		}
		if record.Type != "event" {
			continue
		}
		e := &controlv1.Event{}
		if err := protojson.Unmarshal(record.Event, e); err != nil {
			t.Fatalf("the exported event %s: %v", record.Event, err)
		}
		if e.GetRunId() != run {
			t.Errorf("the refused call's %s names run %q, want %q", e.GetKind(), e.GetRunId(), run)
		}
		kinds = append(kinds, e.GetKind().String())
		if e.GetKind() == controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED {
			blocked = e.GetDecision().GetReasonCodes()
		}
	}
	// The export holds the trail in the order the plane's batches landed,
	// which need not be the order its links give.
	slices.Sort(kinds)
	want := []string{"EVENT_KIND_ACTION_BLOCKED", "EVENT_KIND_ACTION_PROPOSED", "EVENT_KIND_POLICY_DECIDED"}
	if !slices.Equal(kinds, want) || !slices.Equal(blocked, []string{"RUN_STOPPED"}) {
		t.Fatalf("the refused call's trail is %q, blocked with %q; want %q, blocked with RUN_STOPPED", kinds, blocked, want)
	}
}
