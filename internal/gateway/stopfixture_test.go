package gateway_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/supervise"
)

const (
	codeRunStopped           = "RUN_STOPPED"
	codeSubjectStopped       = "AGENT_OR_PRINCIPAL_STOPPED"
	codeStopStateUnavailable = "STOP_STATE_UNAVAILABLE"

	stopInterval = time.Minute
)

// stopProcedure is the refund example's procedure as supervise reads it, so
// a stop names it as a finding record would.
func stopProcedure(t *testing.T) *supervise.Procedure {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "refund-supervision", "refund.procedure.json"))
	if err != nil {
		t.Fatalf("the refund procedure: %v", err)
	}
	p, err := supervise.ReadProcedure(raw)
	if err != nil {
		t.Fatalf("ReadProcedure: %v", err)
	}
	return p
}

// stopLiftKey signs lifts; derived from a seed at run time.
func stopLiftKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4c}, ed25519.SeedSize))
}

// stopRoute lets STEP_OUTSIDE_PROCEDURE of the refund procedure stop a run
// of tenant-1, the tenant opened() names, for at most an hour.
func stopRoute(t *testing.T) reaction.Route {
	t.Helper()
	p := stopProcedure(t)
	lift := base64.StdEncoding.EncodeToString(stopLiftKey().Public().(ed25519.PublicKey))
	doc := `{"kind":"reaction-route/v1alpha1","route_id":"refunds","serial":1,"tenant_id":"tenant-1","scope":"run",` +
		`"lift_public_key":"` + lift + `","rules":[{"procedure_id":"` + p.ID() + `","version":"` + p.Version() +
		`","digest":"` + p.Digest() + `","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","expires_seconds":3600}]}`
	r, err := reaction.ParseRoute([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRoute: %v", err)
	}
	return r
}

// stopList is a stop list written line by line.
type stopList struct {
	t     *testing.T
	route reaction.Route
	proc  *supervise.Procedure
	lines [][]byte
}

func newStopList(t *testing.T) *stopList {
	t.Helper()
	l := &stopList{t: t, route: stopRoute(t), proc: stopProcedure(t)}
	l.add(reaction.HeaderFor(l.route, "list-1").Marshal())
	return l
}

func (l *stopList) add(line []byte, err error) int64 {
	l.t.Helper()
	if err != nil {
		l.t.Fatalf("line %d: %v", len(l.lines)+1, err)
	}
	l.lines = append(l.lines, line)
	return int64(len(l.lines))
}

// stopFrom appends a stop of run created at created that lasts an hour, and
// returns its line.
func (l *stopList) stopFrom(run string, created time.Time) int64 {
	l.t.Helper()
	finding := "finding-" + run + "-" + strconv.Itoa(len(l.lines))
	return l.add(reaction.Stop{
		EntryID: reaction.EntryID(finding), TenantID: "tenant-1", RunID: run, FindingID: finding,
		ProcedureID: l.proc.ID(), ProcedureVersion: l.proc.Version(), ProcedureDigest: l.proc.Digest(),
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1",
		CreatedAt: created, ExpiresAt: created.Add(time.Hour),
	}.Marshal())
}

// stop appends a stop of run created at the second of base().
func (l *stopList) stop(run string) int64 { return l.stopFrom(run, base().Truncate(time.Second)) }

// lift appends a lift of run through line, signed under the route's lift key.
func (l *stopList) lift(run string, through int64) {
	l.t.Helper()
	env, err := reaction.SignLift(reaction.Lift{
		Version: "1.0", ListID: "list-1", RouteDigest: l.route.Digest(), RunID: run, ThroughLine: through,
	}, stopLiftKey())
	if err != nil {
		l.t.Fatalf("SignLift: %v", err)
	}
	l.add(reaction.LiftLine{RunID: run, ThroughLine: through, Envelope: env}.Marshal())
}

// readAt is the snapshot a plane reads of the list at at; the list has to be
// one the judge accepts.
func (l *stopList) readAt(at time.Time) reaction.Snapshot {
	l.t.Helper()
	var content []byte
	for _, line := range l.lines {
		content = append(append(content, line...), '\n')
	}
	s := reaction.Snapshot{}.Next(l.route, content, at, stopInterval)
	if s.State() == reaction.Unknown {
		l.t.Fatalf("the stop list read as unknown: %s: %s", s.Cause(), s.Detail())
	}
	return s
}

// stopped is the list read at base() with one active stop per run.
func stopped(t *testing.T, runs ...string) reaction.Snapshot {
	t.Helper()
	l := newStopList(t)
	for _, run := range runs {
		l.stop(run)
	}
	s := l.readAt(base())
	if len(runs) > 0 && s.State() != reaction.Stopped || len(runs) == 0 && s.State() != reaction.Clear {
		t.Fatalf("the stop list read as %s", s.State())
	}
	return s
}

// liftedAt is a list that stopped run and lifted it, read at at.
func liftedAt(t *testing.T, run string, at time.Time) reaction.Snapshot {
	t.Helper()
	l := newStopList(t)
	l.lift(run, l.stop(run))
	s := l.readAt(at)
	if s.State() != reaction.Clear {
		t.Fatalf("the lifted list read as %s", s.State())
	}
	return s
}

// stopSource serves its snapshots in order, one per read, the last
// repeating, and counts the reads.
type stopSource struct {
	mu    sync.Mutex
	snaps []reaction.Snapshot
	next  int
	reads atomic.Int64
}

func newStopSource(snaps ...reaction.Snapshot) *stopSource {
	return &stopSource{snaps: snaps}
}

func (s *stopSource) Current() reaction.Snapshot {
	s.reads.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.snaps[min(s.next, len(s.snaps)-1)]
	s.next++
	return snap
}

// set serves snaps from the next read on.
func (s *stopSource) set(snaps ...reaction.Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snaps, s.next = snaps, 0
}

// listener is the identity the plane's configuration names, the one
// readEnvelope and opened carry.
var listener = gateway.RunIdentity{TenantID: "tenant-1", PrincipalType: "user", PrincipalID: "user-1", AgentID: "agent-1"}

// withStops serves the stop state from s to a plane whose listener is
// listener.
func withStops(s gateway.StopSource) func(*gateway.Config) {
	return func(c *gateway.Config) { c.Stops, c.Listener = s, listener }
}

// stopPlane is a plane serving opened runs of root-1 and root-2 under src,
// whose harness admits every call under run-a of root-1.
func stopPlane(t *testing.T, mode controlv1.EnforcementMode, rules []string, src gateway.StopSource, mut ...func(*gateway.Config)) *harness {
	t.Helper()
	opts := append([]func(*gateway.Config){withRuns(newRuns("root-1", "root-2")), withStops(src)}, mut...)
	h := build(t, mode, snapshot(t, rules...), opts...)
	h.run = opened("run-a", "root-1")
	return h
}

// stopsRun reports whether an active entry of s, read with no age rule,
// stops run of tenant at now.
func stopsRun(s reaction.Snapshot, tenant, run string, now time.Time) bool {
	entries, _ := s.ActiveEntries(now, time.Time{})
	return slices.ContainsFunc(entries, func(e reaction.Entry) bool {
		return e.TenantID == tenant && e.Target() == reaction.Target{Scope: reaction.ScopeRun, Subject: run}
	})
}
