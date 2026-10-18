package stopwrite_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/supervise"
)

// clock0 is the writer's and the plane's clock in most tests, and poll the
// plane's poll interval.
var clock0 = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

const poll = 30 * time.Second

var bg = context.Background()

var refundOnce struct {
	sync.Once
	digest string
	err    error
}

// refundDigest is the digest supervise gives the refund example's procedure,
// the spelling a finding record carries.
func refundDigest(t testing.TB) string {
	t.Helper()
	refundOnce.Do(func() {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "refund-supervision", "refund.procedure.json"))
		if err != nil {
			refundOnce.err = err
			return
		}
		p, err := supervise.ReadProcedure(raw)
		if err != nil {
			refundOnce.err = err
			return
		}
		refundOnce.digest = p.Digest()
	})
	if refundOnce.err != nil {
		t.Fatalf("the refund procedure: %v", refundOnce.err)
	}
	return refundOnce.digest
}

func seededKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

// liftKey signs lifts under every route here; otherKey is no route's.
func liftKey() ed25519.PrivateKey  { return seededKey(0x4c) }
func otherKey() ed25519.PrivateKey { return seededKey(0x4f) }

// routeOf is a route of tenant acme and serial with STEP_OUTSIDE_PROCEDURE
// stopping for at most an hour, and DEADLINE_EXCEEDED too when both is set.
func routeOf(t testing.TB, serial int, both bool) reaction.Route {
	t.Helper()
	return routeFor(t, serial, "acme", both)
}

// routeFor is routeOf for another tenant.
func routeFor(t testing.TB, serial int, tenant string, both bool) reaction.Route {
	t.Helper()
	pub := base64.StdEncoding.EncodeToString(liftKey().Public().(ed25519.PublicKey))
	rule := func(id, extra string) string {
		return `{"procedure_id":"refund","version":"1","digest":"` + refundDigest(t) + `","rule_id":"` + id + `","rule_version":"1"` + extra + `}`
	}
	rules := rule("STEP_OUTSIDE_PROCEDURE", `,"expires_seconds":3600`)
	if both {
		rules += "," + rule("DEADLINE_EXCEEDED", "")
	}
	doc := `{"kind":"reaction-route/v1alpha1","route_id":"refunds","serial":` + strconv.Itoa(serial) +
		`,"tenant_id":"` + tenant + `","scope":"run","lift_public_key":"` + pub + `","rules":[` + rules + `]}`
	r, err := reaction.ParseRoute([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRoute: %v", err)
	}
	return r
}

func testRoute(t testing.TB) reaction.Route { return routeOf(t, 3, false) }

func stopOf(t testing.TB, finding, run string, created time.Time) reaction.Stop {
	t.Helper()
	return reaction.Stop{
		EntryID: reaction.EntryID(finding), TenantID: "acme", RunID: run, FindingID: finding,
		ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: refundDigest(t),
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: created, ExpiresAt: created.Add(time.Hour),
	}
}

// appendFinding appends the finding of s, a stop made before the lock, at a
// clock that reads now.
func appendFinding(ctx context.Context, dir string, r reaction.Route, s reaction.Stop, now time.Time) (int64, bool, error) {
	n, _, covered, err := stopwrite.AppendFinding(ctx, dir, r, func() time.Time { return now },
		func(time.Time) (reaction.Stop, error) { return s, nil })
	return n, covered, err
}

func coveredOf(finding, run string, created time.Time) reaction.Covered {
	return reaction.Covered{FindingID: finding, TenantID: "acme", RunID: run, CreatedAt: created}
}

// liftOf is a lift line of run through line, signed by key for listID under
// route.
func liftOf(t testing.TB, key ed25519.PrivateKey, r reaction.Route, listID, run string, through int64) reaction.LiftLine {
	t.Helper()
	env, err := reaction.SignLift(reaction.Lift{
		Version: "1.0", ListID: listID, RouteDigest: r.Digest(), RunID: run, ThroughLine: through,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return reaction.LiftLine{RunID: run, ThroughLine: through, Envelope: env}
}

// must takes a marshalled line and fails the test on a refusal.
func must(t testing.TB) func([]byte, error) []byte {
	return func(line []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
}

// emptyDir is a fresh directory of mode 0700 holding nothing.
func emptyDir(t testing.TB) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "stops")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// initDir is a fresh directory holding a list Init started under r, and that
// list's header.
func initDir(t testing.TB, r reaction.Route) (string, reaction.Header) {
	t.Helper()
	dir := emptyDir(t)
	h, err := stopwrite.Init(bg, dir, r, clock0)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return dir, h
}

func listPath(dir string) string { return filepath.Join(dir, stoplist.FileName) }

func content(t testing.TB, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(listPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func setContent(t testing.TB, dir string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(listPath(dir), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// planeOn is a plane's poller over dir under r at clock0.
func planeOn(t testing.TB, dir string, r reaction.Route) *stoplist.Poller {
	t.Helper()
	p, err := stoplist.Open(stoplist.Options{Dir: dir, Route: r, Interval: poll, Clock: func() time.Time { return clock0 }})
	if err != nil {
		t.Fatalf("a plane's poller: %v", err)
	}
	return p
}
