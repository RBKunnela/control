package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/runs"
)

// Fixtures for route sign, the stops commands and react. Every value a test
// compares against is spelled here or computed apart from the code under
// test.

// stopProcDigest is the refund procedure's digest as a finding names it.
const stopProcDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// stopRouteDoc is a route for tenant acme's refund procedure: a repeated
// denial stops a run for ten minutes, a step outside the procedure for as
// long as the run lives. LIFTKEY and SERIAL are filled in.
const stopRouteDoc = `{"kind":"reaction-route/v1alpha1","route_id":"refund-stops","serial":SERIAL,` +
	`"tenant_id":"acme","scope":"run","lift_public_key":"LIFTKEY","rules":[` +
	`{"procedure_id":"refund","version":"1","digest":"` + stopProcDigest + `",` +
	`"rule_id":"REPEATED_DENIAL","rule_version":"2","expires_seconds":600},` +
	`{"procedure_id":"refund","version":"1","digest":"` + stopProcDigest + `",` +
	`"rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1"}]}`

// otherTenant opens the run of a tenant the route does not name.
var otherTenant = runs.Identity{TenantID: "globex", PrincipalType: "user", PrincipalID: "bob", AgentID: "planner"}

// seeded is a key whose seed is one byte repeated, derived at run time so
// no key text is in the tree.
func seeded(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func routeDoc(lift ed25519.PrivateKey, serial int) string {
	line := base64.StdEncoding.EncodeToString(lift.Public().(ed25519.PublicKey))
	return strings.NewReplacer("LIFTKEY", line, "SERIAL", fmt.Sprint(serial)).Replace(stopRouteDoc)
}

// stopTree is an owner-only directory holding a runs directory with the
// runs a test reacts to, a findings directory, a stops directory with a
// list started under the route, the route and lift key pairs and the route
// signed under the route key.
type stopTree struct {
	dir, runs, findings, stops         string
	routeKey, routePub, liftKey        string
	route                              string
	parsed                             reaction.Route
	open, second, child, closed, alien string
}

func ownerDir(t *testing.T, path string) string {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func newStopTree(t *testing.T) stopTree {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: an owner-only directory, which the owner must enter
		t.Fatal(err)
	}
	tr := stopTree{dir: dir, runs: ownerDir(t, filepath.Join(dir, "runs")),
		findings: ownerDir(t, filepath.Join(dir, "findings")), stops: ownerDir(t, filepath.Join(dir, "stops")),
		routeKey: filepath.Join(dir, "route-key", policykey.PrivateFile),
		routePub: filepath.Join(dir, "route-key", policykey.PublicFile),
		liftKey:  filepath.Join(dir, "lift-key", policykey.PrivateFile),
		route:    filepath.Join(dir, "route.signed")}
	for path, key := range map[string]ed25519.PrivateKey{tr.routeKey: seeded(0x52), tr.liftKey: seeded(0x4c)} {
		if err := policykey.WriteKeyPair(filepath.Dir(path), key); err != nil {
			t.Fatal(err)
		}
	}
	tr.parsed = signRouteFile(t, tr.route, routeDoc(seeded(0x4c), 1), seeded(0x52))
	tr.open = openRun(t, tr.runs, who, "1h").runID
	tr.second = openRun(t, tr.runs, who, "1h").runID
	tr.child = openRun(t, tr.runs, who, "30m", "--parent", tr.second).runID
	tr.closed = openRun(t, tr.runs, who, "1h").runID
	if code, _, stderr := invoke(t, "runs", "close", tr.runs, tr.closed); code != exitOK {
		t.Fatalf("runs close answered %d: %q", code, stderr)
	}
	tr.alien = openRun(t, tr.runs, otherTenant, "1h").runID
	if _, err := stopwrite.Init(context.Background(), tr.stops, tr.parsed, time.Now()); err != nil {
		t.Fatal(err)
	}
	return tr
}

// signRouteFile signs doc under key into path and returns the route read.
func signRouteFile(t *testing.T, path, doc string, key ed25519.PrivateKey) reaction.Route {
	t.Helper()
	r, err := reaction.ParseRoute([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	env, err := reaction.SignRoute(r, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := reaction.MarshalRouteFile(env)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, path, string(body))
	return r
}

func (tr stopTree) routeArgs() []string {
	return []string{"--route", tr.route, "--public-key", tr.routePub}
}

func (tr stopTree) reactArgs(findings string) reactArgs {
	return reactArgs{routeFlags: routeFlags{route: tr.route, publicKey: tr.routePub},
		findings: findings, runs: tr.runs, stops: tr.stops, lockWait: stopsLockWait}
}

// clockAt is a clock that always reads now.
func clockAt(now time.Time) func() time.Time { return func() time.Time { return now } }

// react runs react over the log in findings at now.
func (tr stopTree) react(t *testing.T, findings string, now time.Time) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := react(context.Background(), tr.reactArgs(findings), clockAt(now), &out, &errOut)
	return code, out.String(), errOut.String()
}

// listBytes is the stop list as it stands.
func (tr stopTree) listBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(tr.stops, stoplist.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// judged is the list as a plane judges it at now.
func (tr stopTree) judged(t *testing.T, now time.Time) reaction.List {
	t.Helper()
	l, err := reaction.Judge(tr.parsed, reaction.Prefix{}, tr.listBytes(t), now, time.Second)
	if err != nil {
		t.Fatalf("the plane's judge refuses the list: %v", err)
	}
	return l
}

// fid is the finding id numbered n.
func fid(n int) string { return fmt.Sprintf("fnd-%032x", n) }

// finding is a deterministic finding of the refund procedure, numbered n,
// about run, of rule at the version supervise gives it, with verdict.
func finding(n int, run, rule string, verdict controlv1.FindingVerdict) *findingv1alpha1.FindingRecord {
	version := "1"
	if rule == denial {
		version = "2"
	}
	return &findingv1alpha1.FindingRecord{
		SchemaVersion: "0.1", TenantId: "acme", ProjectId: "orders",
		Procedure:  &findingv1alpha1.ProcedureRef{ProcedureId: "refund", Version: "1", Digest: stopProcDigest},
		Escalation: findingv1alpha1.Escalation_ESCALATION_ALERT,
		Finding: &controlv1.Finding{FindingId: fid(n), RuleId: rule, RuleVersion: version,
			Severity: controlv1.FindingSeverity_FINDING_SEVERITY_HIGH, Verdict: verdict, RunId: run,
			Source: controlv1.FindingSource_FINDING_SOURCE_DETERMINISTIC},
	}
}

const (
	confirmed = controlv1.FindingVerdict_FINDING_VERDICT_CONFIRMED
	denial    = "REPEATED_DENIAL"
	outside   = "STEP_OUTSIDE_PROCEDURE"
)

// appendLog appends findings to the log in dir, closed by one report.
func appendLog(t *testing.T, dir string, findings ...*findingv1alpha1.FindingRecord) {
	t.Helper()
	log, err := findinglog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	report := &findingv1alpha1.SuperviseReport{SchemaVersion: "0.1", TenantId: "acme", ProjectId: "orders",
		RunId: "run-" + strings.Repeat("0", 32), Procedure: &findingv1alpha1.ProcedureRef{
			ProcedureId: "refund", Version: "1", Digest: stopProcDigest},
		Read: &findingv1alpha1.ReadCounts{EventsTaken: 1}}
	if _, err := log.Write(findings, report); err != nil {
		t.Fatal(err)
	}
}

// findingsDir is a new owner-only findings directory holding findings.
func (tr stopTree) findingsDir(t *testing.T, name string, findings ...*findingv1alpha1.FindingRecord) string {
	t.Helper()
	dir := ownerDir(t, filepath.Join(tr.dir, name))
	if len(findings) > 0 {
		appendLog(t, dir, findings...)
	}
	return dir
}
