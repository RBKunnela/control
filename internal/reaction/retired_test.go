package reaction_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

func TestRetiredRulesAreTheVersionsNoRouteMayName(t *testing.T) {
	if got := reaction.RetiredRules(); !slices.Equal(got, retiredVersions) {
		t.Fatalf("RetiredRules() = %q, want %q", got, retiredVersions)
	}
	for _, r := range retiredVersions {
		if reaction.MayStop(r.ID, r.Version) || reaction.MayStopWider(r.ID, r.Version) || reaction.Superseded(r.ID, r.Version) ||
			!reaction.Retired(r.ID, r.Version) {
			t.Errorf("%s %s: MayStop %v, MayStopWider %v, Superseded %v, Retired %v", r.ID, r.Version, reaction.MayStop(r.ID, r.Version),
				reaction.MayStopWider(r.ID, r.Version), reaction.Superseded(r.ID, r.Version), reaction.Retired(r.ID, r.Version))
		}
	}
	for _, r := range slices.Concat(mayStop, mayNotStop, superseded) {
		if !slices.Contains(retiredVersions, r) && reaction.Retired(r.ID, r.Version) {
			t.Errorf("Retired(%q, %q) = true", r.ID, r.Version)
		}
	}
	got := reaction.RetiredRules()
	got[0].Version = "9"
	if !reaction.Retired("DEADLINE_EXCEEDED", "1") || reaction.Retired("DEADLINE_EXCEEDED", "9") {
		t.Fatal("a write into RetiredRules' result reached the table")
	}
}

// retiredStop is a stop of run-1 for finding under rule id at version, of
// the procedure listRoute names, created at clock0 and lasting life.
func retiredStop(t testing.TB, finding, id, version string, life time.Duration) reaction.Stop {
	s := stopOf(t, finding, "run-1", clock0, life)
	s.RuleID, s.RuleVersion = id, version
	return s
}

// TestAListUnderARouteThatNoLongerNamesARetiredRuleKeepsItsStop: a carry
// brings a stop of a retired version into a list whose route no longer names
// the rule, so the judge keeps it, bounded by MaxLifetime, and it still stops
// its run; Permits, which react asks, refuses it. A stop of a procedure the
// route does not name, of a version never retired, or lasting past
// MaxLifetime is refused.
func TestAListUnderARouteThatNoLongerNamesARetiredRuleKeepsItsStop(t *testing.T) {
	r := listRoute(t)
	for _, rule := range retiredVersions {
		b := newList(t, r)
		b.add(retiredStop(t, "f-1", rule.ID, rule.Version, reaction.MaxLifetime).Marshal())
		l, err := reaction.Judge(r, reaction.Prefix{}, b.bytes(), clock0, poll)
		if err != nil || entryRuns(l.Entries()) != "run-1@2" {
			t.Fatalf("a stop of %s %s: %q, %v", rule.ID, rule.Version, entryRuns(l.Entries()), err)
		}
		s := reaction.Snapshot{}.Next(r, b.bytes(), clock0, poll)
		if got, _, _ := s.ForSubject(reaction.Subject{Tenant: "acme", Run: "run-1"}, clock0.Add(time.Minute), time.Time{}); got != reaction.Stopped {
			t.Errorf("%s %s: the kept stop's run is %s, want %s", rule.ID, rule.Version, got, reaction.Stopped)
		}
		if err := r.Permits(retiredStop(t, "f-1", rule.ID, rule.Version, time.Minute).Claim()); !errors.Is(err, reaction.ErrClaimRule) {
			t.Errorf("Permits of a stop of %s %s: %v, want %v", rule.ID, rule.Version, err, reaction.ErrClaimRule)
		}
	}
	otherProcedure := retiredStop(t, "f-2", "DEADLINE_EXCEEDED", "1", time.Minute)
	otherProcedure.ProcedureVersion = "2"
	for name, stop := range map[string]reaction.Stop{
		"another procedure":       otherProcedure,
		"a version never retired": retiredStop(t, "f-2", "DEADLINE_EXCEEDED", "2", time.Minute),
		"past MaxLifetime":        retiredStop(t, "f-2", "DEADLINE_EXCEEDED", "1", reaction.MaxLifetime+time.Second),
	} {
		b := newList(t, r)
		b.add(stop.Marshal())
		_, err := reaction.Judge(r, reaction.Prefix{}, b.bytes(), clock0, poll)
		expectOnly(t, name, err, reaction.ErrStopRefused, judgeRefusals())
	}
}

// runOnlyRouteDoc is a v1alpha3 route whose one rule stops a run of refund
// version "3" for an hour, and lets nothing stop an agent or a principal.
const runOnlyRouteDoc = `{"kind":"reaction-route/v1alpha3","plane_id":"plane-a","route_id":"refunds","serial":7,"tenant_id":"acme",
 "project_id":"shop","rules":[
 {"procedure_id":"refund","version":"3","digest":"` + procDigest + `","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run","expires_seconds":3600}]}`

// signedRouteOf is doc signed for plane-a and taken by the fake voucher.
func signedRouteOf(t *testing.T, doc string) reaction.Route {
	t.Helper()
	body, err := reaction.SignedRouteBody([]byte(doc), keyIDOf(operatorKey()), sRouteFile)
	if err != nil {
		t.Fatalf("SignedRouteBody: %v", err)
	}
	r, err := reaction.VerifySignedRoute(envelopeOf(t, reaction.SignedRoutePayloadType, body, operatorKey(), keyIDOf(operatorKey())), newVoucher())
	if err != nil {
		t.Fatalf("VerifySignedRoute: %v", err)
	}
	return r
}

// wideRetiredStop is a 3.0 stop of scope and subject alice, for refund at
// procedure version, under rule id at version, lasting life from sCreated.
func wideRetiredStop(t *testing.T, scope, procedure, id, version string, life time.Duration) []byte {
	t.Helper()
	return wideRetiredStopOf(t, scope, procedure, procDigest, id, version, life)
}

// wideRetiredStopOf is wideRetiredStop of the procedure's version at digest.
func wideRetiredStopOf(t *testing.T, scope, procedure, digest, id, version string, life time.Duration) []byte {
	t.Helper()
	subject := "alice"
	if scope == reaction.ScopeRun {
		subject = "run-1"
	}
	line, err := reaction.Stop{
		EntryID: reaction.EntryID("f-1"), TenantID: sTenant, ProjectID: sProject, Scope: scope,
		Subject: subject, RunID: "run-1", FindingID: "f-1", ProcedureID: "refund", ProcedureVersion: procedure,
		ProcedureDigest: digest, RuleID: id, RuleVersion: version, CreatedAt: sCreated, ExpiresAt: sCreated.Add(life),
	}.Marshal()
	if err != nil {
		t.Fatalf("Stop.Marshal: %v", err)
	}
	return line
}

// TestAKeptStopOfARetiredRuleIsHeldToWhatTheRouteGrantsNow: a stop of a
// retired version stands only where a rule of the route names its procedure
// at its scope, and for no longer than that rule's lifetime. Under the wider
// route, refund "3" stops a run for an hour and an agent for two, and refund
// "4" a principal for two: a retry rule's agent stop of "3" lasting two hours
// stands, one a second longer does not, nor one of "3" at another digest,
// nor a principal stop of "3", nor the deadline's agent stop, which no route
// could ever let stop an agent; a run stop of "3" stands for an hour and not
// a second more. Under a route that stops runs alone, a principal or agent
// stop of the retry rule is refused, as one of REPEATED_DENIAL "2" is.
func TestAKeptStopOfARetiredRuleIsHeldToWhatTheRouteGrantsNow(t *testing.T) {
	const args = "DENIED_ACTION_RETRIED_ARGUMENTS"
	for _, c := range []struct {
		name  string
		doc   string
		stop  func(t *testing.T) []byte
		wants error
	}{
		{"an agent stop within the agent rule's lifetime", widerRouteDoc,
			func(t *testing.T) []byte { return wideRetiredStop(t, reaction.ScopeAgent, "3", args, "1", 2*time.Hour) }, nil},
		{"a principal stop under the procedure that stops a principal", widerRouteDoc,
			func(t *testing.T) []byte {
				return wideRetiredStop(t, reaction.ScopePrincipal, "4", args, "1", 2*time.Hour)
			}, nil},
		{"an agent stop past the agent rule's lifetime", widerRouteDoc,
			func(t *testing.T) []byte {
				return wideRetiredStop(t, reaction.ScopeAgent, "3", args, "1", 2*time.Hour+time.Second)
			}, reaction.ErrClaimLifetime},
		{"a principal stop of a procedure that stops none", widerRouteDoc,
			func(t *testing.T) []byte {
				return wideRetiredStop(t, reaction.ScopePrincipal, "3", args, "1", time.Hour)
			}, reaction.ErrClaimScope},
		{"an agent stop of the procedure's version at another digest", widerRouteDoc,
			func(t *testing.T) []byte {
				return wideRetiredStopOf(t, reaction.ScopeAgent, "3", strings.Repeat("fedcba9876543210", 4), args, "1", time.Hour)
			}, reaction.ErrClaimRule},
		{"the deadline's agent stop", widerRouteDoc,
			func(t *testing.T) []byte {
				return wideRetiredStop(t, reaction.ScopeAgent, "3", "DEADLINE_EXCEEDED", "1", time.Hour)
			}, reaction.ErrClaimScope},
		{"a run stop within the run rule's lifetime", widerRouteDoc,
			func(t *testing.T) []byte { return wideRetiredStop(t, reaction.ScopeRun, "3", args, "1", time.Hour) }, nil},
		{"a run stop past the run rule's lifetime", widerRouteDoc,
			func(t *testing.T) []byte {
				return wideRetiredStop(t, reaction.ScopeRun, "3", args, "1", time.Hour+time.Second)
			}, reaction.ErrClaimLifetime},
		{"a principal stop under a route that stops runs alone", runOnlyRouteDoc,
			func(t *testing.T) []byte {
				return wideRetiredStop(t, reaction.ScopePrincipal, "3", args, "1", reaction.MaxLifetime)
			}, reaction.ErrClaimScope},
		{"an agent stop under a route that stops runs alone", runOnlyRouteDoc,
			func(t *testing.T) []byte { return wideRetiredStop(t, reaction.ScopeAgent, "3", args, "1", time.Minute) }, reaction.ErrClaimScope},
		{"REPEATED_DENIAL's principal stop under a route that stops runs alone", runOnlyRouteDoc,
			func(t *testing.T) []byte {
				return wideRetiredStop(t, reaction.ScopePrincipal, "3", "REPEATED_DENIAL", "2", time.Hour)
			}, reaction.ErrClaimRule},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := signedRouteOf(t, c.doc)
			header, _ := signedHeaderLine(t, r, headerOpts{})
			l, err := reaction.Judge(r, reaction.Prefix{}, joinLines(header, c.stop(t)), sNow, 0)
			if c.wants == nil {
				if err != nil || len(l.Entries()) != 1 {
					t.Fatalf("Judge: %d entries, %v; want the stop kept", len(l.Entries()), err)
				}
				return
			}
			if !errors.Is(err, reaction.ErrStopRefused) || !errors.Is(err, c.wants) {
				t.Fatalf("Judge: %v; want %v and %v", err, reaction.ErrStopRefused, c.wants)
			}
		})
	}
}

// TestNoWriterMayAppendAStopOfARetiredVersion: CheckCurrent, which every
// writer asks, refuses a stop of each retired version and passes the same
// stop at a rule that may stop.
func TestNoWriterMayAppendAStopOfARetiredVersion(t *testing.T) {
	for _, rule := range retiredVersions {
		err := reaction.CheckCurrent(retiredStop(t, "f-1", rule.ID, rule.Version, time.Minute))
		if !errors.Is(err, reaction.ErrStopRetired) {
			t.Errorf("CheckCurrent of a stop of %s %s: %v, want %v", rule.ID, rule.Version, err, reaction.ErrStopRetired)
		}
	}
	if err := reaction.CheckCurrent(retiredStop(t, "f-1", "RESOURCE_OUTSIDE_RUN", "1", time.Minute)); err != nil {
		t.Errorf("CheckCurrent of a stop of a rule that may stop: %v", err)
	}
}
