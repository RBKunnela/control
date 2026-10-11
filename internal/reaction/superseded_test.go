package reaction_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

// superseded is every rule version a later one replaced, spelled here rather
// than read from the package under test.
var superseded = []reaction.StoppingRule{{ID: "REPEATED_DENIAL", Version: "1"}}

// denialRoute is a route for the refund procedure naming REPEATED_DENIAL at
// version, stopping for at most ten minutes, beside STEP_OUTSIDE_PROCEDURE.
func denialRoute(t testing.TB, version string) reaction.Route {
	t.Helper()
	d := refundDigest(t)
	r, err := reaction.ParseRoute([]byte(withLift(`{"kind":"reaction-route/v1alpha1","route_id":"refunds","serial":3,` +
		`"tenant_id":"acme","scope":"run","lift_public_key":"LIFTKEY","rules":[` +
		`{"procedure_id":"refund","version":"1","digest":"` + d + `","rule_id":"REPEATED_DENIAL","rule_version":"` + version + `","expires_seconds":600},` +
		`{"procedure_id":"refund","version":"1","digest":"` + d + `","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1"}]}`)))
	if err != nil {
		t.Fatalf("ParseRoute: %v", err)
	}
	return r
}

// denialStop is a stop of run-1 for finding under REPEATED_DENIAL at
// version, created at clock0 and lasting life.
func denialStop(t testing.TB, finding, version string, life time.Duration) reaction.Stop {
	s := stopOf(t, finding, "run-1", clock0, life)
	s.RuleID, s.RuleVersion = "REPEATED_DENIAL", version
	return s
}

func TestSupersededRulesAreTheVersionsStoppingRulesReplaced(t *testing.T) {
	if got := reaction.SupersededRules(); !slices.Equal(got, superseded) {
		t.Fatalf("SupersededRules() = %q, want %q", got, superseded)
	}
	for _, r := range superseded {
		if reaction.MayStop(r.ID, r.Version) || !reaction.Superseded(r.ID, r.Version) {
			t.Errorf("%s %s: MayStop %v, Superseded %v", r.ID, r.Version, reaction.MayStop(r.ID, r.Version), reaction.Superseded(r.ID, r.Version))
		}
	}
	for _, r := range append(slices.Clone(mayStop), mayNotStop...) {
		if !slices.Contains(superseded, r) && reaction.Superseded(r.ID, r.Version) {
			t.Errorf("Superseded(%q, %q) = true", r.ID, r.Version)
		}
	}
	got := reaction.SupersededRules()
	got[0].Version = "9"
	if !reaction.Superseded("REPEATED_DENIAL", "1") || reaction.Superseded("REPEATED_DENIAL", "9") {
		t.Fatal("a write into SupersededRules' result reached the table")
	}
}

// TestOnlyACarrySourceMayNameASupersededVersion: a route naming
// REPEATED_DENIAL at version "1" verifies and judges its own list only as
// the route a list is carried from; VerifyRoute, Judge and JudgeFrom refuse
// it.
func TestOnlyACarrySourceMayNameASupersededVersion(t *testing.T) {
	old := denialRoute(t, "1")
	env, err := reaction.SignRoute(old, routeKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reaction.VerifyRoute(env, pubOf(routeKey())); !errors.Is(err, reaction.ErrRouteRuleStops) {
		t.Errorf("VerifyRoute of the old route: %v, want %v", err, reaction.ErrRouteRuleStops)
	}
	if v, err := reaction.VerifyCarrySource(env, pubOf(routeKey())); err != nil || v.Digest() != old.Digest() {
		t.Fatalf("VerifyCarrySource of the old route: %v", err)
	}
	other, err := reaction.SignRoute(old, seededKey(0x4f))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reaction.VerifyCarrySource(other, pubOf(routeKey())); !errors.Is(err, reaction.ErrRouteKey) {
		t.Errorf("VerifyCarrySource under another key: %v, want %v", err, reaction.ErrRouteKey)
	}

	b := newList(t, old)
	b.add(denialStop(t, "f-1", "1", 10*time.Minute).Marshal())
	content := b.bytes()
	if _, err := reaction.Judge(old, reaction.Prefix{}, content, clock0, poll); !errors.Is(err, reaction.ErrRouteRuleStops) {
		t.Errorf("Judge under the old route: %v, want %v", err, reaction.ErrRouteRuleStops)
	}
	if _, err := reaction.JudgeFrom(old, reaction.List{}, content, clock0, poll); !errors.Is(err, reaction.ErrRouteRuleStops) {
		t.Errorf("JudgeFrom under the old route: %v, want %v", err, reaction.ErrRouteRuleStops)
	}
	l, err := reaction.JudgeCarrySource(old, content, clock0)
	if err != nil || entryRuns(l.Entries()) != "run-1@2" {
		t.Fatalf("JudgeCarrySource under the old route: %q, %v", entryRuns(l.Entries()), err)
	}

}

// TestACarrySourceNamingAnyOtherRuleIsRefused: a route naming the six that
// may stop and the superseded version is a carry source; one naming any
// other rule beside one that may stop is refused by CheckCarrySource,
// VerifyCarrySource and JudgeCarrySource.
func TestACarrySourceNamingAnyOtherRuleIsRefused(t *testing.T) {
	if err := reaction.CheckCarrySource(routeNaming(t, append(slices.Clone(mayStop), superseded...)...)); err != nil {
		t.Errorf("CheckCarrySource of the six and the superseded: %v", err)
	}
	for _, r := range insertable() {
		err := reaction.CheckCarrySource(routeNaming(t, mayStop[0], r))
		if slices.Contains(superseded, r) {
			if err != nil {
				t.Errorf("CheckCarrySource naming %s %s: %v", r.ID, r.Version, err)
			}
			continue
		}
		expectOnly(t, "CheckCarrySource naming "+r.ID+" "+r.Version, err, reaction.ErrRouteRuleStops,
			append(routeRefusals(), reaction.ErrRouteRuleStops))
		signed, err := reaction.SignRoute(routeNaming(t, mayStop[0], r), routeKey())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reaction.VerifyCarrySource(signed, pubOf(routeKey())); !errors.Is(err, reaction.ErrRouteRuleStops) {
			t.Errorf("VerifyCarrySource naming %s %s: %v", r.ID, r.Version, err)
		}
		route := routeNaming(t, mayStop[0], r)
		if _, err := reaction.JudgeCarrySource(route, newList(t, route).bytes(), clock0); !errors.Is(err, reaction.ErrRouteRuleStops) {
			t.Errorf("JudgeCarrySource under %s %s: %v", r.ID, r.Version, err)
		}
	}
}

// TestAListUnderTheCurrentVersionHoldsAStopOfTheSupersededOne: under a route
// naming REPEATED_DENIAL at version "2", a stop line naming version "1" of
// the same procedure is judged as one of version "2", its lifetime held to
// that rule's, and stops its run; Permits, which react asks, still refuses
// it. A stop naming version "1" of a rule the route names at no version, of
// another procedure, at a version never superseded, or lasting past the
// rule's lifetime is refused.
func TestAListUnderTheCurrentVersionHoldsAStopOfTheSupersededOne(t *testing.T) {
	current := denialRoute(t, "2")
	b := newList(t, current)
	b.add(denialStop(t, "f-1", "1", 10*time.Minute).Marshal())
	l, err := reaction.Judge(current, reaction.Prefix{}, b.bytes(), clock0, poll)
	if err != nil || entryRuns(l.Entries()) != "run-1@2" {
		t.Fatalf("a stop of version 1 under the route of version 2: %q, %v", entryRuns(l.Entries()), err)
	}
	s := reaction.Snapshot{}.Next(current, b.bytes(), clock0, poll)
	if got, _ := s.ForCall("run-1", "acme", clock0.Add(time.Minute), time.Time{}); got != reaction.Stopped {
		t.Errorf("the carried stop's run: %s, want %s", got, reaction.Stopped)
	}
	if err := current.Permits(denialStop(t, "f-1", "1", 10*time.Minute).Claim()); !errors.Is(err, reaction.ErrClaimRule) {
		t.Errorf("Permits of a stop of version 1: %v, want %v", err, reaction.ErrClaimRule)
	}

	otherProcedure := denialStop(t, "f-2", "1", 10*time.Minute)
	otherProcedure.ProcedureVersion = "2"
	for name, c := range map[string]struct {
		route reaction.Route
		stop  reaction.Stop
	}{
		"a rule the route names at no version": {listRoute(t), denialStop(t, "f-2", "1", time.Minute)},
		"another procedure":                    {current, otherProcedure},
		"a version never superseded":           {current, denialStop(t, "f-2", "9", time.Minute)},
		"a lifetime past the rule's":           {current, denialStop(t, "f-2", "1", 10*time.Minute+time.Second)},
	} {
		b := newList(t, c.route)
		b.add(c.stop.Marshal())
		_, err := reaction.Judge(c.route, reaction.Prefix{}, b.bytes(), clock0, poll)
		expectOnly(t, name, err, reaction.ErrStopRefused, judgeRefusals())
	}
}
