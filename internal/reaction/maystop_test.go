package reaction_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/reaction"
)

// mayStop is every rule, at its version, a confirmed finding of which may
// stop a run, spelled here rather than read from the package under test.
var mayStop = []reaction.StoppingRule{
	{ID: "REPEATED_DENIAL", Version: "2"}, {ID: "STEP_OUTSIDE_PROCEDURE", Version: "1"},
	{ID: "DEADLINE_EXCEEDED", Version: "1"}, {ID: "RESOURCE_OUTSIDE_RUN", Version: "1"},
	{ID: "DENIED_ACTION_RETRIED_ARGUMENTS", Version: "1"}, {ID: "DENIED_ACTION_RETRIED_RESOURCE", Version: "1"},
}

// mayNotStop is every other rule supervise has, and ids no rule has, a
// spelling of a stopping rule apart from its own among them, each at version
// "1"; and each stopping rule at a version that is not its own, a version it
// had before among them.
var mayNotStop = []reaction.StoppingRule{
	{ID: "REQUIRED_STEP_SKIPPED", Version: "1"}, {ID: "STEP_OUT_OF_ORDER", Version: "1"},
	{ID: "CONTINUED_AFTER_FAILURE", Version: "1"}, {ID: "DENIED_ACTION_RETRIED_AROUND", Version: "1"},
	{ID: "EXCEPTION_TAKEN", Version: "1"}, {ID: "", Version: "1"}, {ID: "REPEATED_DENIALS", Version: "1"},
	{ID: "repeated_denial", Version: "1"}, {ID: "REPEATED_DENIAL ", Version: "1"}, {ID: "DENIED_ACTION_RETRIED", Version: "1"},
	{ID: "REPEATED_DENIAL", Version: "9"}, {ID: "REPEATED_DENIAL", Version: "1"}, {ID: "REPEATED_DENIAL", Version: "02"},
	{ID: "REPEATED_DENIAL", Version: "2 "}, {ID: "REPEATED_DENIAL", Version: ""},
	{ID: "STEP_OUTSIDE_PROCEDURE", Version: "9"}, {ID: "DEADLINE_EXCEEDED", Version: "9"},
	{ID: "RESOURCE_OUTSIDE_RUN", Version: "9"}, {ID: "DENIED_ACTION_RETRIED_ARGUMENTS", Version: "9"},
	{ID: "DENIED_ACTION_RETRIED_RESOURCE", Version: "9"},
}

// namesOnlyStoppingRules reports whether every rule of r is in mayStop.
func namesOnlyStoppingRules(r reaction.Route) bool {
	for _, rule := range r.Rules() {
		if !slices.Contains(mayStop, reaction.StoppingRule{ID: rule.RuleID, Version: rule.RuleVersion}) {
			return false
		}
	}
	return true
}

func TestMayStopIsTheSixRulesThatMayStopAtTheirVersions(t *testing.T) {
	for _, r := range mayStop {
		if !reaction.MayStop(r.ID, r.Version) {
			t.Errorf("MayStop(%q, %q) = false", r.ID, r.Version)
		}
	}
	for _, r := range mayNotStop {
		if reaction.MayStop(r.ID, r.Version) {
			t.Errorf("MayStop(%q, %q) = true", r.ID, r.Version)
		}
	}
	got := reaction.StoppingRules()
	byID := func(a, b reaction.StoppingRule) int {
		return strings.Compare(a.ID+"\x00"+a.Version, b.ID+"\x00"+b.Version)
	}
	if !slices.Equal(slices.SortedFunc(slices.Values(got), byID), slices.SortedFunc(slices.Values(mayStop), byID)) {
		t.Fatalf("StoppingRules() = %q, want %q", got, mayStop)
	}
	got[0] = reaction.StoppingRule{ID: "EXCEPTION_TAKEN", Version: "1"}
	got[1].Version = "9"
	if reaction.MayStop("EXCEPTION_TAKEN", "1") || !reaction.MayStop(mayStop[0].ID, mayStop[0].Version) ||
		reaction.MayStop(mayStop[1].ID, "9") {
		t.Fatal("a write into StoppingRules' result reached the table")
	}
}

// routeNaming is a route whose rules name each of rules in order, all of one
// procedure.
func routeNaming(t *testing.T, rules ...reaction.StoppingRule) reaction.Route {
	t.Helper()
	docs := make([]string, len(rules))
	for i, r := range rules {
		docs[i] = fmt.Sprintf(`{"procedure_id":"refund","version":"3","digest":"%s","rule_id":%q,"rule_version":%q}`, procDigest, r.ID, r.Version)
	}
	doc := withLift(`{"kind":"reaction-route/v1alpha1","route_id":"refunds","serial":7,"tenant_id":"acme",` +
		`"scope":"run","lift_public_key":"LIFTKEY","rules":[` + strings.Join(docs, ",") + `]}`)
	r, err := reaction.ParseRoute([]byte(doc))
	if err != nil {
		t.Fatalf("the case's route does not parse: %v", err)
	}
	return r
}

// insertable is each rule of mayNotStop a route document can hold; ParseRoute
// refuses the others before this check.
func insertable() []reaction.StoppingRule {
	return slices.DeleteFunc(slices.Clone(mayNotStop), func(r reaction.StoppingRule) bool {
		return r.ID == "" || r.Version == "" || strings.ContainsAny(r.ID+r.Version, " ")
	})
}

// TestCheckStoppingRefusesTheWholeRouteForOneRule: a route whose rules are
// the six that may stop at their versions passes; the same route with any
// other rule, or one of the six at another version, in any place is refused,
// naming that place and the rule.
func TestCheckStoppingRefusesTheWholeRouteForOneRule(t *testing.T) {
	if err := reaction.CheckStopping(routeNaming(t, mayStop...)); err != nil {
		t.Fatalf("a route of the rules that may stop: %v", err)
	}
	cases := insertable()
	if len(cases) < 15 {
		t.Fatalf("only %d case(s) a route can hold", len(cases))
	}
	for _, r := range cases {
		for _, place := range []int{0, 3, len(mayStop)} {
			err := reaction.CheckStopping(routeNaming(t, slices.Insert(slices.Clone(mayStop), place, r)...))
			name := fmt.Sprintf("%s %s at rules[%d]", r.ID, r.Version, place)
			expectOnly(t, name, err, reaction.ErrRouteRuleStops, append(routeRefusals(), reaction.ErrRouteRuleStops))
			want := fmt.Sprintf("rules[%d]: %s: rule_id %q rule_version %q", place, reaction.ErrRouteRuleStops, r.ID, r.Version)
			if err != nil && err.Error() != want {
				t.Errorf("%s: the refusal is %q, want %q", name, err, want)
			}
		}
	}
	if err := reaction.CheckStopping(reaction.Route{}); err != nil {
		t.Errorf("the zero route, which permits nothing: %v", err)
	}
}

// TestVerifyRouteRefusesARuleThatMayNotStop: a route signed under the route
// key whose signature, body and keys are all good is refused when one rule
// may not stop a run, whatever signed it; the six at their versions are the
// control and verify.
func TestVerifyRouteRefusesARuleThatMayNotStop(t *testing.T) {
	sign := func(r reaction.Route) reaction.Envelope {
		t.Helper()
		env, err := reaction.SignRoute(r, routeKey())
		if err != nil {
			t.Fatalf("SignRoute: %v", err)
		}
		return env
	}
	control := routeNaming(t, mayStop...)
	if v, err := reaction.VerifyRoute(sign(control), pubOf(routeKey())); err != nil || v.Digest() != control.Digest() {
		t.Fatalf("the six at their versions: %v", err)
	}
	for _, r := range insertable() {
		_, err := reaction.VerifyRoute(sign(routeNaming(t, mayStop[0], r)), pubOf(routeKey()))
		expectOnly(t, r.ID+" "+r.Version, err, reaction.ErrRouteRuleStops, append(routeRefusals(), envelopeRefusals()...))
	}
}

// TestJudgeRefusesARouteThatNamesARuleThatMayNotStop: a route parsed, never
// verified, that names one rule outside the table judges no list, from the
// start or from a list accepted before; the same list under the six rules
// that may stop is accepted.
func TestJudgeRefusesARouteThatNamesARuleThatMayNotStop(t *testing.T) {
	control := routeNaming(t, mayStop...)
	if _, err := reaction.Judge(control, reaction.Prefix{}, newList(t, control).bytes(), clock0, poll); err != nil {
		t.Fatalf("the six at their versions: %v", err)
	}
	for _, r := range insertable() {
		route := routeNaming(t, mayStop[0], r)
		content := newList(t, route).bytes()
		_, err := reaction.Judge(route, reaction.Prefix{}, content, clock0, poll)
		expectOnly(t, "Judge under "+r.ID+" "+r.Version, err, reaction.ErrRouteRuleStops,
			append(routeRefusals(), reaction.ErrRouteRuleStops, reaction.ErrListRoute))
		_, err = reaction.JudgeFrom(route, reaction.List{}, content, clock0, poll)
		expectOnly(t, "JudgeFrom under "+r.ID+" "+r.Version, err, reaction.ErrRouteRuleStops,
			append(routeRefusals(), reaction.ErrRouteRuleStops, reaction.ErrListRoute))
	}
}
