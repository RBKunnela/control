package gateway

import (
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/policy/match"
)

// TestTheListingOfEachDecision: only the kernel's own DENY for no matching
// rule alone, beside an ALLOW rule every input of which it lacked a call
// brings, leaves the tool to be decided per call. A decision the plane minted
// is not the kernel's, and a pause, a stop or a halt is denied to the listing
// whatever the kernel said.
func TestTheListingOfEachDecision(t *testing.T) {
	of := func(verdict controlv1.Verdict, codes ...string) *controlv1.Decision {
		return &controlv1.Decision{Verdict: verdict, ReasonCodes: codes}
	}
	deny := controlv1.Verdict_VERDICT_DENY
	noMatch := of(deny, "NO_MATCHING_RULE")
	allowed := of(controlv1.Verdict_VERDICT_ALLOW, "RULE_ALLOW")
	obliged := of(controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS, "OBLIGATIONS_ATTACHED")
	approval := of(controlv1.Verdict_VERDICT_REQUIRE_APPROVAL, "APPROVAL_REQUIRED")
	undetermined := of(controlv1.Verdict_VERDICT_INDETERMINATE, "RULE_UNDETERMINED")
	byID := []match.UnknownAllow{{ID: "allow-order", Needs: []string{"resource.id"}}}
	pointed := Admission{Classification: classify.Classification{ResourceFrom: "/order"}}
	for _, c := range []struct {
		name             string
		decision, kernel *controlv1.Decision
		noRuleMatched    bool
		unknownAllows    []match.UnknownAllow
		want             Listing
	}{
		{"the kernel's no match beside an ALLOW a call can meet", noMatch, noMatch, true, byID, ListingPerCall},
		{"the kernel's no match with no unknown allow", noMatch, noMatch, true, nil, ListingDenied},
		{"a DENY the kernel does not mark as no match", noMatch, noMatch, false, byID, ListingDenied},
		{"a plane decision over the kernel's no match", of(deny, "NO_MATCHING_RULE"), noMatch, true, byID, ListingDenied},
		{"a pause over the kernel's no match", of(deny, codePaused), noMatch, true, byID, ListingDenied},
		{"a stop over the kernel's no match", of(deny, codeRunStopped), noMatch, true, byID, ListingDenied},
		{"LOCKDOWN over the kernel's no match", of(deny, codeLockdown), noMatch, true, byID, ListingDenied},
		{"a halt over the kernel's no match", of(deny, codeExecutedArgsMismatch), noMatch, true, byID, ListingDenied},
		{"an ALLOW that lacked nothing it names", noMatch, noMatch, true, []match.UnknownAllow{{ID: "odd"}}, ListingDenied},
		{"ALLOW", allowed, allowed, false, byID, ListingDecided},
		{"ALLOW_WITH_OBLIGATIONS", obliged, obliged, false, nil, ListingDecided},
		{"REQUIRE_APPROVAL", approval, approval, false, nil, ListingDecided},
		{"INDETERMINATE", undetermined, undetermined, false, nil, ListingPerCall},
		{"no decision", nil, nil, false, nil, ListingPerCall},
	} {
		if got := listingOf(c.decision, c.kernel, c.noRuleMatched, c.unknownAllows, pointed); got != c.want {
			t.Errorf("%s: listing %d, want %d", c.name, got, c.want)
		}
	}
}

// TestWhatACallSupplies: a call brings the resource id only where its
// classification points at one, and the run's flow always; every other input
// it carries as the preview did. A rule that lacked several is met only when
// the call brings each.
func TestWhatACallSupplies(t *testing.T) {
	noMatch := &controlv1.Decision{Verdict: controlv1.Verdict_VERDICT_DENY, ReasonCodes: []string{"NO_MATCHING_RULE"}}
	pointed := Admission{Classification: classify.Classification{ResourceFrom: "/order"}}
	for _, c := range []struct {
		name  string
		a     Admission
		rules []match.UnknownAllow
		want  Listing
	}{
		{"the resource id behind a pointer", pointed, []match.UnknownAllow{{ID: "r", Needs: []string{"resource.id"}}}, ListingPerCall},
		{"the resource id with no pointer", Admission{}, []match.UnknownAllow{{ID: "r", Needs: []string{"resource.id"}}}, ListingDenied},
		{"a run nobody tracked", Admission{}, []match.UnknownAllow{{ID: "r", Needs: []string{"flow"}}}, ListingPerCall},
		{"the run's reading", Admission{}, []match.UnknownAllow{{ID: "r", Needs: []string{"flow.max_sensitivity_read"}}}, ListingPerCall},
		{"data labels", pointed, []match.UnknownAllow{{ID: "r", Needs: []string{"data.sensitivities"}}}, ListingDenied},
		{"the authentication strength", pointed, []match.UnknownAllow{{ID: "r", Needs: []string{"principal.authn_strength"}}}, ListingDenied},
		{"a delegation", pointed, []match.UnknownAllow{{ID: "r", Needs: []string{"delegation"}}}, ListingDenied},
		{"the resource id and the authentication strength", pointed,
			[]match.UnknownAllow{{ID: "r", Needs: []string{"resource.id", "principal.authn_strength"}}}, ListingDenied},
		{"beside it, a rule on the resource id alone", pointed, []match.UnknownAllow{
			{ID: "r", Needs: []string{"resource.id", "principal.authn_strength"}},
			{ID: "s", Needs: []string{"resource.id"}},
		}, ListingPerCall},
	} {
		if got := listingOf(noMatch, noMatch, true, c.rules, c.a); got != c.want {
			t.Errorf("%s: listing %d, want %d", c.name, got, c.want)
		}
	}
}
