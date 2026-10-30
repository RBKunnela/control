package gateway

import (
	"slices"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/match"
)

// Listing is what a preview lets a listing do with a tool. Hiding is the one
// thing a listing subtracts, so the zero value is the one that keeps the
// tool: a listing never hides what nothing decided.
type Listing uint8

const (
	// ListingPerCall is a preview that could not decide without what the
	// call will carry, so the tool stays listed and its call is decided when
	// it is made.
	ListingPerCall Listing = iota
	// ListingDenied is a preview that denies a call to the tool whatever it
	// carries, so a listing may leave the tool out.
	ListingDenied
	// ListingDecided is a preview whose verdict lets a call proceed or wait
	// for approval.
	ListingDecided
)

// Previewed is a preview's decision and what a listing may do with the tool.
type Previewed struct {
	Decision *controlv1.Decision
	Listing  Listing
}

// listingOf is what a listing may do with a tool previewed as decision under
// a, where decision is kernel itself when the plane added no cause of its
// own and noRuleMatched is the kernel's word that nothing but no matching
// rule denied it. Only such a DENY, beside an ALLOW rule every input of which
// it lacked a call to the tool brings, is short of a denial: that call may be
// allowed. A plane cause denies whatever the kernel said.
func listingOf(decision, kernel *controlv1.Decision, noRuleMatched bool, unknownAllows []match.UnknownAllow, a Admission) Listing {
	switch decision.GetVerdict() {
	case verdictDeny:
		if decision == kernel && noRuleMatched && slices.ContainsFunc(unknownAllows, func(u match.UnknownAllow) bool {
			return len(u.Needs) > 0 && !slices.ContainsFunc(u.Needs, func(need string) bool { return !callSupplies(a, need) })
		}) {
			return ListingPerCall
		}
		return ListingDenied
	case controlv1.Verdict_VERDICT_ALLOW, controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS, controlv1.Verdict_VERDICT_REQUIRE_APPROVAL:
		return ListingDecided
	}
	return ListingPerCall
}

// callSupplies reports whether need, an input an ALLOW rule lacked at
// preview, is one a call to the tool previewed as a can bring. A preview
// carries the call's identity and classification but no arguments and no
// run, so a call adds only the resource id its classification's pointer
// reads and the run's flow. Every other input reads at the call as it read
// at preview, and a rule that lacked it is never met.
func callSupplies(a Admission, need string) bool {
	switch need {
	case "resource.id":
		return a.Classification.ResourceFrom != ""
	case "flow", "flow.max_sensitivity_read":
		return true
	}
	return false
}
