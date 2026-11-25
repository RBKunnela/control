package reaction

import (
	"encoding/json"
	"fmt"

	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/pkg/contract"
)

// SignedRouteKindV3 is the kind of a route an operator signs under the
// signed authority: SignedRouteKind's members and the id of the one plane
// it is signed for, with a scope per rule.
const SignedRouteKindV3 = "reaction-route/v1alpha3"

// The scopes a v1alpha3 rule, a 3.0 line and a v1alpha3 lift may name
// besides ScopeRun.
const (
	ScopeAgent     = "agent"
	ScopePrincipal = "principal"
)

const (
	memberPlaneID = "plane_id"
	memberSubject = "subject"
)

// maxUpgradeBodyBytes bounds a body of a format only a carry reads: the
// bound it was signed under.
const maxUpgradeBodyBytes = 16384

// RouteFormat is which format a route was read in, and so which list
// version, header and lift it is judged with. The zero value is no format,
// which nothing reads as any of the others.
type RouteFormat uint8

// The route formats.
const (
	FormatNone RouteFormat = iota
	// FormatV1Alpha1 is a route signed with a route key, whose lists are 1.0.
	FormatV1Alpha1
	// FormatV1Alpha2Carry is a route an operator signed that names no plane,
	// whose lists are 2.0: read only as the route a list is carried from.
	FormatV1Alpha2Carry
	// FormatV1Alpha3 is a route an operator signed for one plane, whose lists
	// are 3.0.
	FormatV1Alpha3
)

// The refusals of a format a signed plane no longer serves, each naming the
// command that upgrades it.
const (
	ErrRouteUpgrade Error = "reaction: a " + SignedRouteKind + " route is not served; sign a " + SignedRouteKindV3 +
		" route naming plane_id with route sign"
	ErrListUpgrade Error = "reaction: a " + SignedListVersion + " stop list is not served; carry it into " + SignedListVersionV3 +
		" with stops init --carry"
	ErrLiftUpgrade Error = "reaction: a " + SignedLiftKind + " lift is not served; carry its list with stops init --carry"
)

// listVersion is the version of every line of a list judged against a
// route of format f.
func listVersion(f RouteFormat) (string, error) {
	switch f {
	case FormatV1Alpha1:
		return ListVersion, nil
	case FormatV1Alpha2Carry:
		return SignedListVersion, nil
	case FormatV1Alpha3:
		return SignedListVersionV3, nil
	}
	return "", fmt.Errorf("%w: no route was read", ErrListRoute)
}

// readScope reads raw as a scope the grammar names: run, agent or principal.
// A missing or empty scope is none of them.
func readScope(raw json.RawMessage) (string, bool) {
	s, ok := strictjson.String(raw)
	return s, ok && (s == ScopeRun || s == ScopeAgent || s == ScopePrincipal)
}

// MaxSubjectBytes bounds the agent or principal a stop or lift names, as a
// run record bounds each field of its identity.
const MaxSubjectBytes = 256

// wider reports whether scope names an agent or a principal, whose stop
// holds every run of it rather than one.
func wider(scope string) bool { return scope == ScopeAgent || scope == ScopePrincipal }

// subjectBound is the longest subject a line or lift of scope may name.
func subjectBound(scope string) int {
	if wider(scope) {
		return MaxSubjectBytes
	}
	return MaxRunIDBytes
}

// checkRuleScope refuses a rule of an agent or a principal unless
// MayStopWider names its rule, or it is a retired version a route could let
// stop one, and it names a lifetime: such a stop outlives the run whose
// finding made it, so nothing else would end it. CheckStopping refuses a
// retired version whatever its scope.
func checkRuleScope(r Rule) error {
	retiredWider, _ := retired(r.RuleID, r.RuleVersion)
	switch {
	case !wider(r.Scope):
		return nil
	case !MayStopWider(r.RuleID, r.RuleVersion) && !retiredWider:
		return fmt.Errorf("%w: rule_id %q rule_version %q may not stop an %s", ErrRouteScope, r.RuleID, r.RuleVersion, r.Scope)
	case r.Lifetime == 0:
		return fmt.Errorf("%w: a rule of scope %s names no %s", ErrRouteLifetime, r.Scope, memberExpires)
	}
	return nil
}

// planeIdentifier reads raw as a plane id, by the rule the configuration
// reads plane_id by.
func planeIdentifier(raw json.RawMessage) (string, bool) {
	s, ok := strictjson.String(raw)
	return s, ok && contract.CheckID(s) == nil
}
