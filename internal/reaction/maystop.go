package reaction

import (
	"fmt"
	"slices"
)

// StoppingRule is a supervise rule at one version.
type StoppingRule struct{ ID, Version string }

// stoppingRules is every supervise rule, at its version, a confirmed finding
// of which may stop a run, and so every rule a route may name. It copies
// supervise's table, since a plane links no supervision code; a test of the
// route command holds the two equal. A rule's next version changes what it
// fires on, so a route naming it is refused until this table names it too.
var stoppingRules = [...]StoppingRule{
	{"REPEATED_DENIAL", "2"},
	{"STEP_OUTSIDE_PROCEDURE", "1"},
	{"RESOURCE_OUTSIDE_RUN", "1"},
}

// widerRules is every rule in stoppingRules whose finding is the conduct of
// the actor rather than a property of one task, and so the rules alone a
// route may let stop an agent or a principal.
var widerRules = [...]StoppingRule{
	{"REPEATED_DENIAL", "2"},
}

// MayStopWider reports whether a route may let rule id at version stop an
// agent or a principal, both compared byte for byte.
func MayStopWider(id, version string) bool {
	return slices.Contains(widerRules[:], StoppingRule{id, version})
}

// StoppingRules is a copy of every rule a route may name.
func StoppingRules() []StoppingRule { return slices.Clone(stoppingRules[:]) }

// MayStop reports whether a route may name rule id at version, both compared
// byte for byte.
func MayStop(id, version string) bool {
	return slices.Contains(stoppingRules[:], StoppingRule{id, version})
}

// supersededRules is every version of a rule in stoppingRules that its
// version there replaced. A route naming one is read only as the route a list
// is carried from, and a stop naming one, which only a carry writes, is
// judged as a stop of the version that replaced it, so an upgrade drops no
// stop; a lift does not cover the replacing version's finding, whose id differs.
var supersededRules = [...]StoppingRule{
	{"REPEATED_DENIAL", "1"},
}

// SupersededRules is a copy of every rule version a later one replaced.
func SupersededRules() []StoppingRule { return slices.Clone(supersededRules[:]) }

// Superseded reports whether version of rule id is one StoppingRules
// replaced, both compared byte for byte.
func Superseded(id, version string) bool {
	_, ok := replacement(id, version)
	return ok
}

// replacement is the version StoppingRules names for a superseded version of
// rule id.
func replacement(id, version string) (string, bool) {
	if !slices.Contains(supersededRules[:], StoppingRule{id, version}) {
		return "", false
	}
	for _, r := range stoppingRules {
		if r.ID == id {
			return r.Version, true
		}
	}
	return "", false
}

// retiredRules is every rule version a route could once name whose rule may
// stop a run at no version now, since its verdict compares two events' times,
// which no event ties to one plane's clock. A route naming one is read only
// as the route a list is carried from, and a stop naming one, which only a
// carry writes, stays until it expires or an operator lifts it: an upgrade
// lifts no stop. wider is whether a route could let it stop an agent or a
// principal.
var retiredRules = [...]struct {
	rule  StoppingRule
	wider bool
}{
	{StoppingRule{"DEADLINE_EXCEEDED", "1"}, false},
	{StoppingRule{"DENIED_ACTION_RETRIED_ARGUMENTS", "1"}, true},
	{StoppingRule{"DENIED_ACTION_RETRIED_RESOURCE", "1"}, true},
}

// RetiredRules is a copy of every rule version no route may name any more
// and no later version replaced.
func RetiredRules() []StoppingRule {
	out := make([]StoppingRule, 0, len(retiredRules))
	for _, r := range retiredRules {
		out = append(out, r.rule)
	}
	return out
}

// Retired reports whether version of rule id is one RetiredRules names,
// both compared byte for byte.
func Retired(id, version string) bool {
	_, ok := retired(id, version)
	return ok
}

// retired is whether a route could let retired rule id at version stop an
// agent or a principal; ok is false for a rule version that is not retired.
func retired(id, version string) (wider, ok bool) {
	for _, r := range retiredRules {
		if r.rule == (StoppingRule{id, version}) {
			return r.wider, true
		}
	}
	return false, false
}

// CheckStopping refuses a route that names any rule outside StoppingRules,
// or a rule of an agent or principal checkRuleScope refuses.
// VerifyRoute, Judge and the stop list's writers call it, so a route read
// from a signed file, judged against or handed to a writer is held to the
// table however it was signed. ParseRoute does not, so route sign can first say which of
// supervise's own checks a rule fails.
func CheckStopping(r Route) error {
	return checkRules(r, MayStop)
}

// CheckCarrySource refuses a route that names any rule outside
// StoppingRules, SupersededRules and RetiredRules. Only the route a list is
// carried from is held to it, by VerifyCarrySource and JudgeCarrySource.
func CheckCarrySource(r Route) error {
	return checkRules(r, func(id, version string) bool {
		return MayStop(id, version) || Superseded(id, version) || Retired(id, version)
	})
}

func checkRules(r Route, allowed func(id, version string) bool) error {
	for i, rule := range r.rules {
		if !allowed(rule.RuleID, rule.RuleVersion) {
			return fmt.Errorf("rules[%d]: %w: rule_id %q rule_version %q", i, ErrRouteRuleStops, rule.RuleID, rule.RuleVersion)
		}
		if err := checkRuleScope(rule); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}
