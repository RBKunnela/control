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
	{"DEADLINE_EXCEEDED", "1"},
	{"RESOURCE_OUTSIDE_RUN", "1"},
	{"DENIED_ACTION_RETRIED_ARGUMENTS", "1"},
	{"DENIED_ACTION_RETRIED_RESOURCE", "1"},
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

// CheckStopping refuses a route that names any rule outside StoppingRules.
// VerifyRoute, Judge and the stop list's writers call it, so a route read
// from a signed file, judged against or handed to a writer is held to the
// table however it was signed. ParseRoute does not, so route sign can first say which of
// supervise's own checks a rule fails.
func CheckStopping(r Route) error {
	return checkRules(r, MayStop)
}

// CheckCarrySource refuses a route that names any rule outside StoppingRules
// and SupersededRules. Only the route a list is carried from is held to it,
// by VerifyCarrySource and JudgeCarrySource.
func CheckCarrySource(r Route) error {
	return checkRules(r, func(id, version string) bool { return MayStop(id, version) || Superseded(id, version) })
}

func checkRules(r Route, allowed func(id, version string) bool) error {
	for i, rule := range r.rules {
		if !allowed(rule.RuleID, rule.RuleVersion) {
			return fmt.Errorf("rules[%d]: %w: rule_id %q rule_version %q", i, ErrRouteRuleStops, rule.RuleID, rule.RuleVersion)
		}
	}
	return nil
}
