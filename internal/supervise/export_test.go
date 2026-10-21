package supervise

import "slices"

// RuleIDs is every rule a 0.1 procedure configures, in the order a report
// lists them. The slice is a copy.
func RuleIDs() []string { return slices.Clone(ruleIDs) }
