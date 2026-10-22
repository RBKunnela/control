package supervise

import (
	"slices"
	"strings"
)

// RuleIDs is every rule a 0.1 procedure configures, in the order a report
// lists them. The slice is a copy.
func RuleIDs() []string { return slices.Clone(ruleIDs) }

// ApplyAlone applies rule id to in with no other rule applied before it, and
// returns the anchor of each finding it would raise, its parts joined by a
// slash.
func ApplyAlone(in Input, id string) ([]string, error) {
	e, err := prepare(in)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range e.apply(id) {
		out = append(out, strings.Join(d.anchor, "/"))
	}
	return out, nil
}
