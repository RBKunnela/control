package diagramdoc

import (
	"fmt"
	"slices"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
)

// The five inputs of the fail-closed rule beside the effect, in the order
// the table's columns show them and the reverse of the order rows collapse.
var dimensions = []string{"a cause in the request", "a cause in the policy's availability", "fail-open reads on", "a snapshot present", "the determinate verdict"}

// row is one line of the rendered table: a value per dimension, or "any",
// or a list of the values that share the action.
type row struct {
	values [5]string
	action string
}

// failClosedTable renders the kernel's fail-closed table from the listing:
// effects with the same answers under every input share one group, and
// within a group the values of a dimension that make no difference to the
// action collapse into "any", or into the list of values that share it.
func failClosedTable() ([]byte, error) {
	rows := core.FailClosedRows()
	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: the kernel listed no fail-closed cell", ErrBlock)
	}
	groups, labels := groupEffects(rows)
	verdicts := controlv1.Verdict(0).Descriptor().Values().Len()
	cardinality := [5]int{2, 2, 2, 2, verdicts}
	var b strings.Builder
	fmt.Fprintf(&b, "| Effect class | %s | Action |\n| --- |", strings.Join(dimensions, " | "))
	b.WriteString(strings.Repeat(" --- |", len(dimensions)+1) + "\n")
	for _, label := range labels {
		for _, r := range collapse(groups[label], cardinality) {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", label, strings.Join(r.values[:], " | "), r.action)
		}
	}
	return []byte(b.String()), nil
}

// groupEffects keys every effect by the answers it gets, so effects the rule
// treats alike share a label, in descriptor order with the undeclared last.
func groupEffects(rows []core.FailClosedRow) (map[string][]row, []string) {
	byEffect := map[string][]row{}
	var order []string
	for _, r := range rows {
		name := effectName(r)
		if _, seen := byEffect[name]; !seen {
			order = append(order, name)
		}
		byEffect[name] = append(byEffect[name], row{values: [5]string{yesNo(r.Input), yesNo(r.Availability), yesNo(r.FailOpenRead), yesNo(r.Snapshot), verdictName(r.Determinate)}, action: actionName(r)})
	}
	signature := func(rs []row) string {
		parts := make([]string, len(rs))
		for i, r := range rs {
			parts[i] = strings.Join(r.values[:], ",") + "=" + r.action
		}
		slices.Sort(parts)
		return strings.Join(parts, ";")
	}
	groups := map[string][]row{}
	var labels []string
	members := map[string][]string{}
	for _, name := range order {
		sig := signature(byEffect[name])
		if _, seen := members[sig]; !seen {
			labels = append(labels, sig)
			groups[sig] = byEffect[name]
		}
		members[sig] = append(members[sig], name)
	}
	out := map[string][]row{}
	labelled := make([]string, len(labels))
	for i, sig := range labels {
		label := strings.Join(members[sig], ", ")
		labelled[i] = label
		out[label] = groups[sig]
	}
	return out, labelled
}

// collapse merges, dimension by dimension from the last, the rows that
// differ only in that dimension and share an action: every value of it
// becomes "any", and a proper subset becomes the list of those values.
func collapse(rows []row, cardinality [5]int) []row {
	for d := len(dimensions) - 1; d >= 0; d-- {
		var merged []row
		var order []string
		buckets := map[string][]row{}
		for _, r := range rows {
			key := r.values
			key[d] = ""
			k := strings.Join(key[:], "|")
			if _, seen := buckets[k]; !seen {
				order = append(order, k)
			}
			buckets[k] = append(buckets[k], r)
		}
		for _, k := range order {
			merged = append(merged, mergeBucket(buckets[k], d, cardinality[d])...)
		}
		rows = merged
	}
	return rows
}

// mergeBucket joins the rows of one bucket by action, in first-seen order:
// an action every value of the dimension shares reads "any", fewer values
// read as their list.
func mergeBucket(bucket []row, d, cardinality int) []row {
	var out []row
	var actions []string
	values := map[string][]string{}
	for _, r := range bucket {
		if _, seen := values[r.action]; !seen {
			actions = append(actions, r.action)
		}
		values[r.action] = append(values[r.action], r.values[d])
	}
	for _, action := range actions {
		r := bucket[0]
		r.action = action
		if len(values[action]) == cardinality {
			r.values[d] = "any"
		} else {
			r.values[d] = strings.Join(values[action], " or ")
		}
		out = append(out, r)
	}
	return out
}

func effectName(r core.FailClosedRow) string {
	if !r.Declared {
		return "a number no build declares"
	}
	return "`" + strings.TrimPrefix(r.Effect.String(), "EFFECT_CLASS_") + "`"
}

func verdictName(v controlv1.Verdict) string {
	return "`" + strings.TrimPrefix(v.String(), "VERDICT_") + "`"
}

func actionName(r core.FailClosedRow) string {
	if r.OpenedRead {
		return "runs, recorded as a fail-open read"
	}
	return "blocks"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
