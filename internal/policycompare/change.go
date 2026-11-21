package policycompare

import (
	"slices"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
)

// Change is how a case's decision moved from the current policy to the
// candidate.
type Change string

const (
	// Unchanged is the same verdict, action, codes and obligations.
	Unchanged Change = "unchanged"
	// Stricter is an after side further from running the call, or as far
	// under more binding obligations, that still binds every obligation the
	// before side bound; a block binds them all.
	Stricter Change = "stricter"
	// Looser is the reverse of Stricter.
	Looser Change = "looser"
	// Other is a change that moves both ways, changes an obligation's
	// parameters, or changes only the verdict, codes or advisory
	// obligations; it is read row by row.
	Other Change = "other"
	// Unknown is a case unknown on either side, never one of the four.
	Unknown Change = "unknown"
)

// Changes is every change, in the order the report counts them.
func Changes() []Change { return []Change{Unchanged, Stricter, Looser, Other, Unknown} }

// side is one policy's decision of one case.
type side struct {
	evaluated   bool
	err         string
	verdict     controlv1.Verdict
	action      core.EnforcementAction
	codes       []string
	obligations []*controlv1.Obligation
	// missing is every input an undetermined rule lacked, once each, in the
	// order the rules read them.
	missing  []string
	external bool
	stale    bool
}

// strictness orders the four actions by how far each is from running the
// call: run, run under obligations, hold for an approval, block.
var strictness = map[core.EnforcementAction]int{
	core.Execute:                0,
	core.ExecuteWithObligations: 1,
	core.AwaitApproval:          2,
	core.Block:                  3,
}

// classify compares two decisions of one case by the action and the binding
// obligations together. A side not evaluated, or an action this order does
// not name, is unknown rather than guessed.
func classify(before, after side) Change {
	b, knownB := rank(before)
	a, knownA := rank(after)
	switch {
	case !before.evaluated || !after.evaluated || !knownB || !knownA:
		return Unknown
	case sameDecision(before, after):
		return Unchanged
	}
	// A block lets nothing run, so it holds every obligation the other side
	// would have the call meet.
	afterHolds := after.action == core.Block || holdsAll(binding(after), binding(before))
	beforeHolds := before.action == core.Block || holdsAll(binding(before), binding(after))
	return order(a-b, afterHolds, beforeHolds)
}

// order is stricter when the after side is further from running the call,
// or as far while binding more, and still holds every binding obligation of
// the before side; looser the reverse; other whatever moves both ways.
func order(further int, afterHolds, beforeHolds bool) Change {
	switch {
	case afterHolds && (further > 0 || further == 0 && !beforeHolds):
		return Stricter
	case beforeHolds && (further < 0 || further == 0 && !afterHolds):
		return Looser
	}
	return Other
}

// rank is the side's place in strictness. Obligations that are all advisory
// bind nothing, so a call run under them ranks as one run without.
func rank(s side) (int, bool) {
	r, known := strictness[s.action]
	if s.action == core.ExecuteWithObligations && len(binding(s)) == 0 {
		r = strictness[core.Execute]
	}
	return r, known
}

func sameDecision(before, after side) bool {
	return before.verdict == after.verdict && slices.Equal(before.codes, after.codes) &&
		slices.EqualFunc(before.obligations, after.obligations, func(x, y *controlv1.Obligation) bool { return proto.Equal(x, y) })
}

// binding is every obligation of s the call must meet.
func binding(s side) []*controlv1.Obligation {
	var out []*controlv1.Obligation
	for _, o := range s.obligations {
		if !o.GetAdvisory() {
			out = append(out, o)
		}
	}
	return out
}

// holdsAll reports whether have holds each of need, type and parameters
// alike; a parameter changed is not ordered.
func holdsAll(have, need []*controlv1.Obligation) bool {
	for _, n := range need {
		if !slices.ContainsFunc(have, func(h *controlv1.Obligation) bool { return proto.Equal(h, n) }) {
			return false
		}
	}
	return true
}
