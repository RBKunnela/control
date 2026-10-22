package supervise

import (
	"slices"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// continued fires for a failed instance that a different step's instance
// follows: the first proposed after the failed one's terminal event. A retry
// of the same step is no finding: one proposed after the failure ends the
// search, since what follows it follows the retry, and one that may have come
// before the failure is passed over, as is the first of a step reported out
// of order, which is not also a continuation. When the line of timed
// proposals names no such instance, one of another step whose place against
// the failure is unknown makes the pair indeterminate.
func (e *evaluation) continued() []draft {
	_, outOfOrder := e.outOfOrder()
	var line, unplaced []*instance
	for _, in := range e.inst {
		if in.timed {
			line = append(line, in)
		} else {
			unplaced = append(unplaced, in)
		}
	}
	slices.SortFunc(line, byProposal)
	excused := func(in *instance) bool {
		first, _ := e.firstOf(in.step)
		return outOfOrder[in.step] && first == in
	}
	var out []draft
	for _, failed := range slices.Concat(line, unplaced) {
		if !failed.failed || excused(failed) {
			continue
		}
		other := func(in *instance) bool { return in.step != failed.step && !excused(in) }
		next, verdict := e.afterFailure(line, failed, other)
		if next == nil {
			next, verdict = mayFollow(line, unplaced, failed, other), indeterminate
		}
		if next != nil {
			out = append(out, draft{rule: RuleContinuedAfterFailure, anchor: []string{failed.request},
				cap: verdict, refs: []ref{failed.end, next.start}})
		}
	}
	return out
}

// afterFailure is the first instance of line, ordered by proposal, that
// follows failed's failure and is other, before any retry proposed after the
// failure, and the verdict the pair allows. One proposed at the failure's own
// time, or the next proposed when the failure has no time, may have come
// before it, so the pair is then indeterminate. A failure with no time whose
// proposal has none either has no place in line. Proposals of one time are
// untold against each other wherever they were read: when a retry may have
// come first the pair is indeterminate, and of several next instances the
// one of the least request id is cited.
func (e *evaluation) afterFailure(line []*instance, failed *instance, other func(*instance) bool) (*instance, controlv1.FindingVerdict) {
	from := failed.endAt
	switch {
	case failed.endTimed:
	case failed.timed:
		from = failed.at
	default:
		return nil, indeterminate
	}
	i, _ := slices.BinarySearchFunc(line, from, func(in *instance, t time.Time) int { return in.at.Compare(t) })
	retry, next := firstAfter(line[i:], failed, other)
	if next == nil {
		return nil, indeterminate
	}
	if retry || !failed.endTimed || next.at.Equal(failed.endAt) {
		return next, indeterminate
	}
	return next, e.absenceCap()
}

// firstAfter takes the earliest instant of line at which an instance is a
// retry of failed or other, and returns whether a retry is among that
// instant's instances and the first of them that is other, if any.
func firstAfter(line []*instance, failed *instance, other func(*instance) bool) (retry bool, next *instance) {
	var at time.Time
	found := false
	for _, in := range line {
		isRetry := retried(failed, in)
		if !isRetry && !other(in) {
			continue
		}
		if found && !in.at.Equal(at) {
			break
		}
		found, at = true, in.at
		switch {
		case isRetry:
			retry = true
		case next == nil:
			next = in
		}
	}
	return retry, next
}

// retried reports in a retry of failed's step proposed after its failure.
func retried(failed, in *instance) bool {
	return in != failed && in.step == failed.step && failed.endTimed && in.at.After(failed.endAt)
}

// mayFollow is the first instance that is other and may have been proposed
// after failed's failure without line saying so: one whose proposal has no
// time, or, when the failure has no time, any proposed after failed.
func mayFollow(line, unplaced []*instance, failed *instance, other func(*instance) bool) *instance {
	pool := unplaced
	if !failed.endTimed {
		pool = slices.Concat(line[slices.Index(line, failed)+1:], unplaced)
	}
	for _, in := range pool {
		if other(in) {
			return in
		}
	}
	return nil
}
