package core

import (
	"time"

	"github.com/guardana/control/internal/policy"
)

// Basis is what a decision stood on: the bundle it was decided under, none
// for no snapshot, whether that bundle was fresh then, and whether the
// fail-closed table let a read run under FailOpenRead. Only the kernel makes
// one; the zero value stood on nothing, and Recheck never hands out a call on
// it.
type Basis struct {
	set    bool
	digest string
	fresh  bool
	opened bool
}

// Stood reports whether the decision's policy let its call run when it was
// made: the bundle was fresh, or the table let the read run. A call whose
// basis did not stand was not let run by its policy in the first place.
func (b Basis) Stood() bool { return b.set && (b.fresh || b.opened) }

// Standing is how a decision's basis stands at a later reading.
type Standing uint8

const (
	// StandingUnknown is a basis that cannot be judged: none, a kernel nobody
	// built, a reading the clock step would refuse or one behind the caller's
	// floor, or no snapshot where the decision had one. It withholds the call.
	StandingUnknown Standing = iota
	// StandingCurrent is the bundle the decision stood on, still fresh, or
	// still in the row of the fail-closed table that let the read run.
	StandingCurrent
	// StandingStale is the bundle the decision stood on, no longer fresh.
	StandingStale
	// StandingReplaced is another bundle than the decision's, or one where
	// the decision had none.
	StandingReplaced
)

// Recheck judges again, at the reading now, the basis b of a decision this
// kernel made, against installed, the snapshot the plane holds now
// (ADR-0055). It can only withhold a call the decision let run, never let one
// run that the decision did not: only StandingCurrent hands it out. A reading
// earlier than floor, an instant the caller already relied on, judges
// nothing, so a clock that stepped back cannot make a stale bundle fresh. A
// read the table let run under a stale bundle stays in that row while the
// bundle is the same; a call decided fresh that is stale now is withheld even
// where the table would open a read, since its record carries no
// FAIL_OPEN_READ_CONFIGURED.
func (k *Kernel) Recheck(b Basis, installed *policy.Snapshot, now, floor time.Time) Standing {
	switch {
	case k == nil || k.clock == nil || !b.set:
		return StandingUnknown
	case !policy.UsableTime(now) || now.Before(floor) || now.Before(installed.NotBefore()):
		return StandingUnknown
	case installed == nil && b.digest != "":
		return StandingUnknown
	case installed.Ref().GetDigest() != b.digest:
		return StandingReplaced
	case b.opened || installed.FreshAt(now, k.maxStale):
		return StandingCurrent
	}
	return StandingStale
}
