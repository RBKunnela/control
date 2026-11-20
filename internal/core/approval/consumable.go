package approval

import (
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// Standing is what an approval allows at one moment, as every store that
// consumes approvals reads it. The zero value refuses.
type Standing uint8

const (
	// StandingUnusable is an approval nothing may run on: no moment to judge
	// it at, no approval, no answer inside its window, or no approval given.
	StandingUnusable Standing = iota
	// StandingUsable is an approval an approver gave, inside its window and
	// before its expiry: one execution may spend it.
	StandingUsable
	// StandingRejected is an approval an approver refused inside its window.
	StandingRejected
	// StandingExpired is an approval at or past its expiry, or with none.
	StandingExpired
	// StandingMultiUse is an approval marked multi-use, which no store
	// spends.
	StandingMultiUse
)

// Consumable is the standing of a at now, decided in one order that every
// store applies:
//
//  1. a zero now, or no approval, is unusable;
//  2. an approval marked multi-use is multi-use;
//  3. one at or past its expiry, or with none or one that is no valid
//     timestamp, is expired;
//  4. one decided at no time, before its request, or after now is unusable;
//  5. a rejected one is rejected;
//  6. an approved one with an approver is usable;
//  7. anything else is unusable.
//
// The answer says nothing about whether a store already spent the approval:
// that is the store's own record to keep.
func Consumable(a *controlv1.Approval, now time.Time) Standing {
	switch {
	case now.IsZero() || a == nil:
		return StandingUnusable
	case a.GetMultiUse():
		return StandingMultiUse
	case Expired(a, now):
		return StandingExpired
	case !decidedWithin(a, now):
		return StandingUnusable
	case a.GetState() == controlv1.ApprovalState_APPROVAL_STATE_REJECTED:
		return StandingRejected
	case a.GetState() == controlv1.ApprovalState_APPROVAL_STATE_APPROVED && a.GetApproverId() != "":
		return StandingUsable
	}
	return StandingUnusable
}

// Expired reports whether a is at or past its expiry at now. An approval with
// no expiry is expired: a record that never expires is one no bound reaches.
// So is one whose expiry is no valid timestamp, which AsTime would normalise
// to some other moment. A zero now stands before every expiry and reads as
// unexpired, so a record long past its expiry would read as live: every
// caller refuses a zero time before it asks, as Consumable does.
func Expired(a *controlv1.Approval, now time.Time) bool {
	expiry := a.GetExpiresAt()
	return expiry.CheckValid() != nil || !now.Before(expiry.AsTime())
}

// decidedWithin reports whether a was decided at or after its request and not
// after now. An answer is only an answer from the time it was decided at,
// and a decision time that is no valid timestamp names no time. A missing
// request time reads as the Unix epoch, which only a store that takes such a
// record can hand in.
func decidedWithin(a *controlv1.Approval, now time.Time) bool {
	if a.GetDecidedAt().CheckValid() != nil {
		return false
	}
	at := a.GetDecidedAt().AsTime()
	return !at.Before(a.GetRequestedAt().AsTime()) && !at.After(now)
}
