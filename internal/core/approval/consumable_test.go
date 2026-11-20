package approval_test

import (
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
)

// The moments every row is placed against. One nanosecond apart is the
// closest a timestamp can stand to a bound without reaching it.
var (
	requestedAt = time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	judgedAt    = requestedAt.Add(10 * time.Minute)
)

type decidedAt uint8

const (
	decidedNever decidedAt = iota
	decidedBeforeRequest
	decidedAtRequest
	decidedAtNow
	decidedAfterNow
)

type expiresAt uint8

const (
	expiresNever expiresAt = iota
	expiresBeforeNow
	expiresAtNow
	expiresAfterNow
)

const undeclaredState = controlv1.ApprovalState(99)

// row is one combination of what Consumable reads, named by what it is
// rather than by the times it becomes.
type row struct {
	state    controlv1.ApprovalState
	approver string
	multiUse bool
	decided  decidedAt
	expires  expiresAt
}

func (r row) String() string {
	return fmt.Sprintf("%s/approver=%q/multi=%t/decided=%d/expires=%d", r.state, r.approver, r.multiUse, r.decided, r.expires)
}

func (r row) approval() *controlv1.Approval {
	a := &controlv1.Approval{
		State:       r.state,
		ApproverId:  r.approver,
		MultiUse:    r.multiUse,
		RequestedAt: timestamppb.New(requestedAt),
	}
	switch r.decided {
	case decidedBeforeRequest:
		a.DecidedAt = timestamppb.New(requestedAt.Add(-time.Nanosecond))
	case decidedAtRequest:
		a.DecidedAt = timestamppb.New(requestedAt)
	case decidedAtNow:
		a.DecidedAt = timestamppb.New(judgedAt)
	case decidedAfterNow:
		a.DecidedAt = timestamppb.New(judgedAt.Add(time.Nanosecond))
	}
	switch r.expires {
	case expiresBeforeNow:
		a.ExpiresAt = timestamppb.New(judgedAt.Add(-time.Nanosecond))
	case expiresAtNow:
		a.ExpiresAt = timestamppb.New(judgedAt)
	case expiresAfterNow:
		a.ExpiresAt = timestamppb.New(judgedAt.Add(time.Nanosecond))
	}
	return a
}

// rows is every combination of the five dimensions.
func rows() []row {
	var out []row
	for _, state := range []controlv1.ApprovalState{
		controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
		controlv1.ApprovalState_APPROVAL_STATE_REJECTED,
		controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED,
		undeclaredState,
	} {
		for _, approver := range []string{"", "duty-officer"} {
			for _, multiUse := range []bool{false, true} {
				for decided := decidedNever; decided <= decidedAfterNow; decided++ {
					for expires := expiresNever; expires <= expiresAfterNow; expires++ {
						out = append(out, row{state, approver, multiUse, decided, expires})
					}
				}
			}
		}
	}
	return out
}

// standingOf is the order restated over the row's names, with no time in it.
func standingOf(r row) approval.Standing {
	switch {
	case r.multiUse:
		return approval.StandingMultiUse
	case r.expires != expiresAfterNow:
		return approval.StandingExpired
	case r.decided != decidedAtRequest && r.decided != decidedAtNow:
		return approval.StandingUnusable
	case r.state == controlv1.ApprovalState_APPROVAL_STATE_REJECTED:
		return approval.StandingRejected
	case r.state == controlv1.ApprovalState_APPROVAL_STATE_APPROVED && r.approver != "":
		return approval.StandingUsable
	}
	return approval.StandingUnusable
}

// TestConsumableAnswersEveryCombinationInItsOrder: each row's standing is the
// one the order names, and the counts per standing are written out, so an
// expectation that drifted with the code under test would still be caught.
func TestConsumableAnswersEveryCombinationInItsOrder(t *testing.T) {
	counts := map[approval.Standing]int{}
	for _, r := range rows() {
		got := approval.Consumable(r.approval(), judgedAt)
		if want := standingOf(r); got != want {
			t.Errorf("%s: Consumable = %d, want %d", r, got, want)
		}
		counts[got]++
	}
	want := map[approval.Standing]int{
		approval.StandingUsable:   2,
		approval.StandingRejected: 4,
		approval.StandingExpired:  120,
		approval.StandingMultiUse: 160,
		approval.StandingUnusable: 34,
	}
	for standing, n := range want {
		if counts[standing] != n {
			t.Errorf("%d rows stand at %d, want %d", counts[standing], standing, n)
		}
	}
}

// TestAZeroMomentRefusesEveryRow: a zero now would pass every expiry, so no
// row stands at anything but unusable, the multi-use and expired ones
// included.
func TestAZeroMomentRefusesEveryRow(t *testing.T) {
	for _, r := range rows() {
		if got := approval.Consumable(r.approval(), time.Time{}); got != approval.StandingUnusable {
			t.Errorf("%s at a zero now: Consumable = %d, want unusable", r, got)
		}
	}
}

// TestTheNamedRowsStandWhereTheOrderPutsThem holds the rows each step of the
// order turns on to a literal standing.
func TestTheNamedRowsStandWhereTheOrderPutsThem(t *testing.T) {
	approved := controlv1.ApprovalState_APPROVAL_STATE_APPROVED
	rejected := controlv1.ApprovalState_APPROVAL_STATE_REJECTED
	for name, c := range map[string]struct {
		r    row
		want approval.Standing
	}{
		"approved at now":                         {row{approved, "duty-officer", false, decidedAtNow, expiresAfterNow}, approval.StandingUsable},
		"approved at the request":                 {row{approved, "duty-officer", false, decidedAtRequest, expiresAfterNow}, approval.StandingUsable},
		"approved with no approver":               {row{approved, "", false, decidedAtNow, expiresAfterNow}, approval.StandingUnusable},
		"approved and multi-use":                  {row{approved, "duty-officer", true, decidedAtNow, expiresAfterNow}, approval.StandingMultiUse},
		"multi-use and expired":                   {row{approved, "duty-officer", true, decidedAtNow, expiresBeforeNow}, approval.StandingMultiUse},
		"approved and expiring at now":            {row{approved, "duty-officer", false, decidedAtNow, expiresAtNow}, approval.StandingExpired},
		"approved with no expiry":                 {row{approved, "duty-officer", false, decidedAtNow, expiresNever}, approval.StandingExpired},
		"expired before it was decided":           {row{approved, "duty-officer", false, decidedNever, expiresBeforeNow}, approval.StandingExpired},
		"approved with no decision time":          {row{approved, "duty-officer", false, decidedNever, expiresAfterNow}, approval.StandingUnusable},
		"approved before the request":             {row{approved, "duty-officer", false, decidedBeforeRequest, expiresAfterNow}, approval.StandingUnusable},
		"approved after now":                      {row{approved, "duty-officer", false, decidedAfterNow, expiresAfterNow}, approval.StandingUnusable},
		"rejected at now":                         {row{rejected, "duty-officer", false, decidedAtNow, expiresAfterNow}, approval.StandingRejected},
		"rejected with no approver":               {row{rejected, "", false, decidedAtRequest, expiresAfterNow}, approval.StandingRejected},
		"rejected after now":                      {row{rejected, "duty-officer", false, decidedAfterNow, expiresAfterNow}, approval.StandingUnusable},
		"rejected before the request":             {row{rejected, "", false, decidedBeforeRequest, expiresAfterNow}, approval.StandingUnusable},
		"unspecified with an approver":            {row{controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED, "duty-officer", false, decidedAtNow, expiresAfterNow}, approval.StandingUnusable},
		"an undeclared state with an approver":    {row{undeclaredState, "duty-officer", false, decidedAtNow, expiresAfterNow}, approval.StandingUnusable},
		"pending with an approver and a decision": {row{controlv1.ApprovalState_APPROVAL_STATE_PENDING, "duty-officer", false, decidedAtNow, expiresAfterNow}, approval.StandingUnusable},
	} {
		if got := approval.Consumable(c.r.approval(), judgedAt); got != c.want {
			t.Errorf("%s: Consumable = %d, want %d", name, got, c.want)
		}
	}
}

// TestAnApprovalNotThereIsUnusable: nil is no approval at any moment.
func TestAnApprovalNotThereIsUnusable(t *testing.T) {
	for _, now := range []time.Time{judgedAt, {}} {
		if got := approval.Consumable(nil, now); got != approval.StandingUnusable {
			t.Errorf("Consumable(nil, %v) = %d, want unusable", now, got)
		}
	}
}

// TestAnAnswerWithNoDecisionTimeIsNoAnswer: with no request time either, a
// missing decision time read as a time would fall inside the window.
func TestAnAnswerWithNoDecisionTimeIsNoAnswer(t *testing.T) {
	a := &controlv1.Approval{
		State:      controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
		ApproverId: "duty-officer",
		ExpiresAt:  timestamppb.New(judgedAt.Add(time.Nanosecond)),
	}
	if got := approval.Consumable(a, judgedAt); got != approval.StandingUnusable {
		t.Errorf("an approval with no request and no decision time = %d, want unusable", got)
	}
}

// TestExpiredIsAtOrPastTheExpiry: the bound itself is expired, one
// nanosecond before it is not, and no expiry or no approval is expired at any
// moment, one before the Unix epoch included.
func TestExpiredIsAtOrPastTheExpiry(t *testing.T) {
	expiry := timestamppb.New(judgedAt)
	for name, c := range map[string]struct {
		a    *controlv1.Approval
		now  time.Time
		want bool
	}{
		"before the expiry":  {&controlv1.Approval{ExpiresAt: expiry}, judgedAt.Add(-time.Nanosecond), false},
		"at the expiry":      {&controlv1.Approval{ExpiresAt: expiry}, judgedAt, true},
		"past the expiry":    {&controlv1.Approval{ExpiresAt: expiry}, judgedAt.Add(time.Nanosecond), true},
		"with no expiry":     {&controlv1.Approval{}, judgedAt, true},
		"no expiry, in 1960": {&controlv1.Approval{}, time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC), true},
		"with no approval":   {nil, judgedAt, true},
		"long before expiry": {&controlv1.Approval{ExpiresAt: expiry}, requestedAt, false},
		"at a zero moment":   {&controlv1.Approval{ExpiresAt: expiry}, time.Time{}, false},
	} {
		if got := approval.Expired(c.a, c.now); got != c.want {
			t.Errorf("%s: Expired = %t, want %t", name, got, c.want)
		}
	}
}

// TestAMalformedExpiryIsExpired: an expiry that is not a timestamp, which
// the runtime would normalise to a moment after now, bounds nothing and is
// read as no expiry. The same approval with a well-formed expiry one second
// later is usable, so the expiry alone decides each row.
func TestAMalformedExpiryIsExpired(t *testing.T) {
	approved := func(expiry *timestamppb.Timestamp) *controlv1.Approval {
		return &controlv1.Approval{
			State:       controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
			ApproverId:  "duty-officer",
			RequestedAt: timestamppb.New(requestedAt),
			DecidedAt:   timestamppb.New(judgedAt),
			ExpiresAt:   expiry,
		}
	}
	second := judgedAt.Unix()
	if got := approval.Consumable(approved(&timestamppb.Timestamp{Seconds: second + 1}), judgedAt); got != approval.StandingUsable {
		t.Fatalf("the approval with a well-formed expiry = %d, want usable, so the rows below prove nothing", got)
	}
	for name, expiry := range map[string]*timestamppb.Timestamp{
		"nanos of two seconds":   {Seconds: second - 1, Nanos: 2_000_000_000},
		"nanos of one second":    {Seconds: second, Nanos: 1_000_000_000},
		"negative nanos":         {Seconds: second + 2, Nanos: -1},
		"seconds past year 9999": {Seconds: 253_402_300_800},
	} {
		if got := approval.Consumable(approved(expiry), judgedAt); got != approval.StandingExpired {
			t.Errorf("%s: Consumable = %d, want expired", name, got)
		}
		if !approval.Expired(approved(expiry), judgedAt) {
			t.Errorf("%s: Expired = false, want true", name)
		}
	}
}

func TestAMalformedDecisionTimeIsNoDecision(t *testing.T) {
	approved := func(decided *timestamppb.Timestamp) *controlv1.Approval {
		return &controlv1.Approval{
			State:       controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
			ApproverId:  "duty-officer",
			RequestedAt: timestamppb.New(requestedAt),
			DecidedAt:   decided,
			ExpiresAt:   timestamppb.New(judgedAt.Add(time.Minute)),
		}
	}
	if got := approval.Consumable(approved(timestamppb.New(judgedAt)), judgedAt); got != approval.StandingUsable {
		t.Fatalf("the approval decided at a well-formed time = %d, want usable, so the rows below prove nothing", got)
	}
	second := judgedAt.Unix()
	for name, decided := range map[string]*timestamppb.Timestamp{
		"nanos of two seconds": {Seconds: second - 2, Nanos: 1_999_999_999},
		"negative nanos":       {Seconds: second - 1, Nanos: -5},
	} {
		if got := approval.Consumable(approved(decided), judgedAt); got != approval.StandingUnusable {
			t.Errorf("%s: Consumable = %d, want unusable", name, got)
		}
	}
}
