package approvals_test

import (
	"errors"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
)

// TestTwoApproversAnsweringOneRecordFileOneAnswer: two handles, each with a
// mutex of its own, both read the record pending. The second files its answer
// after the first linked its own and before the first took the held name
// away, so only the link can tell them apart: one answer is filed, the other
// is refused, and the record carries the first.
func TestTwoApproversAnsweringOneRecordFileOneAnswer(t *testing.T) {
	_, dir, _ := heldOne(t)
	second := openApprover(t, dir)
	var secondErr error
	opt, arm := afterLink(t, func() {
		_, secondErr = second.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_REJECTED,
			"approver-b", "too late", minted.Add(2*time.Minute))
	})
	first := openApprover(t, dir, opt)
	arm()
	_, firstErr := first.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
		"approver-a", "first", minted.Add(time.Minute))
	if firstErr != nil {
		t.Fatalf("the first answer = %v, want it filed", firstErr)
	}
	if !errors.Is(secondErr, approvals.ErrApprovalAnswered) {
		t.Fatalf("the second answer = %v, want ErrApprovalAnswered", secondErr)
	}
	assertNames(t, dir, answeredName)
	l, err := openApprover(t, dir).List(t.Context())
	if err != nil || len(l.Entries) != 1 {
		t.Fatalf("listing the record: %d entries, %v", len(l.Entries), err)
	}
	got := l.Entries[0].Record.Approval
	if got.GetState() != controlv1.ApprovalState_APPROVAL_STATE_APPROVED || got.GetApproverId() != "approver-a" ||
		got.GetReason() != "first" || !got.GetDecidedAt().AsTime().Equal(minted.Add(time.Minute)) {
		t.Errorf("the record carries %s by %q for %q at %v, want the first answer",
			got.GetState(), got.GetApproverId(), got.GetReason(), got.GetDecidedAt().AsTime())
	}
}

// TestAnAnswerDecidedAfterTheReadingIsNotYetAnAnswer: an answer whose decided
// time is later than the clock it is read at would put the decision after the
// action it allowed. Find hands it back as it was decided, and what the plane
// judges it by says it is no answer yet; nothing on disk changes.
func TestAnAnswerDecidedAfterTheReadingIsNotYetAnAnswer(t *testing.T) {
	decided := minted.Add(2 * time.Minute)
	for _, c := range []struct {
		answer controlv1.ApprovalState
		at     approval.Standing
	}{
		{controlv1.ApprovalState_APPROVAL_STATE_APPROVED, approval.StandingUsable},
		{controlv1.ApprovalState_APPROVAL_STATE_REJECTED, approval.StandingRejected},
	} {
		t.Run(c.answer.String(), func(t *testing.T) {
			p, dir, h := heldOne(t)
			if _, err := openApprover(t, dir).Answer(t.Context(), firstApproval, c.answer, "approver-1", "", decided); err != nil {
				t.Fatalf("answering: %v", err)
			}
			early := decided.Add(-time.Nanosecond)
			found, err := p.Find(t.Context(), h.Binding, early)
			if err != nil || len(found) != 1 || !found[0].Approval.GetDecidedAt().AsTime().Equal(decided) {
				t.Fatalf("Find one nanosecond before the decision = %v, %v; want the answer as it was decided", found, err)
			}
			if got := approval.Consumable(found[0].Approval, early); got != approval.StandingUnusable {
				t.Errorf("the answer one nanosecond before its decision stands %v, want unusable", got)
			}
			if got := approval.Consumable(found[0].Approval, decided); got != c.at {
				t.Errorf("the answer at its decision stands %v, want %v", got, c.at)
			}
			assertNames(t, dir, answeredName)
		})
	}
}

// TestAnApprovalWithNoDecidedTimeIsNotUsable: a record written straight into
// the directory as approved, with no time it was decided at, cannot be shown
// to have been decided before the call it would allow.
func TestAnApprovalWithNoDecidedTimeIsNotUsable(t *testing.T) {
	p, dir, h := heldOne(t)
	forged := withApprovalField(t, readFile(t, dir, heldName), "state", `"APPROVAL_STATE_APPROVED"`)
	writeFile(t, dir, heldName, withApprovalField(t, forged, "approverId", `"approver-1"`))
	found, err := p.Find(t.Context(), h.Binding, minted.Add(time.Minute))
	if err != nil || len(found) != 1 {
		t.Fatalf("Find = %v, %v", found, err)
	}
	if got := approval.Consumable(found[0].Approval, minted.Add(time.Minute)); got != approval.StandingUnusable {
		t.Errorf("an approval decided at no time stands %v, want unusable", got)
	}
	assertNames(t, dir, heldName)
}
