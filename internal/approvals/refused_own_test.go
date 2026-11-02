package approvals_test

import (
	"errors"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
)

// TestTheOwnResolvedRecordRefusedForItsApproverRefusesTheCall: the plane's
// own record, spent or given up on, is rewritten to an approver id the claim
// rule refuses. Consume and Resolve then refuse with the reservation's
// sentinel, never ErrNoApproval, which would tell the agent its request is
// still pending rather than block it. The same record under a plain approver
// answers as its state says.
func TestTheOwnResolvedRecordRefusedForItsApproverRefusesTheCall(t *testing.T) {
	spend := func(t *testing.T, p *approvals.Plane, h approvals.Hold, now time.Time) {
		if _, err := p.Consume(t.Context(), h.Binding, "req-1", firstApproval, now); err != nil {
			t.Fatalf("consuming: %v", err)
		}
	}
	giveUp := func(t *testing.T, p *approvals.Plane, h approvals.Hold, now time.Time) {
		if err := p.Resolve(t.Context(), h.Binding, "req-1", firstApproval, approvals.ResolutionNotResumed, now); err != nil {
			t.Fatalf("resolving: %v", err)
		}
	}
	for _, c := range []struct {
		name, file, approver string
		resolve              func(*testing.T, *approvals.Plane, approvals.Hold, time.Time)
		consume, resolveErr  error
	}{
		{"consumed, a plain approver", consumedName, "approver-2", spend, approvals.ErrApprovalConsumed, approvals.ErrApprovalConsumed},
		{"consumed, a reserved approver", consumedName, reservedApprover, spend, approval.ErrReservedApproverID, approval.ErrReservedApproverID},
		{"not resumed, a plain approver", notResumedName, "approver-2", giveUp, approvals.ErrNoApproval, nil},
		{"not resumed, a reserved approver", notResumedName, reservedApprover, giveUp, approval.ErrReservedApproverID, approval.ErrReservedApproverID},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, dir, h := heldOne(t)
			answerAt(t, dir, minted.Add(time.Minute))
			now := minted.Add(2 * time.Minute)
			c.resolve(t, p, h, now)
			writeFile(t, dir, c.file, withApprovalField(t, readFile(t, dir, c.file), "approverId", `"`+c.approver+`"`))

			if got, err := p.Consume(t.Context(), h.Binding, "req-1", firstApproval, now); got != nil || !errors.Is(err, c.consume) {
				t.Errorf("Consume = %v, %v; want nothing and %v", got, err, c.consume)
			}
			err := p.Resolve(t.Context(), h.Binding, "req-1", firstApproval, approvals.ResolutionNotResumed, now)
			if !errors.Is(err, c.resolveErr) {
				t.Errorf("Resolve = %v, want %v", err, c.resolveErr)
			}
		})
	}
}
