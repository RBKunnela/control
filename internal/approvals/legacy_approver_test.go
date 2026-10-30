package approvals_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
)

// legacyApprovers are approver ids an earlier release wrote legally, which a
// claim may no longer hold: one mixes Latin and Cyrillic, one holds a
// private-use code point, one an unassigned one.
var legacyApprovers = []string{"Ivan \u0418\u0432\u0430\u043d", "ali\U000f0000ce", "ali\u0378ce"}

// heldElsewhere is the hold of a request for another action, so its record
// stands under another binding than held's.
func heldElsewhere(t *testing.T, approvalID, requestID string) approvals.Hold {
	t.Helper()
	h := held(t, approvalID, requestID)
	h.Envelope.Resource.Id = "pay-8"
	digest, binding, err := approval.Bind(h.Envelope, authorizedArgs, bundle)
	if err != nil {
		t.Fatalf("binding the fixture: %v", err)
	}
	h.Approval.ActionDigest, h.Binding = string(digest), binding
	return h
}

// legacyBeside holds two requests under two bindings, answers both as
// duty-officer, and rewrites the first answer's approver to approver, as a
// record an earlier release filed would read.
func legacyBeside(t *testing.T, approver string) (p *approvals.Plane, dir string, legacy, valid approvals.Hold) {
	t.Helper()
	p, dir = openPlane(t)
	legacy, valid = held(t, firstApproval, "req-1"), heldElsewhere(t, "APPROVAL2", "req-2")
	for _, h := range []approvals.Hold{legacy, valid} {
		if err := p.Hold(t.Context(), h, minted); err != nil {
			t.Fatalf("holding %s: %v", h.Approval.GetApprovalId(), err)
		}
	}
	a := openApprover(t, dir)
	for _, id := range []string{firstApproval, "APPROVAL2"} {
		if _, err := a.Answer(t.Context(), id, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "duty-officer", "", minted.Add(time.Minute)); err != nil {
			t.Fatalf("answering %s: %v", id, err)
		}
	}
	writeFile(t, dir, answeredName, withApprovalField(t, readFile(t, dir, answeredName), "approverId", jsonString(t, approver)))
	return p, dir, legacy, valid
}

// jsonString is s as a JSON string.
func jsonString(t *testing.T, s string) string {
	t.Helper()
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("quoting %+q: %v", s, err)
	}
	return string(out)
}

// TestARefusedLegacyApproverRefusesOnlyItsOwnApproval: beside a record whose
// approver the claim rule now refuses, another binding's approval is found,
// consumed and pruned, and another request is held. The record's own approval
// answers with the refusal, which a plane closes as unknown, and nothing
// spends it; once it expires Prune removes it.
func TestARefusedLegacyApproverRefusesOnlyItsOwnApproval(t *testing.T) {
	for _, approver := range legacyApprovers {
		t.Run(approver, func(t *testing.T) {
			p, dir, legacy, valid := legacyBeside(t, approver)
			ctx, now := t.Context(), minted.Add(2*time.Minute)

			if found, err := p.Find(ctx, valid.Binding, now); err != nil || len(found) != 1 || found[0].ApprovalID != "APPROVAL2" {
				t.Fatalf("finding the other binding = %v, %v; want APPROVAL2 alone", found, err)
			}
			assertOwnApprovalRefused(t, p, legacy.Binding, now)
			if err := p.Hold(ctx, heldElsewhere(t, "APPROVAL3", "req-3"), now); err != nil {
				t.Fatalf("holding another request beside the legacy record: %v", err)
			}
			if n, err := p.Prune(ctx, now); err != nil || n != 0 {
				t.Fatalf("pruning before any expiry = %d, %v; want nothing pruned and no error", n, err)
			}
			got, err := p.Consume(ctx, valid.Binding, "req-2", "APPROVAL2", now)
			if err != nil || got.GetApproverId() != "duty-officer" {
				t.Fatalf("consuming the other binding = %v, %v", got, err)
			}
			assertNames(t, dir, answeredName, "APPROVAL2.3-consumed.rec", "APPROVAL3.0-held.rec")

			if n, err := p.Prune(ctx, expires); err != nil || n != 3 {
				t.Fatalf("pruning at the expiry = %d, %v; want all three records", n, err)
			}
			assertNames(t, dir)
		})
	}
}

// assertOwnApprovalRefused holds a lookup and a consume of the legacy
// record's own approval to the claim rule's refusal.
func assertOwnApprovalRefused(t *testing.T, p *approvals.Plane, binding approval.Binding, now time.Time) {
	t.Helper()
	for name, err := range map[string]error{
		"find":    second(p.Find(t.Context(), binding, now)),
		"consume": secondApproval(p.Consume(t.Context(), binding, "req-1", firstApproval, now)),
	} {
		if !errors.Is(err, approvals.ErrApproverID) || !errors.Is(err, approval.ErrReservedApproverID) {
			t.Errorf("%s of the legacy record = %v, want ErrApproverID and ErrReservedApproverID", name, err)
		}
	}
}

// TestOtherUnreadableRecordsStillRefuseTheWholeLookup: only the claim rule's
// refusal is confined to its own record. A reason holding a control
// character, and an approver the identifier rule refuses, still refuse a
// lookup under another binding and a prune.
func TestOtherUnreadableRecordsStillRefuseTheWholeLookup(t *testing.T) {
	for name, c := range map[string]struct {
		key, raw string
		want     error
	}{
		"a control character in the reason":  {"reason", `"a\u0001b"`, approvals.ErrReason},
		"a format character in the approver": {"approverId", `"ali\u200bce"`, approvals.ErrApproverID},
	} {
		t.Run(name, func(t *testing.T) {
			p, dir, _, valid := legacyBeside(t, "duty-officer")
			writeFile(t, dir, answeredName, withApprovalField(t, readFile(t, dir, answeredName), c.key, c.raw))
			now := minted.Add(2 * time.Minute)
			if _, err := p.Find(t.Context(), valid.Binding, now); !errors.Is(err, c.want) || errors.Is(err, approval.ErrReservedApproverID) {
				t.Errorf("finding the other binding = %v, want %v alone", err, c.want)
			}
			if _, err := p.Prune(t.Context(), expires); !errors.Is(err, c.want) {
				t.Errorf("pruning = %v, want %v", err, c.want)
			}
		})
	}
}
