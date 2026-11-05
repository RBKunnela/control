package gateway_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/gateway"
)

func ctx() context.Context { return context.Background() }

// held is a complete held request under binding for requestID, expiring ten
// minutes after base.
func held(binding approval.Binding, approvalID, requestID string) gateway.Held {
	return gateway.Held{
		Approval: &controlv1.Approval{
			ApprovalId: approvalID, RequestId: requestID, State: controlv1.ApprovalState_APPROVAL_STATE_PENDING,
			RequestedAt: timestamppb.New(base()),
			ExpiresAt:   timestamppb.New(base().Add(10 * time.Minute)),
		},
		Envelope:    readEnvelope(),
		Decision:    &controlv1.Decision{DecisionId: "d-" + approvalID, RequestId: requestID},
		Binding:     binding,
		LastEventID: "evt-3",
	}
}

// TestMemoryApprovalsApproveNothing: the zero value hands out no approval,
// under any clock, and refuses a clock that reads zero before it looks.
func TestMemoryApprovalsApproveNothing(t *testing.T) {
	var store gateway.MemoryApprovals
	binding := approval.Binding("sha256:0")
	if helds, err := store.Find(ctx(), binding, base()); helds != nil || !errors.Is(err, gateway.ErrNoApproval) {
		t.Errorf("Find = %+v, %v; want nothing, ErrNoApproval", helds, err)
	}
	if helds, err := store.Find(ctx(), binding, time.Time{}); helds != nil || !errors.Is(err, gateway.ErrZeroTime) {
		t.Errorf("Find at the zero time = %+v, %v; want nothing, ErrZeroTime", helds, err)
	}
	if err := store.Hold(ctx(), held(binding, "a-1", "req-1"), time.Time{}); !errors.Is(err, gateway.ErrZeroTime) {
		t.Errorf("Hold at the zero time = %v, want ErrZeroTime", err)
	}
	if err := store.Answer("a-1", approved, "alice", "", base()); !errors.Is(err, gateway.ErrNoApproval) {
		t.Errorf("Answer of nothing = %v, want ErrNoApproval", err)
	}
}

func TestHoldRefusesWhatCannotBeResumed(t *testing.T) {
	var store gateway.MemoryApprovals
	binding := approval.Binding("sha256:0")
	incomplete := map[string]func(*gateway.Held){
		"no approval":   func(h *gateway.Held) { h.Approval = nil },
		"no request id": func(h *gateway.Held) { h.Approval.RequestId = "" },
		"no binding":    func(h *gateway.Held) { h.Binding = "" },
		"no envelope":   func(h *gateway.Held) { h.Envelope = nil },
		"no decision":   func(h *gateway.Held) { h.Decision = nil },
		// The directory store refuses both at read, and a store that took
		// them would judge the answer's window against the Unix epoch.
		"no requested time": func(h *gateway.Held) { h.Approval.RequestedAt = nil },
		"no expiry":         func(h *gateway.Held) { h.Approval.ExpiresAt = nil },
		// A hold is the pending approval the plane mints. One that carries an
		// answer is a grant the holder made itself, which a resume would spend.
		"no approval id": func(h *gateway.Held) { h.Approval.ApprovalId = "" },
		"an approved state": func(h *gateway.Held) {
			h.Approval.State = controlv1.ApprovalState_APPROVAL_STATE_APPROVED
		},
		"an approver id":  func(h *gateway.Held) { h.Approval.ApproverId = "alice" },
		"a decision time": func(h *gateway.Held) { h.Approval.DecidedAt = timestamppb.New(base()) },
		"a self-grant": func(h *gateway.Held) {
			h.Approval.State = controlv1.ApprovalState_APPROVAL_STATE_APPROVED
			h.Approval.ApproverId = "alice"
			h.Approval.DecidedAt = timestamppb.New(base())
		},
	}
	for name, mut := range incomplete {
		h := held(binding, "a-1", "req-1")
		mut(&h)
		if err := store.Hold(ctx(), h, base()); !errors.Is(err, gateway.ErrInvalidHold) {
			t.Errorf("Hold with %s = %v, want ErrInvalidHold", name, err)
		}
	}
	if err := store.Hold(ctx(), held(binding, "a-1", "req-1"), base()); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if err := store.Hold(ctx(), held(binding, "a-2", "req-1"), base()); !errors.Is(err, gateway.ErrAlreadyHeld) {
		t.Errorf("a second hold of one request id under one binding = %v, want ErrAlreadyHeld", err)
	}
	if err := store.Hold(ctx(), held(binding, "a-2", "req-2"), base()); err != nil {
		t.Errorf("a second request under the same binding: %v", err)
	}
	helds, err := store.Find(ctx(), binding, base())
	if err != nil || len(helds) != 2 || helds[0].Approval.GetRequestId() != "req-1" || helds[1].Approval.GetRequestId() != "req-2" {
		t.Errorf("Find = %d held, %v; want req-1 then req-2", len(helds), err)
	}
	// Clones both ways: the caller's later write and the store's copy differ.
	helds[0].Approval.RequestId = "rewritten"
	if again, _ := store.Find(ctx(), binding, base()); again[0].Approval.GetRequestId() != "req-1" {
		t.Errorf("Find handed out the stored record rather than a clone")
	}
}

// mustHold and mustAnswer fail the test on a refusal of what it set up.
func mustHold(t *testing.T, store *gateway.MemoryApprovals, h gateway.Held) {
	t.Helper()
	if err := store.Hold(ctx(), h, base()); err != nil {
		t.Fatalf("Hold: %v", err)
	}
}

func mustAnswer(t *testing.T, store *gateway.MemoryApprovals, approvalID string) {
	t.Helper()
	if err := store.Answer(approvalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
}

// answerOf is what Find hands back for approvalID under binding at now, or
// nil.
func answerOf(t *testing.T, store *gateway.MemoryApprovals, binding approval.Binding, approvalID string, now time.Time) *controlv1.Approval {
	t.Helper()
	helds, err := store.Find(ctx(), binding, now)
	if err != nil && !errors.Is(err, gateway.ErrNoApproval) {
		t.Fatalf("Find: %v", err)
	}
	for _, h := range helds {
		if h.Approval.GetApprovalId() == approvalID {
			return h.Approval
		}
	}
	return nil
}

// TestAnswerDecidesAPendingRecordOnce: an answer is APPROVED with an approver
// or REJECTED, once, and Find hands the answer back as the record now stands;
// a hold that arrives answered already is refused, so no grant the holder
// made itself is ever there to be read.
func TestAnswerDecidesAPendingRecordOnce(t *testing.T) {
	binding := approval.Binding("sha256:0")
	var store gateway.MemoryApprovals
	mustHold(t, &store, held(binding, "a-1", "req-1"))
	if err := store.Answer("a-1", approved, "", "", base()); !errors.Is(err, gateway.ErrApprovalAnswer) {
		t.Errorf("Answer APPROVED with no approver = %v, want ErrApprovalAnswer", err)
	}
	if err := store.Answer("a-1", controlv1.ApprovalState_APPROVAL_STATE_EXPIRED, "alice", "", base()); !errors.Is(err, gateway.ErrApprovalAnswer) {
		t.Errorf("Answer EXPIRED = %v, want ErrApprovalAnswer", err)
	}
	if a := answerOf(t, &store, binding, "a-1", base()); a.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Errorf("after two refused answers the record reads %v, want pending", a)
	}
	mustAnswer(t, &store, "a-1")
	if err := store.Answer("a-1", rejected, "", "", base()); !errors.Is(err, gateway.ErrApprovalAnswered) {
		t.Errorf("a second answer = %v, want ErrApprovalAnswered", err)
	}
	if a := answerOf(t, &store, binding, "a-1", base()); a.GetState() != approved || a.GetApproverId() != "alice" || !a.GetDecidedAt().AsTime().Equal(base()) {
		t.Errorf("Find after the answer = %v, want approved by alice at base", a)
	}
	for _, tc := range []struct{ id, approver string }{{"a-7", ""}, {"a-8", "alice"}} {
		h := held(binding, tc.id, "req-"+tc.id)
		h.Approval.State, h.Approval.ApproverId, h.Approval.DecidedAt = approved, tc.approver, timestamppb.New(base())
		if err := store.Hold(ctx(), h, base()); !errors.Is(err, gateway.ErrInvalidHold) {
			t.Errorf("Hold approved by %q = %v, want ErrInvalidHold", tc.approver, err)
		}
		if a := answerOf(t, &store, binding, tc.id, base()); a != nil {
			t.Errorf("a refused self-grant is in the store: %v", a)
		}
	}
}

// TestHoldAndFindDropExpiredRecords: a record whose approval expired, pending
// or answered, is gone from Find at its expiry and not a nanosecond before,
// and Hold sweeps every binding, so a store nobody retries against does not
// grow.
func TestHoldAndFindDropExpiredRecords(t *testing.T) {
	var store gateway.MemoryApprovals
	first, second := approval.Binding("sha256:1"), approval.Binding("sha256:2")
	mustHold(t, &store, held(first, "a-1", "req-1"))
	mustHold(t, &store, held(first, "a-2", "req-2"))
	mustAnswer(t, &store, "a-2")
	expiry := base().Add(10 * time.Minute)
	if helds, err := store.Find(ctx(), first, expiry.Add(-time.Nanosecond)); err != nil || len(helds) != 2 {
		t.Errorf("Find before the expiry = %d held, %v; want both, the answered one included", len(helds), err)
	}
	if helds, err := store.Find(ctx(), first, expiry); helds != nil || !errors.Is(err, gateway.ErrNoApproval) {
		t.Errorf("Find at the expiry = %+v, %v; want nothing", helds, err)
	}

	mustHold(t, &store, held(first, "a-3", "req-3"))
	later := held(second, "a-4", "req-4")
	later.Approval.ExpiresAt = timestamppb.New(expiry.Add(time.Hour))
	if err := store.Hold(ctx(), later, expiry); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	// The record under the other binding went at that Hold, before any Find
	// of its binding: still there, a Find at an earlier reading would see it.
	if a := answerOf(t, &store, first, "a-3", base()); a != nil {
		t.Errorf("the expired record under the other binding is still kept: %v", a)
	}
	if helds, err := store.Find(ctx(), second, expiry); err != nil || len(helds) != 1 {
		t.Errorf("Find of the live record = %d held, %v", len(helds), err)
	}
}

// TestMemoryApprovalsRefuseAClaimOfTheReservedPrefix: an answer whose
// approver reads as the reserved prefix is refused, approving or rejecting,
// and leaves the approval pending, so a plain name can still answer it.
func TestMemoryApprovalsRefuseAClaimOfTheReservedPrefix(t *testing.T) {
	binding := approval.Binding("sha256:0")
	var store gateway.MemoryApprovals
	mustHold(t, &store, held(binding, "a-1", "req-1"))
	for _, id := range []string{"authn:okta:alice", "AUTHN:okta:alice", "\ua4ee\ua4f4\ua4d4\ua4e7\ua4e0:okta:alice"} {
		for _, state := range []controlv1.ApprovalState{approved, rejected} {
			err := store.Answer("a-1", state, id, "", base())
			if !errors.Is(err, gateway.ErrApprovalAnswer) || !errors.Is(err, approval.ErrReservedApproverID) {
				t.Errorf("%s by %+q = %v, want ErrApprovalAnswer and ErrReservedApproverID", state, id, err)
			}
		}
	}
	if a := answerOf(t, &store, binding, "a-1", base()); a.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Errorf("after the refused answers the record reads %v, want pending", a)
	}
	mustAnswer(t, &store, "a-1")
	if a := answerOf(t, &store, binding, "a-1", base()); a.GetApproverId() != "alice" {
		t.Errorf("a plain name's answer reads %v", a)
	}
}
