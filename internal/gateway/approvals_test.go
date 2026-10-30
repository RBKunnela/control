package gateway_test

import (
	"context"
	"errors"
	"sync"
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
			ExpiresAt: timestamppb.New(base().Add(10 * time.Minute)),
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
	if a, err := store.Consume(ctx(), binding, "req-1", "a-1", time.Time{}); a != nil || !errors.Is(err, gateway.ErrZeroTime) {
		t.Errorf("Consume at the zero time = %v, %v; want nil, ErrZeroTime", a, err)
	}
	if a, err := store.Consume(ctx(), binding, "req-1", "a-1", base()); a != nil || !errors.Is(err, gateway.ErrNoApproval) {
		t.Errorf("Consume = %v, %v; want nil, ErrNoApproval", a, err)
	}
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

// expectConsume asserts what Consume answers for requestID, spent by the
// approval id approvalID, at now.
func expectConsume(t *testing.T, store *gateway.MemoryApprovals, binding approval.Binding, requestID, approvalID string, now time.Time, want error) {
	t.Helper()
	a, err := store.Consume(ctx(), binding, requestID, approvalID, now)
	if !errors.Is(err, want) || (want == nil) != (a != nil) {
		t.Errorf("Consume(%s as %s at %v) = %+v, %v; want %v", requestID, approvalID, now.Sub(base()), a, err, want)
	}
}

// TestConsumeInEveryState walks Consume through what a record can be: held
// and pending, answered, consumed, expired, rejected, multi-use, and asked
// for under another request id.
func TestConsumeInEveryState(t *testing.T) {
	binding := approval.Binding("sha256:0")
	t.Run("pending, answered, consumed", func(t *testing.T) {
		var store gateway.MemoryApprovals
		mustHold(t, &store, held(binding, "a-1", "req-1"))
		expectConsume(t, &store, binding, "req-1", "a-1", base(), gateway.ErrNoApproval)
		expectConsume(t, &store, binding, "req-other", "a-1", base(), gateway.ErrNoApproval)
		if err := store.Answer("a-1", approved, "", "", base()); !errors.Is(err, gateway.ErrApprovalAnswer) {
			t.Errorf("Answer APPROVED with no approver = %v, want ErrApprovalAnswer", err)
		}
		if err := store.Answer("a-1", controlv1.ApprovalState_APPROVAL_STATE_EXPIRED, "alice", "", base()); !errors.Is(err, gateway.ErrApprovalAnswer) {
			t.Errorf("Answer EXPIRED = %v, want ErrApprovalAnswer", err)
		}
		mustAnswer(t, &store, "a-1")
		if err := store.Answer("a-1", rejected, "", "", base()); !errors.Is(err, gateway.ErrApprovalAnswered) {
			t.Errorf("a second answer = %v, want ErrApprovalAnswered", err)
		}
		a, err := store.Consume(ctx(), binding, "req-1", "a-1", base())
		if err != nil || a.GetState() != approved || a.GetApproverId() != "alice" {
			t.Fatalf("Consume of an approved approval = %+v, %v", a, err)
		}
		expectConsume(t, &store, binding, "req-1", "a-1", base(), gateway.ErrApprovalConsumed)
		// Consumed stays consumed past the expiry too.
		expectConsume(t, &store, binding, "req-1", "a-1", base().Add(time.Hour), gateway.ErrApprovalConsumed)
	})
	t.Run("expiry at the clock handed in", func(t *testing.T) {
		var store gateway.MemoryApprovals
		mustHold(t, &store, held(binding, "a-2", "req-2"))
		mustAnswer(t, &store, "a-2")
		expectConsume(t, &store, binding, "req-2", "a-2", base().Add(10*time.Minute-time.Nanosecond), nil)
		mustHold(t, &store, held(binding, "a-3", "req-3"))
		expectConsume(t, &store, binding, "req-3", "a-3", base().Add(10*time.Minute), gateway.ErrApprovalExpired)
		// The expired record is dropped.
		expectConsume(t, &store, binding, "req-3", "a-3", base(), gateway.ErrNoApproval)
		noExpiry := held(binding, "a-4", "req-4")
		noExpiry.Approval.ExpiresAt = nil
		mustHold(t, &store, noExpiry)
		expectConsume(t, &store, binding, "req-4", "a-4", base(), gateway.ErrApprovalExpired)
	})
	t.Run("rejected", func(t *testing.T) {
		var store gateway.MemoryApprovals
		mustHold(t, &store, held(binding, "a-5", "req-5"))
		if err := store.Answer("a-5", rejected, "", "no", base()); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		// The refusal comes with the record it read, for the trail to carry.
		a, err := store.Consume(ctx(), binding, "req-5", "a-5", base())
		if !errors.Is(err, gateway.ErrApprovalRejected) || a.GetState() != rejected || a.GetReason() != "no" || a.GetApprovalId() != "a-5" {
			t.Errorf("Consume of a rejected approval = %+v, %v; want the rejected record and ErrApprovalRejected", a, err)
		}
		expectConsume(t, &store, binding, "req-5", "a-5", base(), gateway.ErrNoApproval)
	})
	t.Run("multi-use", func(t *testing.T) {
		var store gateway.MemoryApprovals
		multi := held(binding, "a-6", "req-6")
		multi.Approval.MultiUse = true
		mustHold(t, &store, multi)
		mustAnswer(t, &store, "a-6")
		expectConsume(t, &store, binding, "req-6", "a-6", base(), gateway.ErrMultiUse)
	})
}

// TestConsumeSpendsNoApprovalWithoutAnApprover: a record held already
// approved, which Hold accepts in any state, is spent only when it names who
// approved it.
func TestConsumeSpendsNoApprovalWithoutAnApprover(t *testing.T) {
	binding := approval.Binding("sha256:0")
	var store gateway.MemoryApprovals
	for _, tc := range []struct {
		id, approver string
		want         error
	}{{"a-7", "", gateway.ErrNoApproval}, {"a-8", "alice", nil}} {
		h := held(binding, tc.id, "req-"+tc.id)
		h.Approval.State, h.Approval.ApproverId, h.Approval.DecidedAt = approved, tc.approver, timestamppb.New(base())
		mustHold(t, &store, h)
		expectConsume(t, &store, binding, "req-"+tc.id, tc.id, base(), tc.want)
	}
}

// TestConsumeSpendsNoAnswerOutsideItsWindow: an approval answered before it
// was requested, at the zero time or after the clock handed in is not spent,
// and stays where it was for a reading that can spend it.
func TestConsumeSpendsNoAnswerOutsideItsWindow(t *testing.T) {
	binding := approval.Binding("sha256:0")
	var store gateway.MemoryApprovals
	for _, tc := range []struct {
		approvalID, requestID string
		decided               time.Time
	}{
		{"a-7", "req-7", base().Add(-time.Nanosecond)},
		{"a-8", "req-8", time.Time{}},
		{"a-9", "req-9", base().Add(time.Nanosecond)},
	} {
		h := held(binding, tc.approvalID, tc.requestID)
		h.Approval.RequestedAt = timestamppb.New(base())
		mustHold(t, &store, h)
		if err := store.Answer(tc.approvalID, approved, "alice", "", tc.decided); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		expectConsume(t, &store, binding, tc.requestID, tc.approvalID, base(), gateway.ErrNoApproval)
	}
	// Nothing was spent: the answer decided after the first reading is
	// spent at a reading after it.
	expectConsume(t, &store, binding, "req-9", "a-9", base().Add(time.Nanosecond), nil)
	helds, err := store.Find(ctx(), binding, base())
	if err != nil || len(helds) != 3 {
		t.Fatalf("Find = %d record(s), %v; want the three held", len(helds), err)
	}
	for _, h := range helds {
		if id := h.Approval.GetApprovalId(); id != "a-9" && h.Resolution != gateway.ResolutionPending {
			t.Errorf("the record of %s was refused and stands %d, want pending", id, h.Resolution)
		}
	}
}

// TestConsumeSpendsOnlyTheApprovalTheCallerMinted: a record kept under the
// right binding and request id, carrying an approval id the caller never
// minted, is not the caller's to spend. It is refused and left where it was,
// so the approval the caller does hold still spends it, once.
func TestConsumeSpendsOnlyTheApprovalTheCallerMinted(t *testing.T) {
	var store gateway.MemoryApprovals
	binding := approval.Binding("sha256:7")
	mustHold(t, &store, held(binding, "a-1", "req-1"))
	mustAnswer(t, &store, "a-1")

	expectConsume(t, &store, binding, "req-1", "a-other", base(), gateway.ErrNoApproval)
	expectResolution(t, &store, binding, gateway.ResolutionPending)

	expectConsume(t, &store, binding, "req-1", "a-1", base(), nil)
	expectResolution(t, &store, binding, gateway.ResolutionConsumed)
	// A spent record still answers nothing to a caller holding another id.
	expectConsume(t, &store, binding, "req-1", "a-other", base(), gateway.ErrNoApproval)
}

// TestAnEmptyApprovalIdMatchesNoRecord: asking for no approval at all is a
// refusal, not a record that will do, even where the record carries no
// approval id of its own.
func TestAnEmptyApprovalIdMatchesNoRecord(t *testing.T) {
	var store gateway.MemoryApprovals
	binding := approval.Binding("sha256:8")
	mustHold(t, &store, held(binding, "", "req-1"))
	if err := store.Answer("", approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	expectConsume(t, &store, binding, "req-1", "", base(), gateway.ErrNoApproval)
	expectResolution(t, &store, binding, gateway.ResolutionPending)
}

// TestHoldAndFindDropExpiredRecords: a record whose approval expired, pending
// or consumed, is gone from Find at its expiry and not a nanosecond before,
// and Hold sweeps every binding, so a store nobody retries against does not
// grow; a consumed record is kept until then.
func TestHoldAndFindDropExpiredRecords(t *testing.T) {
	var store gateway.MemoryApprovals
	first, second := approval.Binding("sha256:1"), approval.Binding("sha256:2")
	mustHold(t, &store, held(first, "a-1", "req-1"))
	mustHold(t, &store, held(first, "a-2", "req-2"))
	mustAnswer(t, &store, "a-2")
	expectConsume(t, &store, first, "req-2", "a-2", base(), nil)
	expiry := base().Add(10 * time.Minute)
	if helds, err := store.Find(ctx(), first, expiry.Add(-time.Nanosecond)); err != nil || len(helds) != 2 {
		t.Errorf("Find before the expiry = %d held, %v; want both, the consumed one included", len(helds), err)
	}
	expectConsume(t, &store, first, "req-2", "a-2", base(), gateway.ErrApprovalConsumed)
	if helds, err := store.Find(ctx(), first, expiry); helds != nil || !errors.Is(err, gateway.ErrNoApproval) {
		t.Errorf("Find at the expiry = %+v, %v; want nothing", helds, err)
	}
	expectConsume(t, &store, first, "req-1", "a-1", base(), gateway.ErrNoApproval)
	expectConsume(t, &store, first, "req-2", "a-2", base(), gateway.ErrNoApproval)

	mustHold(t, &store, held(first, "a-3", "req-3"))
	later := held(second, "a-4", "req-4")
	later.Approval.ExpiresAt = timestamppb.New(expiry.Add(time.Hour))
	if err := store.Hold(ctx(), later, expiry); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	// The record under the other binding went at that Hold, before any Find:
	// still there, it would be reported expired.
	expectConsume(t, &store, first, "req-3", "a-3", expiry, gateway.ErrNoApproval)
	if helds, err := store.Find(ctx(), second, expiry); err != nil || len(helds) != 1 {
		t.Errorf("Find of the live record = %d held, %v", len(helds), err)
	}
}

// TestConsumeIsOneCompareAndSwap: many concurrent consumers of one approved
// record, and exactly one gets it.
func TestConsumeIsOneCompareAndSwap(t *testing.T) {
	var store gateway.MemoryApprovals
	binding := approval.Binding("sha256:0")
	if err := store.Hold(ctx(), held(binding, "a-1", "req-1"), base()); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if err := store.Answer("a-1", approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	var wg sync.WaitGroup
	var won, lost sync.Map
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Consume(ctx(), binding, "req-1", "a-1", base())
			switch {
			case err == nil:
				won.Store(i, true)
			case errors.Is(err, gateway.ErrApprovalConsumed):
				lost.Store(i, true)
			default:
				t.Errorf("Consume = %v", err)
			}
		}()
	}
	wg.Wait()
	winners, losers := 0, 0
	won.Range(func(any, any) bool { winners++; return true })
	lost.Range(func(any, any) bool { losers++; return true })
	if winners != 1 || losers != 31 {
		t.Errorf("%d consumers won and %d lost; want 1 and 31", winners, losers)
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
	expectConsume(t, &store, binding, "req-1", "a-1", base(), gateway.ErrNoApproval)
	mustAnswer(t, &store, "a-1")
	expectConsume(t, &store, binding, "req-1", "a-1", base(), nil)
}
