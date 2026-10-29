package main

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/gateway"
)

// holdingDocument needs an approval for a transfer, so the same call is held
// under `ENFORCE` whichever provider keeps the record. `APPROVE` would not
// serve here: it is refused with the memory provider, and a case that could
// not run both rows would compare nothing.
const holdingDocument = `{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"gateway-fixture","version":"2026-09-20.3","serial":3,"maxStaleSeconds":600},
  "rules":[
    {"id":"approve-transfers","effect":"REQUIRE_APPROVAL","when":{"action":{"effect":["TRANSACT"]}}}
  ]}`

// transferArgs is what every call here proposes.
var transferArgs = []byte("{}")

// argumentsHash is the hash of the proposed bytes that the contract makes a
// material call carry. A refusal here is the fixture's own, not the plane's.
func argumentsHash(t *testing.T) string {
	t.Helper()
	hash, err := canon.ArgumentsHashV1(transferArgs)
	if err != nil {
		t.Fatalf("ArgumentsHashV1: %v", err)
	}
	return hash
}

// provider is one approval store as the configuration reaches it, and the way
// an approver answers a record it keeps. Everything else in these cases is
// one code path, so a row that decides differently is a divergence between
// two implementations of one interface and not between two tests.
type provider struct {
	name      string
	configure func(t *testing.T, tr tree)
	answer    func(t *testing.T, tr tree, p *plane, approvalID string)
}

func providers() []provider {
	return []provider{
		{
			name:      "memory",
			configure: func(*testing.T, tree) {},
			answer: func(t *testing.T, _ tree, p *plane, approvalID string) {
				t.Helper()
				store, ok := p.store.(*gateway.MemoryApprovals)
				if !ok {
					t.Fatalf("the memory provider built a %T", p.store)
				}
				err := store.Answer(approvalID, controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
					"approver-1", "ok", time.Now())
				if err != nil {
					t.Fatalf("answering %s: %v", approvalID, err)
				}
			},
		},
		{
			name: "file",
			configure: func(t *testing.T, tr tree) {
				t.Helper()
				tr.fileProvider(t)
			},
			answer: func(t *testing.T, tr tree, _ *plane, approvalID string) {
				t.Helper()
				// The plane holds the directory while this runs, which is
				// what an approver answering a live plane sees.
				answerFrom(t, filepath.Join(tr.dir, recordsDir), approvalID, true)
			},
		},
	}
}

// TestTheProvidersDecideAHeldCallAlike drives one scenario through both
// approval stores at the wiring, where both are reachable: they implement one
// interface, and a divergence in `Find`, `Consume` or `Resolve` fails here.
func TestTheProvidersDecideAHeldCallAlike(t *testing.T) {
	for _, p := range providers() {
		t.Run(p.name, func(t *testing.T) {
			t.Run("an approval is consumed once", func(t *testing.T) { expectConsumedOnce(t, p) })
			t.Run("an expired approval resumes nothing", func(t *testing.T) { expectExpiredResumesNothing(t, p) })
			t.Run("a record this plane never held resumes nothing", func(t *testing.T) { expectUnheldRecordHoldsAnew(t, p) })
		})
	}
}

// expectConsumedOnce: the call is held, an approver answers, the retry runs
// exactly once, and the next identical call reads APPROVAL_ALREADY_USED.
func expectConsumedOnce(t *testing.T, provider provider) {
	t.Helper()
	tr, plane := holdingPlane(t, provider, 15*time.Minute)

	held := admitTransfer(t, plane, "req-hold-1")
	if held.Action != core.AwaitApproval {
		t.Fatalf("the first call is %v, want a hold: %v", held.Action, held.Decision.GetReasonCodes())
	}
	provider.answer(t, tr, plane, held.Pending.ApprovalID)

	resumed := admitTransfer(t, plane, "req-hold-2")
	if resumed.Action != core.Execute {
		t.Fatalf("the approved retry is %v, want an execution: %v", resumed.Action, resumed.Decision.GetReasonCodes())
	}
	closeExecution(t, plane, resumed)

	spent := admitTransfer(t, plane, "req-hold-3")
	if spent.Action != core.Block {
		t.Fatalf("the call after the approved one is %v, want a block", spent.Action)
	}
	if codes := spent.Decision.GetReasonCodes(); !slices.Contains(codes, "APPROVAL_ALREADY_USED") {
		t.Errorf("the block says %v, want APPROVAL_ALREADY_USED among them", codes)
	}
	if s := plane.pipeline.Stats(); s.Executed != 1 {
		t.Errorf("%d execution(s); one approval is consumed once", s.Executed)
	}
}

// expectExpiredResumesNothing: an answer that arrives is worth nothing once
// the approval the plane minted has expired. The retry is held anew, and
// nothing runs.
func expectExpiredResumesNothing(t *testing.T, provider provider) {
	t.Helper()
	tr, plane := holdingPlane(t, provider, 3*time.Second)

	held := admitTransfer(t, plane, "req-expire-1")
	if held.Action != core.AwaitApproval {
		t.Fatalf("the first call is %v, want a hold", held.Action)
	}
	provider.answer(t, tr, plane, held.Pending.ApprovalID)
	time.Sleep(time.Until(held.Pending.ExpiresAt) + 50*time.Millisecond)

	retry := admitTransfer(t, plane, "req-expire-2")
	if retry.Action == core.Execute {
		t.Fatalf("a retry ran on an approval that expired at %s", held.Pending.ExpiresAt)
	}
	if s := plane.pipeline.Stats(); s.Executed != 0 {
		t.Errorf("%d execution(s) on an expired approval", s.Executed)
	}
}

// expectUnheldRecordHoldsAnew: a record the store keeps for a request this
// plane never held proves nothing about an execution, so the call is held
// anew and counted rather than told that an action ran.
func expectUnheldRecordHoldsAnew(t *testing.T, provider provider) {
	t.Helper()
	_, plane := holdingPlane(t, provider, 15*time.Minute)
	ctx := context.Background()

	// The record goes in through the seam itself, so both stores are given
	// the same thing to keep, and it is bound to the bundle this plane
	// serves: a record under any other binding is one the plane never asks
	// about, and this case would then prove nothing.
	envelope := transferEnvelope(t, "req-nobody-held")
	bundle := approval.BundleDigest(plane.holder.Current().Ref().GetDigest())
	digest, binding, err := approval.Bind(envelope, transferArgs, bundle)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	now := time.Now()
	stored := gateway.Held{
		Approval: &controlv1.Approval{
			SchemaVersion: "1.0", ApprovalId: "apr-nobody-held", RequestId: "req-nobody-held",
			ActionDigest: string(digest), PolicyBundleDigest: string(bundle),
			State:       controlv1.ApprovalState_APPROVAL_STATE_PENDING,
			RequestedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(15 * time.Minute)),
		},
		Binding: binding, Envelope: envelope,
		Decision: &controlv1.Decision{RequestId: "req-nobody-held"},
	}
	if err := plane.store.Hold(ctx, stored, now); err != nil {
		t.Fatalf("holding a record this plane does not hold: %v", err)
	}

	call := admitTransfer(t, plane, "req-unheld-1")
	if call.Action != core.AwaitApproval {
		t.Fatalf("the call is %v, want a hold of its own: %v", call.Action, call.Decision.GetReasonCodes())
	}
	if s := plane.pipeline.Stats(); s.UnheldRecords != 1 || s.Executed != 0 {
		t.Errorf("%d unheld record(s) counted and %d execution(s), want 1 and 0", s.UnheldRecords, s.Executed)
	}
}

// holdingPlane is a plane whose policy needs an approval for a transfer, over
// the store the provider names.
func holdingPlane(t *testing.T, provider provider, ttl time.Duration) (tree, *plane) {
	t.Helper()
	tr := newTree(t)
	provider.configure(t, tr)
	writeBundle(t, filepath.Join(tr.dir, "holding.bundle"), holdingDocument)
	setEnv(t, "policy.bundle_file", filepath.Join(tr.dir, "holding.bundle"))
	writeStatement(t, filepath.Join(tr.dir, "policy.statement"), filepath.Join(tr.dir, "holding.bundle"), time.Now().Truncate(time.Second))
	setEnv(t, "mode", "ENFORCE")
	setEnv(t, "approvals.ttl", ttl.String())
	return tr, tr.plane(t)
}

// admitTransfer admits the same transfer again under a fresh request id: the
// digest leaves the id and the timestamps out, so every call here is the same
// request under one binding.
func admitTransfer(t *testing.T, p *plane, requestID string) gateway.Disposition {
	t.Helper()
	return p.pipeline.Admit(context.Background(), gateway.Admission{
		Envelope: transferEnvelope(t, requestID), Arguments: transferArgs,
	})
}

// closeExecution closes the trail of a call that ran, with the bytes the
// plane authorized.
func closeExecution(t *testing.T, p *plane, d gateway.Disposition) {
	t.Helper()
	err := p.pipeline.Close(context.Background(), d, d.AuthorizedArgs,
		&controlv1.ActionResult{Status: controlv1.ResultStatus_RESULT_STATUS_SUCCESS})
	if err != nil {
		t.Fatalf("closing the execution: %v", err)
	}
}

// transferEnvelope is one material call. Only the request id changes between
// calls, which is a field the action digest leaves out.
func transferEnvelope(t *testing.T, requestID string) *controlv1.ActionEnvelope {
	t.Helper()
	return &controlv1.ActionEnvelope{
		SchemaVersion: "1.0",
		RequestId:     requestID,
		ProjectId:     "orders",
		TenantId:      "acme",
		Environment:   "dev",
		OccurredAt:    timestamppb.New(time.Date(2026, time.September, 20, 9, 0, 0, 0, time.UTC)),
		Principal:     &controlv1.Principal{Id: "agent-runner", Type: "service", TenantId: "acme"},
		Agent:         &controlv1.Agent{Id: "orders-assistant"},
		Action:        &controlv1.Action{Kind: channel.KindTool, Name: "orders.transfer", Effect: controlv1.EffectClass_EFFECT_CLASS_TRANSACT, Provider: "orders", Protocol: channel.ProtocolMCP},
		Resource:      &controlv1.Resource{Type: "account", Id: "acct-1", TenantId: "acme", Environment: "dev"},
		Arguments:     &controlv1.Arguments{CanonicalHash: argumentsHash(t)},
		Context:       &controlv1.RunContext{RunId: "run-1"},
	}
}

// TestTheStoreTakesTheConfiguredApprovalWindow holds a call under a lifetime
// longer than the store's own default window. The record the plane writes
// stands that far from its request, so a store left on its default would
// refuse the plane its own hold: the call succeeding is what proves the
// configured lifetime reached the store.
func TestTheStoreTakesTheConfiguredApprovalWindow(t *testing.T) {
	beyond := approvals.DefaultMaxApprovalWindow + time.Hour
	_, p := holdingPlane(t, providers()[1], beyond)

	if d := admitTransfer(t, p, "req-long-window"); d.Action != core.AwaitApproval {
		t.Fatalf("a hold under a %s lifetime is %v, want the call held: the store refused the record the plane minted", beyond, d.Action)
	}
}
