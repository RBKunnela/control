package gateway_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

var errStore = errors.New("store: unavailable")

// fakeStore is a memory store whose answers a test can break: an error from
// Hold, Find or Release, or a rewrite of what Find hands out.
type fakeStore struct {
	*gateway.MemoryApprovals
	holdErr, findErr error
	releaseErr       error
	found            func(*controlv1.Approval)
	listed           func([]gateway.Held) []gateway.Held
}

func newFakeStore() *fakeStore { return &fakeStore{MemoryApprovals: &gateway.MemoryApprovals{}} }

func (f *fakeStore) Hold(ctx context.Context, h gateway.Held, now time.Time) error {
	if f.holdErr != nil {
		return f.holdErr
	}
	return f.MemoryApprovals.Hold(ctx, h, now)
}

func (f *fakeStore) Find(ctx context.Context, b approval.Binding, now time.Time) ([]gateway.Held, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	helds, err := f.MemoryApprovals.Find(ctx, b, now)
	if f.found != nil {
		for _, held := range helds {
			f.found(held.Approval)
		}
	}
	if f.listed != nil {
		helds = f.listed(helds)
	}
	return helds, err
}

func (f *fakeStore) Release(ctx context.Context, b approval.Binding, requestID, approvalID string) error {
	if f.releaseErr != nil {
		return f.releaseErr
	}
	return f.MemoryApprovals.Release(ctx, b, requestID, approvalID)
}

// lieAbout makes f hand out every record through lie, and leave out one lie
// answers nil for.
func lieAbout(f *fakeStore, lie func(*controlv1.Approval) *controlv1.Approval) {
	f.listed = func(helds []gateway.Held) []gateway.Held {
		var out []gateway.Held
		for _, h := range helds {
			if h.Approval = lie(h.Approval); h.Approval != nil {
				out = append(out, h)
			}
		}
		return out
	}
}

// withStore builds a harness over approveRefunds whose store is f.
func withStore(t *testing.T, f *fakeStore) *harness {
	t.Helper()
	return build(t, modeEnforce, snapshot(t, approveRefunds), func(c *gateway.Config) { c.Approvals = f })
}

// holdApproved holds the first refund in f and approves it.
func holdApproved(t *testing.T, h *harness, f *fakeStore) {
	t.Helper()
	first := hold(t, h)
	if err := f.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
}

// What a retry over a lying store comes to.
const (
	// closesExpired closes the held trail with the plane's own approval,
	// expired, and the case's verdict and code.
	closesExpired = iota
	// closesRejected closes the held trail on the rejection it read.
	closesRejected
	// waits tells the agent the held request still awaits its approval.
	waits
	// refusesOwn blocks the retry on a trail of its own and leaves the hold.
	refusesOwn
	// holdsAnew holds the retry as a request of its own.
	holdsAnew
)

// TestThePipelineNeverTrustsTheStoresApproval: a store that hands out a
// record that is not the held approval, approved, unexpired and single-use
// never runs the call. An answer the checks refuse closes the window with the
// plane's own approval, expired; one that is no answer yet leaves the hold
// waiting; a record of a state no build names, or the record of another
// request, is not the hold's. Nothing is spent in the ledger unless the call
// runs, and the genuine record runs.
func TestThePipelineNeverTrustsTheStoresApproval(t *testing.T) {
	cases := []struct {
		name    string
		lie     func(*controlv1.Approval) *controlv1.Approval
		outcome int
		verdict controlv1.Verdict
		code    string
	}{
		{"no record", func(*controlv1.Approval) *controlv1.Approval { return nil }, holdsAnew, 0, ""},
		{"still pending", func(a *controlv1.Approval) *controlv1.Approval {
			a.State = controlv1.ApprovalState_APPROVAL_STATE_PENDING
			return a
		}, waits, 0, ""},
		{"pending, undecided", func(a *controlv1.Approval) *controlv1.Approval {
			a.State, a.DecidedAt = controlv1.ApprovalState_APPROVAL_STATE_PENDING, nil
			return a
		}, waits, 0, ""},
		{"expired, undecided", func(a *controlv1.Approval) *controlv1.Approval {
			a.State, a.DecidedAt = controlv1.ApprovalState_APPROVAL_STATE_EXPIRED, nil
			return a
		}, waits, 0, ""},
		{"rejected", func(a *controlv1.Approval) *controlv1.Approval {
			a.State = controlv1.ApprovalState_APPROVAL_STATE_REJECTED
			return a
		}, closesRejected, verdictDeny, codeApprovalRejected},
		{"no state", func(a *controlv1.Approval) *controlv1.Approval { a.State = 0; return a }, refusesOwn, verdictIndeterminate, codeEvidenceUnavailable},
		{"a state of no name", func(a *controlv1.Approval) *controlv1.Approval { a.State = 99; return a }, refusesOwn, verdictIndeterminate, codeEvidenceUnavailable},
		{"no approver", func(a *controlv1.Approval) *controlv1.Approval { a.ApproverId = ""; return a }, waits, 0, ""},
		{"requested a year earlier", func(a *controlv1.Approval) *controlv1.Approval {
			a.RequestedAt = timestamppb.New(a.GetRequestedAt().AsTime().AddDate(-1, 0, 0))
			return a
		}, closesExpired, verdictIndeterminate, codeEvidenceUnavailable},
		{"requested a nanosecond later", func(a *controlv1.Approval) *controlv1.Approval {
			a.RequestedAt = timestamppb.New(a.GetRequestedAt().AsTime().Add(time.Nanosecond))
			return a
		}, waits, 0, ""},
		{"no request time", func(a *controlv1.Approval) *controlv1.Approval { a.RequestedAt = nil; return a }, closesExpired, verdictIndeterminate, codeEvidenceUnavailable},
		{"another approval", func(a *controlv1.Approval) *controlv1.Approval { a.ApprovalId = "a-other"; return a }, waits, 0, ""},
		{"another request", func(a *controlv1.Approval) *controlv1.Approval { a.RequestId = "req-other"; return a }, holdsAnew, 0, ""},
		{"multi-use", func(a *controlv1.Approval) *controlv1.Approval { a.MultiUse = true; return a }, waits, 0, ""},
		{"another major", func(a *controlv1.Approval) *controlv1.Approval { a.SchemaVersion = "9.0"; return a }, closesExpired, verdictIndeterminate, codeEvidenceUnavailable},
		{"decided later", func(a *controlv1.Approval) *controlv1.Approval {
			a.DecidedAt = timestamppb.New(base().Add(time.Hour))
			return a
		}, waits, 0, ""},
		{"another digest", func(a *controlv1.Approval) *controlv1.Approval { a.ActionDigest = "sha256:" + digits; return a }, closesExpired, verdictDeny, codeApprovalDigestMismatch},
		{"another bundle", func(a *controlv1.Approval) *controlv1.Approval { a.PolicyBundleDigest = "sha256:" + digits; return a }, closesExpired, verdictDeny, codeApprovalBundleMismatch},
		{"expiring now", func(a *controlv1.Approval) *controlv1.Approval { a.ExpiresAt = timestamppb.New(base()); return a }, closesExpired, verdictDeny, codeApprovalExpired},
		{"no expiry", func(a *controlv1.Approval) *controlv1.Approval { a.ExpiresAt = nil; return a }, closesExpired, verdictDeny, codeApprovalExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeStore()
			ledger := &fakeLedger{}
			h := build(t, modeEnforce, snapshot(t, approveRefunds), overStore(f), overLedger(ledger))
			first := hold(t, h)
			if err := f.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
				t.Fatalf("Answer: %v", err)
			}
			lieAbout(f, tc.lie)
			d := h.admit(retry(t, "req-2"), refundArgs())
			expectLiedTo(t, h, d, first, tc.outcome, tc.verdict, tc.code)
			if spends, _ := ledger.asked(); spends != 0 {
				t.Errorf("the plane spent %d approval(s) on a record it refused", spends)
			}
			if s := h.p.Stats(); s.Executed != 0 || s.Open != 0 {
				t.Errorf("Stats = %+v", s)
			}
		})
	}
	f := newFakeStore()
	h := withStore(t, f)
	holdApproved(t, h, f)
	lieAbout(f, func(a *controlv1.Approval) *controlv1.Approval { return a })
	if d := h.admit(retry(t, "req-2"), refundArgs()); d.Action != core.Execute {
		t.Errorf("the genuine approval: Action = %d, decision %+v", d.Action, d.Decision)
	}
}

// expectHeldTrailClosed asserts the retry closed the held trail with verdict
// and code: on the rejection it read, or with the plane's own approval,
// expired.
func expectHeldTrailClosed(t *testing.T, d gateway.Disposition, trail []*controlv1.Event, rejected bool, verdict controlv1.Verdict, code string) {
	t.Helper()
	expectBlock(t, d, verdict, code, gateway.PDPType)
	if d.Decision.GetRequestId() != "req-1" {
		t.Errorf("the block names request %q, want the held req-1", d.Decision.GetRequestId())
	}
	closing := kindApprovalExpired
	if rejected {
		closing = kindApprovalDecided
	}
	expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, closing, kindBlocked})
	if err := evidence.ValidateChain(trail); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	if len(trail) == 5 && !rejected {
		expectPlanesApprovalExpired(t, trail[2].GetApproval(), trail[3].GetApproval())
	}
}

// expectLiedTo asserts what a retry over a lying store came to.
func expectLiedTo(t *testing.T, h *harness, d gateway.Disposition, first gateway.Disposition, outcome int, verdict controlv1.Verdict, code string) {
	t.Helper()
	trail := h.trailOf("req-1")
	switch outcome {
	case closesExpired, closesRejected:
		expectHeldTrailClosed(t, d, trail, outcome == closesRejected, verdict, code)
		return
	case waits:
		if d.Action != core.AwaitApproval || pendingID(d) != first.Pending.ApprovalID {
			t.Errorf("Action = %d, pending %+v; want the hold still waiting", d.Action, d.Pending)
		}
	case refusesOwn:
		expectBlock(t, d, verdict, code, gateway.PDPType)
		expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	case holdsAnew:
		if d.Action != core.AwaitApproval || d.Pending == nil || d.Pending.ApprovalID == first.Pending.ApprovalID {
			t.Errorf("Action = %d, pending %+v; want a hold of its own", d.Action, d.Pending)
		}
	}
	expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
}

// expectPlanesApprovalExpired fails unless closed is the approval the plane
// minted, own, as it held it for req-1, now expired.
func expectPlanesApprovalExpired(t *testing.T, own, closed *controlv1.Approval) {
	t.Helper()
	if closed.GetApprovalId() != own.GetApprovalId() || closed.GetRequestId() != "req-1" || closed.GetSchemaVersion() != "1.0" ||
		!closed.GetRequestedAt().AsTime().Equal(base()) || closed.GetApproverId() != "" ||
		closed.GetDecidedAt() != nil || closed.GetState() != controlv1.ApprovalState_APPROVAL_STATE_EXPIRED {
		t.Errorf("the window closed with %v, want the plane's own approval, expired", closed)
	}
}

const digits = "0000000000000000000000000000000000000000000000000000000000000000"

// TestAStoreThatCannotAnswerBlocksWithEveryRecordWritten: a Find, or a spend
// the ledger cannot write, blocks the call on a whole trail of its own, and a
// Hold that fails closes the window it opened; every trail validates and
// nothing is held but what was.
func TestAStoreThatCannotAnswerBlocksWithEveryRecordWritten(t *testing.T) {
	t.Run("find", func(t *testing.T) {
		f := newFakeStore()
		f.findErr = errStore
		h := withStore(t, f)
		d := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
		expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
		expectValidHeld(t, h, "req-1", 0)
	})
	t.Run("hold", func(t *testing.T) {
		f := newFakeStore()
		f.holdErr = errStore
		h := withStore(t, f)
		d := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
		expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
		if got := h.events()[3].GetApproval().GetState(); got != controlv1.ApprovalState_APPROVAL_STATE_EXPIRED {
			t.Errorf("APPROVAL_EXPIRED carries state %s", got)
		}
		expectValidHeld(t, h, "req-1", 0)
	})
	t.Run("spend", func(t *testing.T) {
		f := newFakeStore()
		ledger := &fakeLedger{spendErr: errLedger}
		h := build(t, modeEnforce, snapshot(t, approveRefunds), overStore(f), overLedger(ledger))
		holdApproved(t, h, f)
		d := h.admit(retry(t, "req-2"), refundArgs())
		expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
		expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
		expectValidHeld(t, h, "req-2", 1)
	})
}

func expectValidHeld(t *testing.T, h *harness, requestID string, held int) {
	t.Helper()
	if err := evidenceOf(h, requestID); err != nil {
		t.Errorf("ValidateChain over %s: %v", requestID, err)
	}
	if s := h.p.Stats(); s.Held != held || s.Executed != 0 {
		t.Errorf("Stats = %+v; want %d held and nothing executed", s, held)
	}
}

// TestHoldsPastTheBoundAreRefused: with MaxHeld requests held, the next one
// closes the window it opened and blocks; one held request expiring makes
// room.
func TestHoldsPastTheBoundAreRefused(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveRefunds), func(c *gateway.Config) { c.MaxHeld = 1 })
	hold(t, h)
	other := retry(t, "req-2")
	other.Context.SessionId = "sess-2"
	d := h.admit(other, refundArgs())
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
	if err := evidenceOf(h, "req-2"); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	if s := h.p.Stats(); s.Held != 1 {
		t.Errorf("Stats().Held = %d, want 1", s.Held)
	}
	h.clock.set(base().Add(10 * time.Minute))
	third := retry(t, "req-3")
	third.Context.SessionId = "sess-3"
	if d := h.admit(third, refundArgs()); d.Action != core.AwaitApproval {
		t.Errorf("after the first hold expired: Action = %d, want a hold", d.Action)
	}
}

// approveReads asks for an approval on every read.
const approveReads = `{"id":"approve-reads","effect":"REQUIRE_APPROVAL","when":{"action":{"effect":["READ"]}}}`

// TestAnUnrecordedCallIsNeverHeld: under the risk setting a read the sink
// refuses runs unrecorded, but one that would wait for an approval is
// blocked instead, because its retry would resume a trail nobody wrote.
func TestAnUnrecordedCallIsNeverHeld(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveReads), func(c *gateway.Config) { c.AllowReadsUnrecorded = true })
	h.sink.fail(true)
	d := h.admit(readEnvelope(), []byte(`{}`))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	if s := h.p.Stats(); s.Held != 0 || s.Pending != 0 {
		t.Errorf("Stats = %+v", s)
	}
	h.sink.fail(false)
	if d := h.admit(readEnvelope(), []byte(`{}`)); d.Action != core.AwaitApproval {
		t.Errorf("the same read with a sink: Action = %d, want a hold", d.Action)
	}
}

// taintedRefunds asks for an approval of a refund in a run that took in
// restricted data, beside approveRefunds: the digest and the binding are the
// same whatever the run took in, the rules that decide are not.
const taintedRefunds = `{"id":"approve-tainted-refunds","effect":"REQUIRE_APPROVAL","obligations":[{"type":"cap_amount","params":{"max":"1000"}}],"when":{"action":{"name":["refund"]},"flow":{"toxicAtLeast":"RESTRICTED"}}}`

// taintRun executes a read, as requestID, whose result the operator did not
// declare trusted and declared restricted, and closes it: from then on the
// run of the refunds is one that took in restricted data under untrusted
// influence.
func taintRun(t *testing.T, h *harness, requestID string) {
	t.Helper()
	env := readEnvelope()
	env.RequestId = requestID
	a := admission(env, []byte(`{}`))
	a.ResultSensitivity = controlv1.Sensitivity_SENSITIVITY_RESTRICTED
	d := h.p.Admit(context.Background(), a)
	if d.Action != core.Execute {
		t.Fatalf("the read that taints the run: Action = %d, decision %+v", d.Action, d.Decision)
	}
	if err := h.p.Close(context.Background(), d, d.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// tainted is a retry of the first refund once the run is tainted: the same
// envelope, so the same binding, and another decision.
func tainted(t *testing.T, requestID string) gateway.Admission {
	t.Helper()
	return admission(retry(t, requestID), refundArgs())
}

// TestARetryDecidedOtherwiseIsHeldAnew: the retry's decision names another
// rule than the held one, which the held trail cannot record, so the retry is
// a request of its own, held with its own approval on its own trail, and the
// approval of the first hold is left for a retry the kernel decides as it did.
func TestARetryDecidedOtherwiseIsHeldAnew(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveRefunds, taintedRefunds, allowReads))
	first := hold(t, h)
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	taintRun(t, h, "read-1")
	d := h.p.Admit(context.Background(), tainted(t, "req-2"))
	if d.Action != core.AwaitApproval || d.Pending == nil || d.Pending.ApprovalID == first.Pending.ApprovalID {
		t.Fatalf("a retry decided otherwise: Action = %d, pending %+v; want a hold of its own", d.Action, d.Pending)
	}
	if d.Pending.ActionDigest != first.Pending.ActionDigest {
		t.Errorf("the new hold is about another action digest; the flow is not in the digest")
	}
	trail := h.trailOf("req-2")
	expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if err := evidence.ValidateChain(trail); err != nil {
		t.Errorf("ValidateChain over the new hold: %v", err)
	}
	held := h.trailOf("req-1")[1].GetDecision()
	if fresh := trail[1].GetDecision(); fresh.GetActionDigest() != held.GetActionDigest() || slices.Equal(fresh.GetPolicyRuleIds(), held.GetPolicyRuleIds()) {
		t.Errorf("the new hold records %v about %s; the held trail %v about %s", fresh.GetPolicyRuleIds(), fresh.GetActionDigest(), held.GetPolicyRuleIds(), held.GetActionDigest())
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	// The run stays tainted, so every later retry is decided as req-2 was and
	// never spends the approval given for the first hold.
	if again := h.admit(retry(t, "req-3"), refundArgs()); pendingID(again) != d.Pending.ApprovalID {
		t.Errorf("a retry in the tainted run: Action = %d, pending %+v; want the tainted hold", again.Action, again.Pending)
	}
}

// TestAResumeTakesTheApprovedOneOfSeveralHolds: two requests end up held under
// one binding, the second because the run was tainted in between and the
// kernel decided it otherwise; a retry is told about the hold its own decision
// matches, the approved one is the one consumed, and every trail is one chain.
func TestAResumeTakesTheApprovedOneOfSeveralHolds(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveRefunds, taintedRefunds, allowReads))
	first := hold(t, h)
	taintRun(t, h, "read-1")
	second := h.p.Admit(context.Background(), tainted(t, "req-2"))
	if second.Action != core.AwaitApproval || second.Pending == nil || second.Pending.ApprovalID == first.Pending.ApprovalID {
		t.Fatalf("the second hold: Action = %d, pending %+v", second.Action, second.Pending)
	}
	if s := h.p.Stats(); s.Held != 2 {
		t.Fatalf("Stats().Held = %d, want both holds", s.Held)
	}
	if d := h.p.Admit(context.Background(), tainted(t, "req-3")); pendingID(d) != second.Pending.ApprovalID {
		t.Errorf("a tainted retry with neither answered is told about %+v; want the tainted hold", d.Pending)
	}
	if err := h.store.Answer(second.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	run := h.p.Admit(context.Background(), tainted(t, "req-5"))
	if run.Action != core.Execute {
		t.Fatalf("with the tainted hold approved: Action = %d, decision %+v", run.Action, run.Decision)
	}
	if err := h.p.Close(context.Background(), run, run.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close: %v", err)
	}
	expectOneHoldConsumed(t, h)
}

// expectOneHoldConsumed asserts the tainted hold ran on its own trail, the
// first hold is the prefix it was, and no retry wrote a trail of its own.
func expectOneHoldConsumed(t *testing.T, h *harness) {
	t.Helper()
	expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted, kindCompleted})
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	for _, id := range []string{"req-1", "req-2"} {
		if err := evidenceOf(h, id); err != nil {
			t.Errorf("ValidateChain over %s: %v", id, err)
		}
	}
	if got := len(h.events()) - len(h.trailOf("req-1")) - len(h.trailOf("req-2")) - len(h.trailOf("read-1")); got != 0 {
		t.Errorf("%d event(s) outside the two held trails and the read; a retry that resumes one writes no trail of its own", got)
	}
	if s := h.p.Stats(); s.Held != 1 || s.Executed != 2 || s.Pending != 3 {
		t.Errorf("Stats = %+v; want the first hold still held, the read and the resume executed", s)
	}
}

// TestARejectionCarriesTheRecordTheStoreRead: what APPROVAL_DECIDED records
// is the rejection the store handed back, not the pending copy the plane
// minted.
func TestARejectionCarriesTheRecordTheStoreRead(t *testing.T) {
	f := newFakeStore()
	h := withStore(t, f)
	first := hold(t, h)
	if err := f.Answer(first.Pending.ApprovalID, rejected, "bob", "not today", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	d := h.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictDeny, codeApprovalRejected, gateway.PDPType)
	trail := h.trailOf("req-1")
	expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindBlocked})
	if a := trail[3].GetApproval(); a.GetState() != rejected || a.GetApproverId() != "bob" || a.GetReason() != "not today" {
		t.Errorf("APPROVAL_DECIDED carries %+v; want the rejection the store read", a)
	}
}

// TestAnExpiryTheStoreReportsClosesTheHeldTrail: a store that hands back the
// approval expired at this reading has the held trail closed with
// APPROVAL_EXPIRED and the plane's DENY about the held request.
func TestAnExpiryTheStoreReportsClosesTheHeldTrail(t *testing.T) {
	f := newFakeStore()
	h := withStore(t, f)
	holdApproved(t, h, f)
	f.found = func(a *controlv1.Approval) { a.ExpiresAt = timestamppb.New(base()) }
	d := h.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictDeny, codeApprovalExpired, gateway.PDPType)
	trail := h.trailOf("req-1")
	expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
	if err := evidence.ValidateChain(trail); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	if trail[3].GetApproval().GetState() != controlv1.ApprovalState_APPROVAL_STATE_EXPIRED || trail[4].GetDecision().GetRequestId() != "req-1" {
		t.Errorf("APPROVAL_EXPIRED carries %+v and ACTION_BLOCKED names %q", trail[3].GetApproval(), trail[4].GetDecision().GetRequestId())
	}
}

// lyingStore rewrites the approval of every record it hands out. With frozen
// set it answers as at that reading, so it keeps a record the plane minted to
// expire.
type lyingStore struct {
	*gateway.MemoryApprovals
	lie    func(*controlv1.Approval)
	frozen time.Time
}

func (l *lyingStore) at(now time.Time) time.Time {
	if l.frozen.IsZero() {
		return now
	}
	return l.frozen
}

func (l *lyingStore) Find(ctx context.Context, b approval.Binding, now time.Time) ([]gateway.Held, error) {
	helds, err := l.MemoryApprovals.Find(ctx, b, l.at(now))
	for i := range helds {
		l.lie(helds[i].Approval)
	}
	return helds, err
}

// TestAStoreThatLiesTheSameWayTwiceIsStillRefused: a store that rewrites the
// action digest and the bundle of every record it hands out is checked against
// the pipeline's own record of the hold and this call's own decision, so
// nothing runs and the held trail is closed.
func TestAStoreThatLiesTheSameWayTwiceIsStillRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		lie  func(*controlv1.Approval)
		code string
	}{
		"another digest in every record": {func(a *controlv1.Approval) { a.ActionDigest = "sha256:" + digits }, codeApprovalDigestMismatch},
		"another bundle in every record": {func(a *controlv1.Approval) { a.PolicyBundleDigest = "sha256:" + digits }, codeApprovalBundleMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			l := &lyingStore{MemoryApprovals: &gateway.MemoryApprovals{}, lie: tc.lie}
			h := build(t, modeEnforce, snapshot(t, approveRefunds), func(c *gateway.Config) { c.Approvals = l })
			first := hold(t, h)
			if err := l.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
				t.Fatalf("Answer: %v", err)
			}
			d := h.admit(retry(t, "req-2"), refundArgs())
			expectBlock(t, d, verdictDeny, tc.code, gateway.PDPType)
			expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
			if err := evidenceOf(h, "req-1"); err != nil {
				t.Errorf("ValidateChain: %v", err)
			}
			if s := h.p.Stats(); s.Executed != 0 || s.Open != 0 || s.Held != 0 {
				t.Errorf("Stats = %+v", s)
			}
		})
	}
}

// TestAStoreThatStretchesTheExpiryIsRefused: an approval that outlives the
// window the plane minted is not the record it minted, and past that window the
// plane holds no such request at all, whatever the store still answers.
func TestAStoreThatStretchesTheExpiryIsRefused(t *testing.T) {
	stretch := func(a *controlv1.Approval) { a.ExpiresAt = timestamppb.New(base().Add(24 * time.Hour)) }

	inside := &lyingStore{MemoryApprovals: &gateway.MemoryApprovals{}, lie: stretch}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), func(c *gateway.Config) { c.Approvals = inside })
	first := hold(t, h)
	if err := inside.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	d := h.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})

	// Past the window the plane minted, the plane holds no such request, so the
	// retry is a request of its own and the hold's trail is closed as expired,
	// however alive the store still says its record is.
	after := &lyingStore{MemoryApprovals: &gateway.MemoryApprovals{}, lie: stretch, frozen: base()}
	h = build(t, modeEnforce, snapshot(t, approveRefunds), func(c *gateway.Config) {
		c.Approvals = after
		c.ApprovalTTL = time.Minute
	})
	first = hold(t, h)
	if err := after.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	h.clock.set(base().Add(2 * time.Minute))
	d = h.admit(retry(t, "req-2"), refundArgs())
	if d.Action != core.AwaitApproval || d.Pending == nil || d.Pending.ApprovalID == first.Pending.ApprovalID {
		t.Fatalf("past the minted expiry: Action = %d, pending %+v; want a hold of its own", d.Action, d.Pending)
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
	if err := evidenceOf(h, "req-1"); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	if s := h.p.Stats(); s.Executed != 0 {
		t.Errorf("Stats = %+v; want nothing executed on an approval the plane minted to expire", s)
	}
}

// forgedStore files every hold under an approval id the plane never minted,
// which is what a writer of an approvals directory can do to a record that
// carries the binding and request id of a live hold.
type forgedStore struct {
	*gateway.MemoryApprovals
	forged  string
	binding approval.Binding
}

func (f *forgedStore) Hold(ctx context.Context, h gateway.Held, now time.Time) error {
	f.binding = h.Binding
	h.Approval = proto.CloneOf(h.Approval)
	h.Approval.ApprovalId = f.forged
	return f.MemoryApprovals.Hold(ctx, h, now)
}

// TestARecordUnderAnotherApprovalIdIsNeverSpent: the store keeps a record
// under the binding and request id of a live hold, carrying an approval id the
// plane never minted, and an approver answers that record. The plane judges
// only the record of the approval it minted, so nothing is spent and nothing
// runs, and the record is left for a reconciliation to settle (ADR-0016).
func TestARecordUnderAnotherApprovalIdIsNeverSpent(t *testing.T) {
	f := &forgedStore{MemoryApprovals: &gateway.MemoryApprovals{}, forged: "apr-forged"}
	ledger := &fakeLedger{}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), overStore(f), overLedger(ledger))
	first := hold(t, h)
	if first.Pending.ApprovalID == f.forged {
		t.Fatalf("the plane minted %q, which the store forged", f.forged)
	}
	if err := f.Answer(f.forged, approved, "mallory", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}

	d := h.admit(retry(t, "req-2"), refundArgs())
	if d.Action == core.Execute {
		t.Fatalf("a record the plane never minted ran the call: %+v", d.Decision)
	}
	if d.Action != core.AwaitApproval || pendingID(d) != first.Pending.ApprovalID {
		t.Errorf("Action = %d, pending %+v; want the call still awaiting the approval the plane minted", d.Action, d.Pending)
	}
	if spends, _ := ledger.asked(); spends != 0 {
		t.Errorf("the plane spent %d approval(s); a record it never minted is never spent", spends)
	}
	if marks, err := ledger.Lookup(context.Background(), f.binding, base()); err != nil || len(marks) != 0 {
		t.Errorf("the ledger holds %v, %v; want nothing", marks, err)
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if s := h.p.Stats(); s.Executed != 0 || s.Held != 1 {
		t.Errorf("Stats = %+v; want the hold still held and nothing executed", s)
	}
}

// TestALedgerThatSpendsOneApprovalTwiceRunsItOnce: the flip from held to
// running is the pipeline's, so even a ledger that answers a second spend as
// a first cannot have the held trail written twice; the second retry is
// refused on its own trail.
func TestALedgerThatSpendsOneApprovalTwiceRunsItOnce(t *testing.T) {
	f := newFakeStore()
	ledger := &forgetfulLedger{}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), overStore(f), overLedger(ledger))
	holdApproved(t, h, f)
	inner := false
	ledger.beforeSpend = func() {
		if inner {
			return
		}
		inner = true
		// The held request runs, and its trail stops being held, while the
		// outer retry is between the lookup and its own spend.
		if d := h.admit(retry(t, "req-inner"), refundArgs()); d.Action != core.Execute {
			t.Errorf("the inner retry: Action = %d, decision %+v", d.Action, d.Decision)
		}
	}
	d := h.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted})
	expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	if err := evidenceOf(h, "req-1"); err != nil {
		t.Errorf("ValidateChain over the resumed trail: %v", err)
	}
	if s := h.p.Stats(); s.Executed != 1 {
		t.Errorf("Stats = %+v; want the one execution the approval was for", s)
	}
}

// forgetfulLedger answers every spend as the first, which no ledger may do;
// it runs beforeSpend first.
type forgetfulLedger struct {
	gateway.MemoryLedger
	beforeSpend func()
}

func (l *forgetfulLedger) Spend(_ context.Context, _ approval.Binding, _, _, _ string, _ time.Time) (gateway.Resolution, error) {
	if l.beforeSpend != nil {
		l.beforeSpend()
	}
	return gateway.ResolutionConsumed, nil
}

// TestSixteenRetriesOfOneApprovedHoldRunItOnce: sixteen retries of one
// approved hold race for it, and the ledger's compare-and-swap and the
// pipeline's take of the hold let exactly one run.
func TestSixteenRetriesOfOneApprovedHoldRunItOnce(t *testing.T) {
	f := newFakeStore()
	h := withStore(t, f)
	holdApproved(t, h, f)
	var wg sync.WaitGroup
	runs := make([]gateway.Disposition, 16)
	for i := range runs {
		wg.Go(func() { runs[i] = h.admit(retry(t, "req-r"+strconv.Itoa(i)), refundArgs()) })
	}
	wg.Wait()
	executed := 0
	for _, d := range runs {
		if d.Action == core.Execute {
			executed++
		}
	}
	if s := h.p.Stats(); executed != 1 || s.Executed != 1 {
		t.Fatalf("%d of 16 retries ran, Stats().Executed = %d; want one", executed, s.Executed)
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted})
}

// TestAStoreThatRewritesTheHeldEnvelopeResumesNothing: what the retry is
// compared with is the envelope the pipeline holds, so a store that hands out
// an envelope matching a call the approval was not given for resumes nothing
// and that call is held on its own.
func TestAStoreThatRewritesTheHeldEnvelopeResumesNothing(t *testing.T) {
	l := &envelopeStore{MemoryApprovals: &gateway.MemoryApprovals{}}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), func(c *gateway.Config) { c.Approvals = l })
	first := hold(t, h)
	if err := l.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	other := retry(t, "req-2")
	other.Context.SessionId = "sess-2"
	l.session = "sess-2"
	d := h.admit(other, refundArgs())
	if d.Action != core.AwaitApproval || d.Pending == nil || d.Pending.ApprovalID == first.Pending.ApprovalID {
		t.Fatalf("a retry the store dressed as the held request: Action = %d, pending %+v; want a hold of its own", d.Action, d.Pending)
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if s := h.p.Stats(); s.Executed != 0 {
		t.Errorf("Stats = %+v; want nothing executed on an approval given for another run context", s)
	}
}

// envelopeStore rewrites the run context of every held envelope it hands out.
type envelopeStore struct {
	*gateway.MemoryApprovals
	session string
}

func (e *envelopeStore) Find(ctx context.Context, b approval.Binding, now time.Time) ([]gateway.Held, error) {
	helds, err := e.MemoryApprovals.Find(ctx, b, now)
	for i := range helds {
		if e.session != "" {
			helds[i].Envelope.Context.SessionId = e.session
		}
	}
	return helds, err
}

// anyBindingStore answers every lookup with the records it holds under the
// first binding it was given, whatever binding was asked for.
type anyBindingStore struct {
	*gateway.MemoryApprovals
	first approval.Binding
}

func (s *anyBindingStore) Hold(ctx context.Context, held gateway.Held, now time.Time) error {
	if s.first == "" {
		s.first = held.Binding
	}
	return s.MemoryApprovals.Hold(ctx, held, now)
}

func (s *anyBindingStore) Find(ctx context.Context, _ approval.Binding, now time.Time) ([]gateway.Held, error) {
	return s.MemoryApprovals.Find(ctx, s.first, now)
}

// TestAHoldIsResumedOnlyUnderTheBindingItWasHeldFor: the bundle changes between
// the hold and the retry, so the same call has another binding; a store that
// hands out the hold anyway resumes nothing, because the pipeline's own record
// says which binding it was held under.
func TestAHoldIsResumedOnlyUnderTheBindingItWasHeldFor(t *testing.T) {
	s := &anyBindingStore{MemoryApprovals: &gateway.MemoryApprovals{}}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), func(c *gateway.Config) { c.Approvals = s })
	first := hold(t, h)
	if err := s.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	h.policy.snap = snapshot(t, approveRefunds, allowReads)
	d := h.admit(retry(t, "req-2"), refundArgs())
	if d.Action != core.AwaitApproval || d.Pending == nil || d.Pending.ApprovalID == first.Pending.ApprovalID {
		t.Fatalf("under another bundle: Action = %d, pending %+v; want a hold of its own", d.Action, d.Pending)
	}
	if d.Pending.ActionDigest != first.Pending.ActionDigest {
		t.Errorf("the two calls have different action digests, so this test says nothing about the binding")
	}
	expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if s := h.p.Stats(); s.Executed != 0 || s.Held != 2 {
		t.Errorf("Stats = %+v; want both requests held and nothing executed", s)
	}
}

// TestTwoRecordsOfTheMintedApprovalAreNoAnswer: a store that hands back two
// records under the approval the plane minted disagrees with itself, so the
// retry is blocked on its own trail, nothing is spent and the hold stands;
// either record alone runs.
func TestTwoRecordsOfTheMintedApprovalAreNoAnswer(t *testing.T) {
	f := newFakeStore()
	ledger := &fakeLedger{}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), overStore(f), overLedger(ledger))
	holdApproved(t, h, f)
	f.listed = func(helds []gateway.Held) []gateway.Held {
		if len(helds) == 0 {
			return helds
		}
		twin := helds[0]
		twin.Approval = proto.CloneOf(twin.Approval)
		return append(helds, twin)
	}
	expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if spends, _ := ledger.asked(); spends != 0 {
		t.Errorf("the plane spent %d approval(s) on a store that disagrees with itself", spends)
	}
	f.listed = nil
	if d := h.admit(retry(t, "req-3"), refundArgs()); d.Action != core.Execute {
		t.Errorf("the record alone: Action = %d, decision %+v; want it run", d.Action, d.Decision)
	}
}
