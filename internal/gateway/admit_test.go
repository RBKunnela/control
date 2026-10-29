package gateway_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/pkg/contract"
)

// TestNothingParsedIsBlockedAndUnrecorded: an envelope the trail cannot be
// named from is decided by the kernel, blocked, counted, and nothing reaches
// the sink because nothing could be written about it. A refused envelope
// that still names its request gets its trail.
func TestNothingParsedIsBlockedAndUnrecorded(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads))
	for name, a := range map[string]gateway.Admission{
		"nil envelope": {Envelope: nil},
		"no project": {Envelope: func() *controlv1.ActionEnvelope {
			env := readEnvelope()
			env.ProjectId = ""
			return env
		}()},
	} {
		d := h.p.Admit(context.Background(), a)
		if d.Action != core.Block || d.Decision.GetVerdict() != verdictIndeterminate || d.AuthorizedArgs != nil {
			t.Errorf("%s: Admit = %+v; want an INDETERMINATE block with nothing to send", name, d)
		}
		if d.Decision.GetDecisionId() == "" || d.Decision.GetDecidedAt() == nil {
			t.Errorf("%s: the decision carries no id or time: %+v", name, d.Decision)
		}
	}
	if got := h.sink.askedFor(); len(got) != 0 {
		t.Errorf("the sink was asked for %v about requests with no trail", got)
	}
	d := h.p.Admit(context.Background(), gateway.Admission{Envelope: readEnvelope(), Refusal: contract.ErrMissingField})
	expectBlock(t, d, verdictIndeterminate, "REQUIRED_FIELD_ABSENT", "builtin")
	expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	total := uint64(0)
	for _, n := range h.p.Stats().Blocks {
		total += n
	}
	if total != 3 {
		t.Errorf("Stats().Blocks sums to %d, want 3", total)
	}
}

// TestAnAllowedReadRunsWithTheExactBytes: the kernel's ALLOW executes with
// the agent's bytes untouched, the trail is proposed, decided and started
// before Admit returns, and Close completes it into a chain that validates.
func TestAnAllowedReadRunsWithTheExactBytes(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads))
	args := []byte(`{ "b": 1, "a": [ ] }`)
	d := h.admit(readEnvelope(), args)
	expectExecute(t, d, args, argumentsHash(t, args))
	if d.Decision.GetPdpType() != "builtin" || !slices.Equal(d.Decision.GetReasonCodes(), []string{codeRuleAllow}) {
		t.Errorf("the decision is not the kernel's ALLOW: %+v", d.Decision)
	}
	expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindStarted})
	if err := h.p.Close(context.Background(), d, args, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close: %v", err)
	}
	events := h.events()
	expectKinds(t, kindsOf(events), []controlv1.EventKind{kindProposed, kindDecided, kindStarted, kindCompleted})
	if err := evidence.ValidateChain(events); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	expectClosedClean(t, events, d)
	expectStamped(t, events, modeEnforce, events[0].GetRunId())
	if id := events[0].GetRunId(); id == "" || id == "run-1" {
		t.Errorf("the trail names run %q; the run id is the one the pipeline minted, never the producer's", id)
	}
	if s := h.p.Stats(); s.Executed != 1 || s.Halted || len(s.Blocks) != 0 {
		t.Errorf("Stats = %+v", s)
	}
}

// expectClosedClean asserts the closing record of a trail of four names the
// digest POLICY_DECIDED recorded, no mismatch, req-1 and the execution
// ACTION_STARTED named, which is the one d carries.
func expectClosedClean(t *testing.T, events []*controlv1.Event, d gateway.Disposition) {
	t.Helper()
	closing := events[3].GetResult()
	decided := events[1].GetDecision().GetActionDigest()
	if decided == "" || closing.GetExecutedActionDigest() != decided || closing.GetToolProtocolStatus() != "" {
		t.Errorf("the closing record = %+v; want the digest POLICY_DECIDED recorded, %q, and no mismatch", closing, decided)
	}
	if closing.GetRequestId() != "req-1" || closing.GetExecutionId() == "" || closing.GetExecutionId() != d.ExecutionID ||
		events[2].GetExecutionId() != d.ExecutionID {
		t.Errorf("the closing record names request %q and execution %q; want req-1 and the started one, %q", closing.GetRequestId(), closing.GetExecutionId(), d.ExecutionID)
	}
}

// expectStamped asserts every event carries the plane's mode and the run.
func expectStamped(t *testing.T, events []*controlv1.Event, mode controlv1.EnforcementMode, runID string) {
	t.Helper()
	for _, e := range events {
		if e.GetEnforcementMode() != mode || e.GetRunId() != runID {
			t.Errorf("event %s carries mode %s and run %q", e.GetKind(), e.GetEnforcementMode(), e.GetRunId())
		}
	}
}

// expectExecute asserts a plain execution of args with digest, decided by a
// decision that carries its id and time.
func expectExecute(t *testing.T, d gateway.Disposition, args []byte, digest string) {
	t.Helper()
	if d.Action != core.Execute {
		t.Fatalf("Action = %d, want Execute; decision %+v", d.Action, d.Decision)
	}
	if !bytes.Equal(d.AuthorizedArgs, args) {
		t.Errorf("AuthorizedArgs = %q, want the exact bytes %q", d.AuthorizedArgs, args)
	}
	if d.AuthorizedDigest != digest {
		t.Errorf("AuthorizedDigest = %q, want %q", d.AuthorizedDigest, digest)
	}
	if d.Decision.GetDecisionId() == "" || d.Decision.GetDecidedAt() == nil {
		t.Errorf("the decision carries no id or time: %+v", d.Decision)
	}
}

// TestADenyIsBlockedWithTheKernelsDecision: ACTION_BLOCKED carries the
// kernel's own DENY, and the pipeline mints nothing.
func TestADenyIsBlockedWithTheKernelsDecision(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, denyWrites))
	d := h.admit(writeEnvelope(), []byte(`{}`))
	expectBlock(t, d, verdictDeny, codeRuleDeny, "builtin")
	events := h.events()
	expectKinds(t, kindsOf(events), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	if events[2].GetDecision().GetDecisionId() != events[1].GetDecision().GetDecisionId() {
		t.Errorf("ACTION_BLOCKED carries another decision than POLICY_DECIDED")
	}
	if err := evidence.ValidateChain(events); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	if h.p.Stats().Blocks[codeRuleDeny] != 1 {
		t.Errorf("Stats().Blocks = %v, want RULE_DENY once", h.p.Stats().Blocks)
	}
}

// TestObligationsRewriteTheArgumentsAndTheRestGoToTheAdapter: redact_fields
// and cap_amount produce the authorized bytes and digest; the advisory
// cap_rate travels to the adapter; the digest is of what is sent.
func TestObligationsRewriteTheArgumentsAndTheRestGoToTheAdapter(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, cappedRefunds))
	d := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
	if d.Action != core.ExecuteWithObligations {
		t.Fatalf("Action = %d, want ExecuteWithObligations; decision %+v", d.Action, d.Decision)
	}
	want := `{"amount":1000,"currency":"EUR"}`
	if string(d.AuthorizedArgs) != want {
		t.Errorf("AuthorizedArgs = %s, want %s", d.AuthorizedArgs, want)
	}
	if d.AuthorizedDigest != argumentsHash(t, []byte(want)) {
		t.Errorf("AuthorizedDigest is not the hash of the authorized bytes")
	}
	if len(d.Obligations) != 1 || d.Obligations[0].GetType() != "cap_rate" || !d.Obligations[0].GetAdvisory() {
		t.Errorf("Obligations = %v, want the advisory cap_rate alone", d.Obligations)
	}
	// The kernel's decision is recorded untouched, all three obligations on it.
	if got := len(h.events()[1].GetDecision().GetObligations()); got != 3 {
		t.Errorf("POLICY_DECIDED carries %d obligations, want the kernel's 3", got)
	}
	// Close with the authorized bytes, canonical or not, completes.
	if err := h.p.Close(context.Background(), d, []byte(`{"currency": "EUR", "amount": 1000}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Errorf("Close with the authorized document in another spelling: %v", err)
	}
}

// TestAnObligationThePlaneCannotApplyDenies: a cap on a member the arguments
// do not hold is not applied and not passed through; the block is the
// plane's own DENY.
func TestAnObligationThePlaneCannotApplyDenies(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, unappliableRefunds))
	d := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
	expectBlock(t, d, verdictDeny, codeObligationNotUnderstood, gateway.PDPType)
	events := h.events()
	expectKinds(t, kindsOf(events), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	if events[1].GetDecision().GetVerdict() != verdictObligations {
		t.Errorf("POLICY_DECIDED carries %s, want the kernel's ALLOW_WITH_OBLIGATIONS", events[1].GetDecision().GetVerdict())
	}
}

// TestLockdownBlocksAMaterialCallTheKernelAllows: both decisions are
// recorded, the kernel's ALLOW on POLICY_DECIDED and the plane's DENY on
// ACTION_BLOCKED, and a read still runs.
func TestLockdownBlocksAMaterialCallTheKernelAllows(t *testing.T) {
	h := build(t, modeLockdown, snapshot(t, allowReads, allowWrites))
	d := h.admit(writeEnvelope(), []byte(`{}`))
	expectBlock(t, d, verdictDeny, codeLockdown, gateway.PDPType)
	if d.Decision.GetEnforcementMode() != modeLockdown || d.Decision.GetDecisionId() == "" {
		t.Errorf("the plane's decision = %+v; want LOCKDOWN mode and an id", d.Decision)
	}
	events := h.events()
	expectKinds(t, kindsOf(events), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	decided, blocked := events[1].GetDecision(), events[2].GetDecision()
	if decided.GetVerdict() != verdictAllow || decided.GetPdpType() != "builtin" {
		t.Errorf("POLICY_DECIDED = %+v; want the kernel's ALLOW", decided)
	}
	if blocked.GetVerdict() != verdictDeny || blocked.GetPdpType() != gateway.PDPType || blocked.GetActionDigest() != decided.GetActionDigest() {
		t.Errorf("ACTION_BLOCKED = %+v; want the plane's DENY about the same digest", blocked)
	}
	if err := evidence.ValidateChain(events); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	if d := h.admit(readEnvelope(), []byte(`{}`)); d.Action != core.Execute {
		t.Errorf("a read under LOCKDOWN: Action = %d, want Execute", d.Action)
	}
}

// TestLockdownTurnsFailOpenReadsOff: with no bundle and FailOpenRead set, a
// read runs under ENFORCE and is blocked under LOCKDOWN.
func TestLockdownTurnsFailOpenReadsOff(t *testing.T) {
	failOpen := func(c *gateway.Config) { c.KernelOptions.FailOpenRead = true }
	open := build(t, modeEnforce, nil, failOpen).admit(readEnvelope(), []byte(`{}`))
	if open.Action != core.Execute || !slices.Contains(open.Decision.GetReasonCodes(), codeFailOpenRead) {
		t.Errorf("under ENFORCE with fail-open reads: Action = %d, codes %v", open.Action, open.Decision.GetReasonCodes())
	}
	locked := build(t, modeLockdown, nil, failOpen).admit(readEnvelope(), []byte(`{}`))
	expectBlock(t, locked, verdictIndeterminate, codePolicyUnavailable, "builtin")
}

// TestObserveRecordsADenyAndExecutes: a denied call proceeds with the
// proposed bytes, nothing the decision says is enforced, and the DENY is in
// the trail.
func TestObserveRecordsADenyAndExecutes(t *testing.T) {
	h := build(t, modeObserve, snapshot(t, denyWrites))
	args := []byte(`{"k": 1}`)
	d := h.admit(writeEnvelope(), args)
	if d.Action != core.Execute || !bytes.Equal(d.AuthorizedArgs, args) {
		t.Fatalf("under OBSERVE a denied write: Action = %d, args %q", d.Action, d.AuthorizedArgs)
	}
	if d.Decision.GetVerdict() != verdictDeny {
		t.Errorf("the recorded decision is %s, want the kernel's DENY", d.Decision.GetVerdict())
	}
	expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindStarted})
	// A rewriting obligation is not applied under OBSERVE either.
	h = build(t, modeObserve, snapshot(t, cappedRefunds))
	d = h.admit(refundEnvelope(t, refundArgs()), refundArgs())
	if d.Action != core.Execute || !bytes.Equal(d.AuthorizedArgs, refundArgs()) || d.Obligations != nil {
		t.Errorf("under OBSERVE with obligations: Action = %d, args %q, obligations %v", d.Action, d.AuthorizedArgs, d.Obligations)
	}
}

// TestApproveHoldsAnAllowedMaterialCallAndNothingElse: under APPROVE the
// kernel's ALLOW on a write waits for an approval, a DENY stays a block, an
// INDETERMINATE stays a block, and a read runs.
func TestApproveHoldsAnAllowedMaterialCallAndNothingElse(t *testing.T) {
	h := build(t, modeApprove, snapshot(t, allowReads, allowWrites))
	d := h.admit(writeEnvelope(), []byte(`{}`))
	if d.Action != core.AwaitApproval || d.Pending == nil || d.Decision.GetVerdict() != verdictAllow {
		t.Errorf("an allowed write under APPROVE: Action = %d, pending %+v, verdict %s", d.Action, d.Pending, d.Decision.GetVerdict())
	}
	expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	read := readEnvelope()
	read.RequestId = "req-read"
	if d := h.admit(read, []byte(`{}`)); d.Action != core.Execute {
		t.Errorf("a read under APPROVE: Action = %d, want Execute", d.Action)
	}
	denied := build(t, modeApprove, snapshot(t, denyWrites)).admit(writeEnvelope(), []byte(`{}`))
	expectBlock(t, denied, verdictDeny, codeRuleDeny, "builtin")
	undecided := build(t, modeApprove, nil).admit(writeEnvelope(), []byte(`{}`))
	expectBlock(t, undecided, verdictIndeterminate, codePolicyUnavailable, "builtin")
}

// TestASinkThatRefusesTheProposalBlocksBeforeAnythingRuns: the block is the
// plane's INDETERMINATE with EVIDENCE_UNAVAILABLE, no later record is
// attempted, nothing is handed to execution, and it is counted.
func TestASinkThatRefusesTheProposalBlocksBeforeAnythingRuns(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowWrites))
	h.sink.refuse[kindProposed] = true
	d := h.admit(writeEnvelope(), []byte(`{}`))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	if asked := h.sink.askedFor(); !slices.Equal(asked, []controlv1.EventKind{kindProposed}) {
		t.Errorf("the sink was asked for %v; want ACTION_PROPOSED alone, the block's own record included", asked)
	}
	s := h.p.Stats()
	if s.SinkFailuresBeforeEffect != 1 || s.Blocks[codeEvidenceUnavailable] != 1 || s.Executed != 0 {
		t.Errorf("Stats = %+v", s)
	}
}

// TestASinkThatRefusesTheStartBlocksWithNothingExecuted: the trail holds the
// proposal and the decision, the start could not be written, so nothing is
// handed out and Close has nothing to close.
func TestASinkThatRefusesTheStartBlocksWithNothingExecuted(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowWrites))
	h.sink.refuse[kindStarted] = true
	d := h.admit(writeEnvelope(), []byte(`{}`))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided})
	if err := h.p.Close(context.Background(), d, []byte(`{}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, gateway.ErrNotMinted) {
		t.Errorf("Close of a blocked disposition = %v, want ErrNotMinted", err)
	}
	if s := h.p.Stats(); s.Executed != 0 || s.SinkFailuresBeforeEffect != 1 {
		t.Errorf("Stats = %+v", s)
	}
}

// TestAReadRunsUnrecordedOnlyUnderTheRiskSetting: a sink that takes nothing
// blocks a read by default; under AllowReadsUnrecorded the read runs,
// nothing of it is recorded, Close writes nothing, and a write is still
// blocked.
func TestAReadRunsUnrecordedOnlyUnderTheRiskSetting(t *testing.T) {
	closed := build(t, modeEnforce, snapshot(t, allowReads))
	closed.sink.fail(true)
	expectBlock(t, closed.admit(readEnvelope(), []byte(`{}`)), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)

	open := build(t, modeEnforce, snapshot(t, allowReads, allowWrites), func(c *gateway.Config) { c.AllowReadsUnrecorded = true })
	open.sink.fail(true)
	d := open.admit(readEnvelope(), []byte(`{}`))
	if d.Action != core.Execute {
		t.Fatalf("a read under the risk setting: Action = %d, want Execute", d.Action)
	}
	if err := open.p.Close(context.Background(), d, []byte(`{}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Errorf("Close of an unrecorded read = %v", err)
	}
	expectBlock(t, open.admit(writeEnvelope(), []byte(`{}`)), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	if got := len(open.events()); got != 0 {
		t.Errorf("the sink kept %d event(s) while refusing everything", got)
	}
	if s := open.p.Stats(); s.ReadsUnrecorded != 1 || s.Executed != 1 || s.Blocks[codeEvidenceUnavailable] != 1 {
		t.Errorf("Stats = %+v", s)
	}
}

// TestACallWithNoArgumentsRunsAndCloses: an admission with no arguments is
// decided, executed and closed as the empty object canon digests it as, so
// nothing downstream carries nil bytes and the trail concludes.
func TestACallWithNoArgumentsRunsAndCloses(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads))
	d := h.admit(readEnvelope(), nil)
	expectExecute(t, d, []byte(`{}`), argumentsHash(t, []byte(`{}`)))
	if err := h.p.Close(context.Background(), d, d.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close of a call admitted with no arguments: %v", err)
	}
	events := h.events()
	expectKinds(t, kindsOf(events), []controlv1.EventKind{kindProposed, kindDecided, kindStarted, kindCompleted})
	if err := evidence.ValidateChain(events); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	expectClosedClean(t, events, d)
	if s := h.p.Stats(); s.Open != 0 || s.Executed != 1 || s.Mismatches != 0 || s.Halted {
		t.Errorf("Stats = %+v", s)
	}
}

// redactNames redacts two ASCII member names.
const redactNames = `{"id":"redact-names","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"redact_fields","params":{"fields":"ssn,id"}}],"when":{"action":{"name":["refund"]}}}`

// TestAMemberNameOutsideASCIIRefusesARedactedCall: while redact_fields
// applies, a top-level member name the fold does not join to a redacted one
// and an upstream may still read as one is a call the plane cannot prove
// anything about, so it is denied with OBLIGATION_NOT_UNDERSTOOD; an
// ASCII-only document is redacted as before, and a nested member is left
// alone.
func TestAMemberNameOutsideASCIIRefusesARedactedCall(t *testing.T) {
	for _, args := range []string{`{"amount":1,"ßn":"123"}`, `{"amount":1,"ıd":"7"}`, `{"amount":1,"ssn":"a","ßn":"b"}`} {
		h := build(t, modeEnforce, snapshot(t, redactNames))
		d := h.admit(refundEnvelope(t, []byte(args)), []byte(args))
		expectBlock(t, d, verdictDeny, codeObligationNotUnderstood, gateway.PDPType)
		expectKinds(t, kindsOf(h.events()), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	}
	for _, tc := range []struct{ args, want string }{
		{`{"amount":1,"ssn":"a","ID":"7"}`, `{"amount":1}`},
		{`{"amount":1,"user":{"ssn":"1"}}`, `{"amount":1,"user":{"ssn":"1"}}`},
		{`{"amount":1,"ſsn":"a"}`, `{"amount":1}`},
	} {
		h := build(t, modeEnforce, snapshot(t, redactNames))
		d := h.admit(refundEnvelope(t, []byte(tc.args)), []byte(tc.args))
		if d.Action != core.ExecuteWithObligations || string(d.AuthorizedArgs) != tc.want || len(d.Obligations) != 0 {
			t.Errorf("%s: Action = %d, sent %s, %d obligation(s) left; want the redacted document sent",
				tc.args, d.Action, d.AuthorizedArgs, len(d.Obligations))
		}
	}
}

// TestABlockTheSinkRefusesIsThePlanesOwn: a material DENY whose
// ACTION_BLOCKED the sink refuses leaves its trail open, so the answer and the
// count are the plane's EVIDENCE_UNAVAILABLE and never the kernel's code,
// which stays on POLICY_DECIDED.
func TestABlockTheSinkRefusesIsThePlanesOwn(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, denyWrites))
	h.sink.refuseKind(kindBlocked)
	d := h.admit(writeEnvelope(), []byte(`{}`))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	events := h.events()
	expectKinds(t, kindsOf(events), []controlv1.EventKind{kindProposed, kindDecided})
	if len(events) == 2 && !slices.Contains(events[1].GetDecision().GetReasonCodes(), codeRuleDeny) {
		t.Errorf("POLICY_DECIDED carries %v, want the kernel's RULE_DENY", events[1].GetDecision().GetReasonCodes())
	}
	if s := h.p.Stats(); s.Blocks[codeEvidenceUnavailable] != 1 || s.Blocks[codeRuleDeny] != 0 {
		t.Errorf("Stats().Blocks = %v; want EVIDENCE_UNAVAILABLE once and no RULE_DENY", s.Blocks)
	}
}

// TestARefusedBlockOfAReadGoesUnrecordedUnderTheRiskSetting: under
// AllowReadsUnrecorded a read's refused ACTION_BLOCKED is one more record the
// read goes on without, so the read is answered and counted with its own
// decision.
func TestARefusedBlockOfAReadGoesUnrecordedUnderTheRiskSetting(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, denyReads), func(c *gateway.Config) { c.AllowReadsUnrecorded = true })
	h.sink.refuseKind(kindBlocked)
	expectBlock(t, h.admit(readEnvelope(), []byte(`{}`)), verdictDeny, codeRuleDeny, "builtin")
	s := h.p.Stats()
	if s.Blocks[codeRuleDeny] != 1 || s.Blocks[codeEvidenceUnavailable] != 0 || s.ReadsUnrecorded != 1 {
		t.Errorf("Stats = %+v; want RULE_DENY once, no EVIDENCE_UNAVAILABLE, one read unrecorded", s)
	}
}

// denyReads refuses every read.
const denyReads = `{"id":"deny-reads","effect":"DENY","when":{"action":{"effect":["READ"]}}}`

// TestABlockAtMaxOpenTheSinkRefusesIsCountedOnce: the plane's own block at
// the bound, refused by the sink, is one block, and its request id is free
// again once the call is answered.
func TestABlockAtMaxOpenTheSinkRefusesIsCountedOnce(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowWrites), func(c *gateway.Config) { c.MaxOpen = 1 })
	first := h.admit(writeEnvelope(), []byte(`{}`))
	if first.Action != core.Execute {
		t.Fatalf("the first write: Action = %d, decision %+v", first.Action, first.Decision)
	}
	h.sink.refuseKind(kindBlocked)
	second := h.admit(requestNamed(writeEnvelope(), "req-2"), []byte(`{}`))
	expectBlock(t, second, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided})
	if s := h.p.Stats(); s.Blocks[codeEvidenceUnavailable] != 1 || len(s.Blocks) != 1 {
		t.Errorf("Stats().Blocks = %v; want EVIDENCE_UNAVAILABLE once", s.Blocks)
	}
	if err := h.p.Close(context.Background(), first, first.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if again := h.admit(requestNamed(writeEnvelope(), "req-2"), []byte(`{}`)); again.Action != core.Execute {
		t.Errorf("req-2 again: Action = %d, decision %+v; want its id free", again.Action, again.Decision)
	}
}
