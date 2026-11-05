package gateway_test

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/reaction"
)

// planeCase is a set of the plane's own causes to block a call, each raised
// the way a running plane raises it.
type planeCase struct {
	paused, stopped, mismatch, lockdown, unknown, stopUnknown, sink, unclassified bool
}

// haltOnMismatch runs a read and closes it with other bytes.
func haltOnMismatch(t *testing.T, h *harness) {
	t.Helper()
	d := h.admit(requestNamed(tool(readEnvelope()), "halt-mismatch"), []byte(`{"q":1}`))
	if err := h.p.Close(context.Background(), d, []byte(`{"q":2}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
		t.Fatalf("the halting close = %v", err)
	}
}

// haltOnSink runs a read whose closing record the sink refuses.
func haltOnSink(t *testing.T, h *harness) {
	t.Helper()
	d := h.admit(requestNamed(tool(readEnvelope()), "halt-sink"), []byte(`{}`))
	h.sink.refuseKind(kindCompleted)
	if err := h.p.Close(context.Background(), d, []byte(`{}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, errSink) {
		t.Fatalf("the halting close = %v", err)
	}
}

// admitUnder builds a plane over rules that serves opened runs under a stop
// list, raises the causes of c in an order that leaves every one standing,
// and admits one material call of run-a as req-x.
func (c planeCase) admitUnder(t *testing.T, rules []string, mut ...func(*gateway.Config)) (*harness, gateway.Disposition) {
	t.Helper()
	mode := modeEnforce
	if c.lockdown {
		mode = modeLockdown
	}
	stops := newStopSource(stopped(t))
	h := stopPlane(t, mode, rules, stops, mut...)
	if c.mismatch {
		haltOnMismatch(t, h)
	}
	if c.sink {
		haltOnSink(t, h)
	}
	switch {
	case c.paused:
		h.pause.set(paused(t, pauseGlobal))
	case c.unknown:
		h.pause.set(pause.Snapshot{})
	}
	switch {
	case c.stopped:
		stops.set(stopped(t, "run-a"))
	case c.stopUnknown:
		stops.set(reaction.Snapshot{})
	}
	a := admission(requestNamed(tool(writeEnvelope()), "req-x"), []byte(`{"k":1}`))
	if c.unclassified {
		a = unclassified([]byte(`{"k":1}`))
		a.Envelope.RequestId = "req-x"
	}
	a.Run = h.run
	return h, h.p.Admit(context.Background(), a)
}

// planeCases is every cause alone and every pair that can stand at once: a
// pause state is paused or unknown, never both, and so is a stop state. The
// codes and verdicts are written out, in the order the decision has to list
// them.
var planeCases = []struct {
	name    string
	c       planeCase
	verdict controlv1.Verdict
	codes   []string
}{
	{"P", planeCase{paused: true}, verdictDeny, []string{codePaused}},
	{"S", planeCase{stopped: true}, verdictDeny, []string{codeRunStopped}},
	{"M", planeCase{mismatch: true}, verdictDeny, []string{codeExecutedArgsMismatch}},
	{"L", planeCase{lockdown: true}, verdictDeny, []string{codeLockdown}},
	{"U", planeCase{unknown: true}, verdictIndeterminate, []string{codePauseStateUnavailable}},
	{"K", planeCase{stopUnknown: true}, verdictIndeterminate, []string{codeStopStateUnavailable}},
	{"E", planeCase{sink: true}, verdictIndeterminate, []string{codeEvidenceUnavailable}},
	{"C", planeCase{unclassified: true}, verdictIndeterminate, []string{codeActionUnclassified}},
	{"PS", planeCase{paused: true, stopped: true}, verdictDeny, []string{codePaused, codeRunStopped}},
	{"PM", planeCase{paused: true, mismatch: true}, verdictDeny, []string{codePaused, codeExecutedArgsMismatch}},
	{"PL", planeCase{paused: true, lockdown: true}, verdictDeny, []string{codePaused, codeLockdown}},
	{"PK", planeCase{paused: true, stopUnknown: true}, verdictDeny, []string{codePaused, codeStopStateUnavailable}},
	{"PE", planeCase{paused: true, sink: true}, verdictDeny, []string{codePaused, codeEvidenceUnavailable}},
	{"PC", planeCase{paused: true, unclassified: true}, verdictDeny, []string{codePaused, codeActionUnclassified}},
	{"SM", planeCase{stopped: true, mismatch: true}, verdictDeny, []string{codeRunStopped, codeExecutedArgsMismatch}},
	{"SL", planeCase{stopped: true, lockdown: true}, verdictDeny, []string{codeRunStopped, codeLockdown}},
	{"SU", planeCase{stopped: true, unknown: true}, verdictDeny, []string{codeRunStopped, codePauseStateUnavailable}},
	{"SE", planeCase{stopped: true, sink: true}, verdictDeny, []string{codeRunStopped, codeEvidenceUnavailable}},
	{"SC", planeCase{stopped: true, unclassified: true}, verdictDeny, []string{codeRunStopped, codeActionUnclassified}},
	{"ML", planeCase{mismatch: true, lockdown: true}, verdictDeny, []string{codeExecutedArgsMismatch, codeLockdown}},
	{"MU", planeCase{mismatch: true, unknown: true}, verdictDeny, []string{codeExecutedArgsMismatch, codePauseStateUnavailable}},
	{"MK", planeCase{mismatch: true, stopUnknown: true}, verdictDeny, []string{codeExecutedArgsMismatch, codeStopStateUnavailable}},
	{"ME", planeCase{mismatch: true, sink: true}, verdictDeny, []string{codeExecutedArgsMismatch, codeEvidenceUnavailable}},
	{"MC", planeCase{mismatch: true, unclassified: true}, verdictDeny, []string{codeExecutedArgsMismatch, codeActionUnclassified}},
	{"LU", planeCase{lockdown: true, unknown: true}, verdictDeny, []string{codeLockdown, codePauseStateUnavailable}},
	{"LK", planeCase{lockdown: true, stopUnknown: true}, verdictDeny, []string{codeLockdown, codeStopStateUnavailable}},
	{"LE", planeCase{lockdown: true, sink: true}, verdictDeny, []string{codeLockdown, codeEvidenceUnavailable}},
	{"LC", planeCase{lockdown: true, unclassified: true}, verdictDeny, []string{codeLockdown, codeActionUnclassified}},
	{"UK", planeCase{unknown: true, stopUnknown: true}, verdictIndeterminate, []string{codePauseStateUnavailable, codeStopStateUnavailable}},
	{"UE", planeCase{unknown: true, sink: true}, verdictIndeterminate, []string{codePauseStateUnavailable, codeEvidenceUnavailable}},
	{"UC", planeCase{unknown: true, unclassified: true}, verdictIndeterminate, []string{codePauseStateUnavailable, codeActionUnclassified}},
	{"KE", planeCase{stopUnknown: true, sink: true}, verdictIndeterminate, []string{codeStopStateUnavailable, codeEvidenceUnavailable}},
	{"KC", planeCase{stopUnknown: true, unclassified: true}, verdictIndeterminate, []string{codeStopStateUnavailable, codeActionUnclassified}},
	{"EC", planeCase{sink: true, unclassified: true}, verdictIndeterminate, []string{codeEvidenceUnavailable, codeActionUnclassified}},
}

// TestEveryPairOfPlaneCauses: the decision lists every cause, DENY first, its
// verdict is DENY when any cause denies, and the block is counted by the
// first code alone.
func TestEveryPairOfPlaneCauses(t *testing.T) {
	for _, pc := range planeCases {
		t.Run(pc.name, func(t *testing.T) {
			h, d := pc.c.admitUnder(t, []string{allowReads, allowWrites})
			expectPlaneBlock(t, h, d, pc.verdict, pc.codes...)
			if got := h.p.Stats().Blocks; !maps.Equal(got, map[string]uint64{pc.codes[0]: 1}) {
				t.Errorf("Stats.Blocks = %v, want one under %s", got, pc.codes[0])
			}
		})
	}
}

// TestACallThePlaneBlocksIsNotAskedAbout: with a bundle whose veto reads the
// decision point, a write under any cause of the plane's own sends it
// nothing, and its POLICY_DECIDED says nobody was asked. The same write with
// no cause is asked once, so the count below is one the policy would spend.
func TestACallThePlaneBlocksIsNotAskedAbout(t *testing.T) {
	rules := []string{allowReads, allowWrites, vetoWrites}
	dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
	h, d := planeCase{}.admitUnder(t, rules, withDecisionPoint(dp))
	if d.Action != core.Execute || len(dp.questions()) != 1 {
		t.Fatalf("with no cause the write: Action = %d after %d ask(s); want it asked once and run", d.Action, len(dp.questions()))
	}
	expectConsulted(t, h.recorded(t, "req-x"), verdictAllow, codePDPAllow)
	for _, pc := range planeCases {
		if pc.c.unclassified {
			continue // the kernel reads no veto of a call it cannot classify
		}
		t.Run(pc.name, func(t *testing.T) {
			dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
			h, d := pc.c.admitUnder(t, rules, withDecisionPoint(dp))
			expectPlaneBlock(t, h, d, pc.verdict, pc.codes...)
			for _, q := range dp.questions() {
				if q.GetRequestId() == "req-x" {
					t.Errorf("the decision point was asked about a call the plane blocks")
				}
			}
			expectNotAsked(t, h.recorded(t, "req-x"))
		})
	}
}

// TestAPausedRetrySpendsNothing: a retry of an approved hold under a pause
// is blocked on a trail of its own, the approval unspent and the hold
// standing; once the pause is lifted the next retry resumes it and runs once.
func TestAPausedRetrySpendsNothing(t *testing.T) {
	ledger := &fakeLedger{}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), overLedger(ledger))
	first := hold(t, h)
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	h.pause.set(paused(t, pausePayments))
	blocked := h.admit(retry(t, "req-2"), refundArgs())
	expectPlaneBlock(t, h, blocked, verdictDeny, codePaused)
	if spends, _ := ledger.asked(); spends != 0 {
		t.Errorf("a paused retry spent %d approval(s)", spends)
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if h.p.Stats().Held != 1 {
		t.Errorf("Stats.Held = %d after a paused retry, want the hold standing", h.p.Stats().Held)
	}
	h.pause.set(paused(t))
	run := h.admit(retry(t, "req-3"), refundArgs())
	if run.Action != core.Execute {
		t.Fatalf("the retry after the lift: Action = %d, decision %v", run.Action, run.Decision.GetReasonCodes())
	}
	want := `{"amount":1000,"currency":"EUR","ssn":"x"}`
	if err := h.p.Close(context.Background(), run, []byte(want), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close: %v", err)
	}
	held := h.trailOf("req-1")
	expectKinds(t, kindsOf(held), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted, kindCompleted})
	if err := evidence.ValidateChain(held); err != nil {
		t.Errorf("ValidateChain over the held trail: %v", err)
	}
	if got := len(h.events()); got != len(held)+3 {
		t.Errorf("%d event(s) outside the held trail; want the paused retry's three alone", got-len(held))
	}
	if spends, _ := ledger.asked(); h.p.Stats().Executed != 1 || spends != 1 {
		t.Errorf("Executed = %d, spent = %d; want the held request run once", h.p.Stats().Executed, spends)
	}
}

// TestTheDecisionsReadOnePauseState: on the rewrite path, where the kernel
// decides twice and nobody is asked, the call reads the pause state once for
// its decisions and once more right before it starts; a read before the second
// decision would make three.
func TestTheDecisionsReadOnePauseState(t *testing.T) {
	clearState, payments := paused(t), paused(t, pausePayments)
	for _, c := range []struct {
		name    string
		snaps   []pause.Snapshot
		reads   int64
		blocked bool
	}{
		{"paused at admission", []pause.Snapshot{payments}, 1, true},
		{"clear throughout", []pause.Snapshot{clearState, clearState}, 2, false},
		{"paused before the start", []pause.Snapshot{clearState, payments}, 2, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := &sequence{snaps: c.snaps}
			h := build(t, modeEnforce, snapshot(t, cappedRefunds), func(cfg *gateway.Config) { cfg.Pause = src })
			d := h.admit(tool(refundEnvelope(t, refundArgs())), refundArgs())
			if got := src.reads.Load(); got != c.reads {
				t.Errorf("the call read the pause source %d time(s), want %d", got, c.reads)
			}
			switch {
			case c.blocked:
				expectPlaneBlock(t, h, d, verdictDeny, codePaused)
			case d.Action != core.ExecuteWithObligations:
				t.Errorf("under clear reads: Action = %d, codes %v; want the capped refund run", d.Action, d.Decision.GetReasonCodes())
			}
		})
	}
}

// TestEveryUnknownPauseStateBlocksWithItsOwnCode: one case per cause the
// reader names, each an INDETERMINATE block with code 43 and never PAUSED.
func TestEveryUnknownPauseStateBlocksWithItsOwnCode(t *testing.T) {
	valid := `{"schema_version":"1","entries":[]}`
	cases := map[string]func(t *testing.T) pause.Snapshot{
		"missing": func(t *testing.T) pause.Snapshot {
			return pause.Read(pauseFile(t)+".none", base(), pauseInterval)
		},
		"0620": func(t *testing.T) pause.Snapshot { return readMode(t, valid, 0o620, 0o700) },
		"0602": func(t *testing.T) pause.Snapshot { return readMode(t, valid, 0o602, 0o700) },
		"directory 0770": func(t *testing.T) pause.Snapshot {
			return readMode(t, valid, 0o600, 0o770)
		},
		"one byte over": func(t *testing.T) pause.Snapshot {
			return readMode(t, valid+strings.Repeat(" ", 163840-len(valid)+1), 0o600, 0o700)
		},
		"malformed": func(t *testing.T) pause.Snapshot { return readMode(t, valid[1:], 0o600, 0o700) },
		"unknown version": func(t *testing.T) pause.Snapshot {
			return readMode(t, strings.Replace(valid, `"1"`, `"2"`, 1), 0o600, 0o700)
		},
		"stale": func(t *testing.T) pause.Snapshot {
			return pause.Read(pauseFile(t), base().Add(-3*pauseInterval-time.Nanosecond), pauseInterval)
		},
		"dated ahead": func(t *testing.T) pause.Snapshot {
			return pause.Read(pauseFile(t), base().Add(time.Nanosecond), pauseInterval)
		},
	}
	for name, snap := range cases {
		t.Run(name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowReads))
			h.pause.set(snap(t))
			expectPlaneBlock(t, h, h.admit(tool(readEnvelope()), []byte(`{}`)), verdictIndeterminate, codePauseStateUnavailable)
		})
	}
	// Three intervals old, the same clear snapshot still lets the read run.
	h := build(t, modeEnforce, snapshot(t, allowReads))
	h.pause.set(pause.Read(pauseFile(t), base().Add(-3*pauseInterval), pauseInterval))
	if d := h.admit(tool(readEnvelope()), []byte(`{}`)); d.Action != core.Execute {
		t.Errorf("a snapshot three intervals old: %v", d.Decision.GetReasonCodes())
	}
}

// readMode reads a pause file of body at mode perm in a directory of mode dir.
func readMode(t *testing.T, body string, perm, dir uint32) pause.Snapshot {
	t.Helper()
	path := pauseFile(t)
	writeMode(t, path, body, perm, dir)
	return pause.Read(path, base(), pauseInterval)
}

// writeMode writes body at path with mode perm, in its directory set to dir.
func writeMode(t *testing.T, path, body string, perm, dir uint32) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, os.FileMode(perm)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), os.FileMode(dir)); err != nil {
		t.Fatal(err)
	}
}
