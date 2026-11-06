package main

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/holdjournal"
)

// TestASpendSurvivesARestartAndALostLedgerOnlyHoldsAnew: over the file
// provider an approved hold runs once. A plane that comes back over the same
// directories answers the same retry APPROVAL_ALREADY_USED from the ledger
// beside its journal; one that comes back after the ledger was emptied holds
// the retry anew under a fresh approval and runs nothing.
func TestASpendSurvivesARestartAndALostLedgerOnlyHoldsAnew(t *testing.T) {
	tr, first := holdingPlane(t, fileProviderOf(t), 15*time.Minute)
	records := filepath.Join(tr.dir, recordsDir)
	held := admitTransfer(t, first, "req-hold-1")
	if held.Action != core.AwaitApproval {
		t.Fatalf("the first call is %v, want a hold: %v", held.Action, held.Decision.GetReasonCodes())
	}
	answerFrom(t, records, held.Pending.ApprovalID, true)
	resumed := admitTransfer(t, first, "req-hold-2")
	if resumed.Action != core.Execute {
		t.Fatalf("the approved retry is %v, want an execution: %v", resumed.Action, resumed.Decision.GetReasonCodes())
	}
	closeExecution(t, first, resumed)
	if err := first.close(); err != nil {
		t.Fatalf("stopping the first plane: %v", err)
	}

	again := tr.plane(t)
	used := admitTransfer(t, again, "req-hold-3")
	if used.Action != core.Block || !slices.Contains(used.Decision.GetReasonCodes(), "APPROVAL_ALREADY_USED") {
		t.Errorf("the retry after a restart is %v with %v, want APPROVAL_ALREADY_USED", used.Action, used.Decision.GetReasonCodes())
	}
	if err := again.close(); err != nil {
		t.Fatalf("stopping the second plane: %v", err)
	}

	expectHeldAnewOverAnEmptyLedger(t, tr, held.Pending.ApprovalID)
}

// expectHeldAnewOverAnEmptyLedger empties the ledger beside tr's journal and
// holds the plane that comes back to holding the same call anew, under an
// approval other than held, and running nothing.
func expectHeldAnewOverAnEmptyLedger(t *testing.T, tr tree, held string) {
	t.Helper()
	ledger := filepath.Join(tr.dir, holdsDir, "ledger")
	if err := os.RemoveAll(ledger); err != nil {
		t.Fatalf("emptying the ledger: %v", err)
	}
	lost := tr.plane(t)
	anew := admitTransfer(t, lost, "req-hold-4")
	if anew.Action != core.AwaitApproval || anew.Pending == nil || anew.Pending.ApprovalID == held {
		t.Errorf("the retry over an emptied ledger is %v pending %+v, want a hold of its own", anew.Action, anew.Pending)
	}
	if s := lost.pipeline.Stats(); s.Executed != 0 || s.UnheldRecords != 1 {
		t.Errorf("over an emptied ledger %d execution(s) and %d unheld record(s), want 0 and 1", s.Executed, s.UnheldRecords)
	}
}

// TestNoNameAnApproverWritesReadsAsSpentOrSettled: a writer of the approvals
// directory plants, beside a live hold, the name a 1.0 plane gave a spent or
// a given-up record, or rewrites the plane's own record to carry the
// resolution a 1.0 record did. None of it reads as spent or as given up: the
// retry is blocked as one the store cannot answer, with nothing spent and the
// hold standing. The control is the same directory with the plant removed.
func TestNoNameAnApproverWritesReadsAsSpentOrSettled(t *testing.T) {
	for _, c := range []struct {
		name  string
		plant func(t *testing.T, records, own string) (undo func())
	}{
		{"a consumed name", func(t *testing.T, records, own string) func() {
			return plantCopy(t, records, own+".0-held.rec", own+".3-consumed.rec")
		}},
		{"a not-resumed name", func(t *testing.T, records, own string) func() {
			return plantCopy(t, records, own+".0-held.rec", own+".2-not-resumed.rec")
		}},
		{"a resolution in the plane's own record", func(t *testing.T, records, own string) func() {
			path := filepath.Join(records, own+".0-held.rec")
			framed, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary directory
			if err != nil {
				t.Fatal(err)
			}
			body := framed[recordHeader:]
			at := slices.Index(body, '{')
			forged := append([]byte(`{"resolution":"consumed",`), body[at+1:]...)
			writeFramed(t, path, forged)
			return func() {
				if err := os.WriteFile(path, framed, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr, plane := holdingPlane(t, fileProviderOf(t), 15*time.Minute)
			records := filepath.Join(tr.dir, recordsDir)
			held := admitTransfer(t, plane, "req-hold-1")
			if held.Action != core.AwaitApproval {
				t.Fatalf("the first call is %v, want a hold", held.Action)
			}
			undo := c.plant(t, records, held.Pending.ApprovalID)
			refused := admitTransfer(t, plane, "req-hold-2")
			if codes := refused.Decision.GetReasonCodes(); refused.Action != core.Block || !slices.Equal(codes, []string{"EVIDENCE_UNAVAILABLE"}) {
				t.Errorf("the retry beside the plant is %v with %v, want a block with EVIDENCE_UNAVAILABLE alone", refused.Action, codes)
			}
			undo()
			waiting := admitTransfer(t, plane, "req-hold-3")
			if waiting.Action != core.AwaitApproval || waiting.Pending.ApprovalID != held.Pending.ApprovalID {
				t.Errorf("the retry with the plant removed is %v, want the hold still pending", waiting.Action)
			}
			if s := plane.pipeline.Stats(); s.Executed != 0 || s.Held != 1 {
				t.Errorf("%d execution(s) and %d held, want 0 and the one hold standing", s.Executed, s.Held)
			}
		})
	}
}

// plantCopy copies the file from under records to name, as a writer of the
// directory would, and returns what removes it again.
func plantCopy(t *testing.T, records, from, name string) func() {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(records, from)) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatalf("reading %s: %v", from, err)
	}
	path := filepath.Join(records, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("planting %s: %v", name, err)
	}
	return func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTheLedgerForgetsAtOpenOnlyWhatOutlivedTheApprovalLifetime: a plane
// opening its journal prunes the marks written more than one approval
// lifetime ago, which no live record can need, and keeps one written just
// inside it, so the next identical call is still refused.
func TestTheLedgerForgetsAtOpenOnlyWhatOutlivedTheApprovalLifetime(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "holds")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const ttl = 10 * time.Minute
	b := approval.Binding("sha256:ledger")
	journal, err := holdjournal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := journal.Ledger()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for req, at := range map[string]time.Time{"req-old": now.Add(-ttl - time.Minute), "req-live": now.Add(-ttl + time.Minute)} {
		if err := ledger.Spend(context.Background(), b, req, "apr-"+req, "duty-officer", at); err != nil {
			t.Fatalf("Spend %s: %v", req, err)
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := &gatewayconfig.Config{Approvals: gatewayconfig.ApprovalsConfig{
		HoldJournalDir: dir, TTL: ttl, MaxRecords: holdjournal.DefaultMaxEntries, MaxRecordBytes: holdjournal.DefaultMaxEntryBytes,
	}}
	holds, opened, err := openJournal(cfg)
	if err != nil {
		t.Fatalf("openJournal: %v", err)
	}
	defer func() { _ = opened.Close() }()
	marks, err := planeLedger(holds).Lookup(context.Background(), b, now)
	if err != nil || !maps.Equal(marks, map[string]gateway.Resolution{"req-live": gateway.ResolutionConsumed}) {
		t.Errorf("after the open the ledger marks %v, %v; want the mark inside the lifetime alone", marks, err)
	}
}

// TestASettledHoldIsNoLongerOfferedToAnApprover: a plane that comes back and
// settles a hold it lost removes its own record of it, so the listing an
// approver reads, which the console renders, no longer shows it, and an
// answer to it is refused as one to an approval nobody holds. The control is
// the same listing before the reconciliation.
func TestASettledHoldIsNoLongerOfferedToAnApprover(t *testing.T) {
	tr := newTree(t)
	records, holds := tr.fileProvider(t)
	lostHold(t, records, holds, time.Now().Add(10*time.Minute))
	if got := recordsUnder(t, records); len(got) != 1 {
		t.Fatalf("before the reconciliation the listing shows %v, want the lost hold", got)
	}
	p := tr.plane(t)
	if r := p.pipeline.Reconcile(context.Background()); r.Closed != 1 {
		t.Fatalf("the reconciliation settled %+v, want the lost hold closed", r)
	}
	if got := recordsUnder(t, records); len(got) != 0 {
		t.Errorf("after the reconciliation the listing shows %v, want nothing", got)
	}
	approver, err := approvals.OpenApprover(records)
	if err != nil {
		t.Fatalf("OpenApprover: %v", err)
	}
	defer func() { _ = approver.Close() }()
	_, err = approver.Answer(context.Background(), lostApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "duty-officer", "", time.Now())
	if !errors.Is(err, approvals.ErrNoApproval) {
		t.Errorf("an answer to the settled hold = %v, want ErrNoApproval", err)
	}
	if s := p.pipeline.Stats(); s.UnheldRecords != 0 {
		t.Errorf("Stats().UnheldRecords = %d, want 0: the record was forgotten", s.UnheldRecords)
	}
}
