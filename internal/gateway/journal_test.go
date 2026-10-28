package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

// journalDouble is a hold journal a test can break: it refuses the write the
// test names and keeps every other one, so a refusal is the only difference
// between the run that passes and the run that does not.
type journalDouble struct {
	gateway.MemoryHoldJournal

	mu           sync.Mutex
	refuseRecord bool
	refuseMark   bool
	unreadable   int
	listErr      error
	// maybeRecord answers Record with errMaybeRecorded, after filing the
	// entry when fileOnMaybe says it was linked.
	maybeRecord, fileOnMaybe bool
}

var errJournal = errors.New("journal: refused")

// errMaybeRecorded is a record that failed after the entry may have been
// filed.
var errMaybeRecorded = fmt.Errorf("%w: the directory could not be forced to disk", gateway.ErrHoldMaybeRecorded)

func (j *journalDouble) Record(ctx context.Context, entry gateway.HoldEntry) error {
	j.mu.Lock()
	refuse, maybe, file := j.refuseRecord, j.maybeRecord, j.fileOnMaybe
	j.mu.Unlock()
	switch {
	case refuse:
		return errJournal
	case maybe && file:
		return errors.Join(j.MemoryHoldJournal.Record(ctx, entry), errMaybeRecorded)
	case maybe:
		return errMaybeRecorded
	}
	return j.MemoryHoldJournal.Record(ctx, entry)
}

func (j *journalDouble) Mark(ctx context.Context, requestID string, state gateway.HoldState) error {
	j.mu.Lock()
	refuse := j.refuseMark
	j.mu.Unlock()
	if refuse {
		return errJournal
	}
	return j.MemoryHoldJournal.Mark(ctx, requestID, state)
}

func (j *journalDouble) List(ctx context.Context, bound int) (gateway.HoldListing, error) {
	j.mu.Lock()
	failure, unreadable := j.listErr, j.unreadable
	j.mu.Unlock()
	if failure != nil {
		return gateway.HoldListing{}, failure
	}
	listing, err := j.MemoryHoldJournal.List(ctx, bound)
	listing.Unreadable += unreadable
	return listing, err
}

func (j *journalDouble) refuse(record, mark bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.refuseRecord, j.refuseMark = record, mark
}

// state is the state the journal holds requestID in, and whether it holds an
// entry for it at all.
func (j *journalDouble) state(requestID string) (gateway.HoldState, bool) {
	entry, kept := j.Entries()[requestID]
	return entry.State, kept
}

// appended is one append the plane made, with what the journal said about
// that trail at the moment it was made.
type appended struct {
	kind      controlv1.EventKind
	requestID string
	state     gateway.HoldState
	journal   bool
}

// watchSink reads the journal on every append, before the event reaches the
// sink under it, so a test can say what the journal claimed at the moment the
// plane wrote.
type watchSink struct {
	inner   evidence.Sink
	journal *journalDouble

	mu   sync.Mutex
	seen []appended
}

func (w *watchSink) Append(ctx context.Context, e *controlv1.Event) error {
	state, kept := w.journal.state(e.GetRequestId())
	w.mu.Lock()
	w.seen = append(w.seen, appended{kind: e.GetKind(), requestID: e.GetRequestId(), state: state, journal: kept})
	w.mu.Unlock()
	return w.inner.Append(ctx, e)
}

func (w *watchSink) appends() []appended {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.seen)
}

// pastTheRequest is every event kind that moves a trail past its request for
// an approval. Each one is an append the write order puts after a flip out of
// held (ADR-0016).
var pastTheRequest = []controlv1.EventKind{
	kindApprovalDecided, kindApprovalExpired, kindStarted, kindBlocked, kindCompleted, kindFailed,
}

// expectNothingAppendedWhileHeld asserts that no event past a request for
// approval was written while the journal still said that trail was held, and
// that such an event was written at all: a run that wrote none examined
// nothing.
func expectNothingAppendedWhileHeld(t *testing.T, w *watchSink) {
	t.Helper()
	examined := 0
	for _, a := range w.appends() {
		if !a.journal || !slices.Contains(pastTheRequest, a.kind) {
			continue
		}
		examined++
		if a.state == gateway.HoldHeld {
			t.Errorf("%s was appended to %s while its entry still read held", a.kind, a.requestID)
		}
	}
	if examined == 0 {
		t.Fatalf("no event past a request for approval reached a journalled trail; nothing was examined")
	}
}

// journalled builds a harness whose holds are journalled in j and whose
// appends are watched.
func journalled(t *testing.T, j *journalDouble, mut ...func(*gateway.Config)) (*harness, *watchSink) {
	t.Helper()
	var w *watchSink
	all := append([]func(*gateway.Config){func(cfg *gateway.Config) {
		cfg.Journal = j
		w = &watchSink{inner: cfg.Sink, journal: j}
		cfg.Sink = w
	}}, mut...)
	return build(t, modeEnforce, snapshot(t, approveRefunds), all...), w
}

// TestNothingIsAppendedPastAHeldRequestWhileItsEntrySaysHeld: on every path
// that moves a held trail past its APPROVAL_REQUESTED — an approved resume, a
// refused one, an expiry nobody answered, and a hold the store would not keep
// — the journal entry has left held before the first of those appends. That
// is what makes an entry that reads held proof that its trail can still be
// closed.
func TestNothingIsAppendedPastAHeldRequestWhileItsEntrySaysHeld(t *testing.T) {
	t.Run("an approved resume", func(t *testing.T) {
		j := &journalDouble{}
		h, w := journalled(t, j)
		first := hold(t, h)
		if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		run := h.admit(retry(t, "req-2"), refundArgs())
		if run.Action != core.Execute {
			t.Fatalf("the approved retry: Action = %d, want Execute", run.Action)
		}
		if err := h.p.Close(context.Background(), run, run.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
			t.Fatalf("Close: %v", err)
		}
		expectNothingAppendedWhileHeld(t, w)
		if _, kept := j.state("req-1"); kept {
			t.Errorf("the entry of a trail that has run is still in the journal")
		}
	})

	t.Run("a refused approval", func(t *testing.T) {
		j := &journalDouble{}
		h, w := journalled(t, j)
		first := hold(t, h)
		if err := h.store.Answer(first.Pending.ApprovalID, rejected, "", "no", base()); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictDeny, codeApprovalRejected, gateway.PDPType)
		expectNothingAppendedWhileHeld(t, w)
	})

	t.Run("an expiry nobody answered", func(t *testing.T) {
		j := &journalDouble{}
		h, w := journalled(t, j)
		hold(t, h)
		h.clock.set(base().Add(10 * time.Minute))
		h.admit(retry(t, "req-2"), refundArgs())
		expectNothingAppendedWhileHeld(t, w)
	})

	t.Run("a hold the store would not keep", func(t *testing.T) {
		store := newFakeStore()
		store.holdErr = errStore
		j := &journalDouble{}
		h, w := journalled(t, j, overStore(store))
		expectBlock(t, h.admit(refundEnvelope(t, refundArgs()), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		expectNothingAppendedWhileHeld(t, w)
		if _, kept := j.state("req-1"); kept {
			t.Errorf("the entry of a closed trail is still in the journal")
		}
	})
}

// TestAJournalThatRefusesAWriteBlocksRatherThanAppends: a journal that will
// not record a hold refuses the hold, and one that will not let an entry out
// of held stops every append that would move that trail on. The trail is left
// exactly where the entry says it stands, so a later plane can still close
// it.
func TestAJournalThatRefusesAWriteBlocksRatherThanAppends(t *testing.T) {
	t.Run("the record of a hold", func(t *testing.T) {
		j := &journalDouble{}
		j.refuse(true, false)
		h, _ := journalled(t, j)
		d := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
		expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{
			kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked,
		})
		if err := evidence.ValidateChain(h.trailOf("req-1")); err != nil {
			t.Errorf("ValidateChain over the refused hold: %v", err)
		}
		if s := h.p.Stats(); s.Held != 0 || s.JournalRefusals != 1 || s.Pending != 0 {
			t.Errorf("Stats = %+v; want nothing held or pending and the refusal counted", s)
		}
	})

	t.Run("the flip of an approved resume", func(t *testing.T) {
		j := &journalDouble{}
		h, _ := journalled(t, j)
		first := hold(t, h)
		if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		j.refuse(false, true)
		expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		expectHeldAtItsRequest(t, h, j)
	})

	t.Run("the flip of a refused approval", func(t *testing.T) {
		j := &journalDouble{}
		h, _ := journalled(t, j)
		first := hold(t, h)
		if err := h.store.Answer(first.Pending.ApprovalID, rejected, "", "no", base()); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		j.refuse(false, true)
		expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		expectHeldAtItsRequest(t, h, j)
	})

	t.Run("the flip of an expiry", func(t *testing.T) {
		j := &journalDouble{}
		h, _ := journalled(t, j)
		hold(t, h)
		j.refuse(false, true)
		h.clock.set(base().Add(10 * time.Minute))
		h.admit(retry(t, "req-2"), refundArgs())
		expectHeldAtItsRequest(t, h, j)
	})
}

// TestARecordThatMayHaveFiledItsEntryClosesTheTrailOnce: a journal that
// says the entry may be filed is taken at its word. The entry is flipped
// before the trail is closed and forgotten after, so a restart finds nothing
// to close; an entry that will not leave held keeps its trail at the request
// for approval, which a restart closes once; and with no entry behind it the
// trail stays open and counted, and nobody closes it twice.
func TestARecordThatMayHaveFiledItsEntryClosesTheTrailOnce(t *testing.T) {
	closed := []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked}
	atRequest := []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested}
	for _, c := range []struct {
		name            string
		filed, markFail bool
		trail           []controlv1.EventKind
		refusals        uint64
		leftOpen        uint64
		reconciled      gateway.Reconciliation
	}{
		{"the entry was filed", true, false, closed, 1, 0, gateway.Reconciliation{Complete: true}},
		{"the entry was filed and will not leave held", true, true, atRequest, 2, 1, gateway.Reconciliation{Closed: 1, Complete: true}},
		{"no entry was filed", false, false, atRequest, 2, 1, gateway.Reconciliation{Complete: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			snap := snapshot(t, approveRefunds)
			j := &journalDouble{maybeRecord: true, fileOnMaybe: c.filed, refuseMark: c.markFail}
			first := build(t, modeEnforce, snap, func(cfg *gateway.Config) { cfg.Journal = j })
			expectBlock(t, first.admit(refundEnvelope(t, refundArgs()), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			expectKinds(t, kindsOf(first.trailOf("req-1")), c.trail)
			if state, kept := j.state("req-1"); kept != c.markFail || (kept && state != gateway.HoldHeld) {
				t.Errorf("the entry of req-1 is %d, kept %v; want it kept held only while the flip is refused", state, kept)
			}
			if s := first.p.Stats(); s.Held != 0 || s.Pending != 0 || s.JournalRefusals != c.refusals || s.HeldTrailsLeftOpen != c.leftOpen {
				t.Errorf("Stats = %+v; want nothing held or pending, %d refusal(s) and %d trail(s) left open", s, c.refusals, c.leftOpen)
			}

			j.refuse(false, false)
			want := closed
			if !c.filed {
				want = atRequest
			}
			expectReconciledOnce(t, lost(t, snap, first, j), first, c.reconciled, want)
		})
	}
}

// expectReconciledOnce asserts a restart's first pass reports reconciled, a
// second finds nothing left to close, and req-1's trail ends as want and
// validates as one chain.
func expectReconciledOnce(t *testing.T, next, first *harness, reconciled gateway.Reconciliation, want []controlv1.EventKind) {
	t.Helper()
	if r := next.p.Reconcile(context.Background()); r != reconciled {
		t.Errorf("Reconcile = %+v; want %+v", r, reconciled)
	}
	if r := next.p.Reconcile(context.Background()); (r != gateway.Reconciliation{Complete: true}) {
		t.Errorf("a second Reconcile = %+v; want nothing left to close", r)
	}
	expectKinds(t, kindsOf(first.trailOf("req-1")), want)
	if err := evidence.ValidateChain(first.trailOf("req-1")); err != nil {
		t.Errorf("ValidateChain over req-1: %v", err)
	}
}

// expectHeldAtItsRequest asserts the held trail stands where its entry says:
// three events, nothing offered to the sink beyond them, and an entry still
// reading held, with the refusal counted.
func expectHeldAtItsRequest(t *testing.T, h *harness, j *journalDouble) {
	t.Helper()
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	for _, kind := range h.sink.askedFor() {
		if slices.Contains(pastTheRequest, kind) && kind != kindBlocked {
			t.Errorf("%s was offered to the sink although the journal refused the flip", kind)
		}
	}
	state, kept := j.state("req-1")
	if !kept || state != gateway.HoldHeld {
		t.Errorf("the entry of req-1 is %d, kept %v; want it still held", state, kept)
	}
	if s := h.p.Stats(); s.JournalRefusals == 0 {
		t.Errorf("Stats = %+v; want the refused flip counted", s)
	}
}

// TestAPlaneWithNoJournalHoldsAsItDidAndSaysSo: the seam is optional in one
// precise sense — without it the plane holds, resumes and expires exactly as
// it otherwise would, and closes no hold it loses. Stats carries that fact
// rather than leaving it to be discovered.
func TestAPlaneWithNoJournalHoldsAsItDidAndSaysSo(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveRefunds))
	if s := h.p.Stats(); s.HoldJournal {
		t.Errorf("Stats().HoldJournal = true for a plane built without a journal")
	}
	first := hold(t, h)
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if run := h.admit(retry(t, "req-2"), refundArgs()); run.Action != core.Execute {
		t.Fatalf("the approved retry without a journal: Action = %d, want Execute", run.Action)
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{
		kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted,
	})
	r := h.p.Reconcile(context.Background())
	if r.Complete || r.Closed != 0 {
		t.Errorf("Reconcile without a journal = %+v; want nothing closed and nothing measured", r)
	}
	if s := h.p.Stats(); s.HoldsClosed != 0 || s.ReconcileIncomplete {
		t.Errorf("Stats = %+v; a plane with no journal has no incomplete pass, it has no journal", s)
	}

	with, _ := journalled(t, &journalDouble{})
	if s := with.p.Stats(); !s.HoldJournal {
		t.Errorf("Stats().HoldJournal = false for a plane built with a journal")
	}
}

// TestNewRefusesANegativeReconcileBound: a bound that is not a bound is
// refused at start; no bound at all takes this build's own, which is why a
// pipeline built without one still reconciles.
func TestNewRefusesANegativeReconcileBound(t *testing.T) {
	cfg := validConfig(t)
	cfg.ReconcileMax = -1
	if _, err := gateway.New(cfg); !errors.Is(err, gateway.ErrReconcileMax) {
		t.Errorf("New with a negative bound = %v, want ErrReconcileMax", err)
	}
	cfg.ReconcileMax = 0
	if _, err := gateway.New(cfg); err != nil {
		t.Errorf("New with no bound = %v, want the build's own bound", err)
	}
}

// entry is a held journal entry a store-level test can record.
func entry(requestID string) gateway.HoldEntry {
	return gateway.HoldEntry{
		SchemaVersion: "1.0",
		State:         gateway.HoldHeld,
		IDs:           evidence.IDs{RequestID: requestID, RunID: "run-1", ProjectID: "proj-1", TenantID: "tenant-1"},
		LastEventID:   "evt-3",
		Binding:       approval.Binding("sha256:3"),
		Approval: &controlv1.Approval{
			ApprovalId: "a-" + requestID, RequestId: requestID,
			ExpiresAt: timestamppb.New(base().Add(10 * time.Minute)),
		},
		Expires: base().Add(10 * time.Minute),
	}
}

// TestTheJournalRecordsAHoldAndLetsItOutOfHeldOnce: what a journal owes the
// plane, as refusals: it records only a complete entry in held, once per
// request, and an entry leaves held once, for resuming or for closing.
func TestTheJournalRecordsAHoldAndLetsItOutOfHeldOnce(t *testing.T) {
	var j gateway.MemoryHoldJournal
	incomplete := map[string]func(*gateway.HoldEntry){
		"no schema version": func(e *gateway.HoldEntry) { e.SchemaVersion = "" },
		"no request id":     func(e *gateway.HoldEntry) { e.IDs.RequestID = "" },
		"no position":       func(e *gateway.HoldEntry) { e.LastEventID = "" },
		"no binding":        func(e *gateway.HoldEntry) { e.Binding = "" },
		"no approval":       func(e *gateway.HoldEntry) { e.Approval = nil },
		"no expiry":         func(e *gateway.HoldEntry) { e.Expires = time.Time{} },
		"already resuming":  func(e *gateway.HoldEntry) { e.State = gateway.HoldResuming },
		"in no state":       func(e *gateway.HoldEntry) { e.State = gateway.HoldUnknown },
	}
	for name, mut := range incomplete {
		broken := entry("req-1")
		mut(&broken)
		if err := j.Record(ctx(), broken); !errors.Is(err, gateway.ErrHoldEntry) {
			t.Errorf("Record with %s = %v, want ErrHoldEntry", name, err)
		}
	}
	if err := j.Record(ctx(), entry("req-1")); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := j.Record(ctx(), entry("req-1")); !errors.Is(err, gateway.ErrHoldRecorded) {
		t.Errorf("a second record of one request = %v, want ErrHoldRecorded", err)
	}
	if err := j.Mark(ctx(), "req-2", gateway.HoldClosing); !errors.Is(err, gateway.ErrNoHoldEntry) {
		t.Errorf("Mark of a request it holds nothing for = %v, want ErrNoHoldEntry", err)
	}
	if err := j.Mark(ctx(), "req-1", gateway.HoldHeld); !errors.Is(err, gateway.ErrHoldFlip) {
		t.Errorf("Mark back into held = %v, want ErrHoldFlip", err)
	}
	if err := j.Mark(ctx(), "req-1", gateway.HoldResuming); err != nil {
		t.Fatalf("Mark as resuming: %v", err)
	}
	if err := j.Mark(ctx(), "req-1", gateway.HoldClosing); !errors.Is(err, gateway.ErrHoldFlip) {
		t.Errorf("a second flip out of held = %v, want ErrHoldFlip", err)
	}
}

// TestAListingHandsBackOnlyWhatReadsHeld: entries that left held are counted
// and never handed out, because nothing can be said about where their trails
// stand.
func TestAListingHandsBackOnlyWhatReadsHeld(t *testing.T) {
	j := recorded(t, "req-1", "req-2", "req-3")
	if err := j.Mark(ctx(), "req-2", gateway.HoldClosing); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	listing, err := j.List(ctx(), 8)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listing.Held) != 2 || !listing.Complete || listing.Interrupted != 1 {
		t.Errorf("List = %+v; want the two held entries, one interrupted and a complete pass", listing)
	}
	for _, e := range listing.Held {
		if e.IDs.RequestID == "req-2" {
			t.Errorf("an entry that left held was handed out: %+v", e)
		}
	}
}

// TestABoundedListingIsUnmeasured: the bound bites at one of three entries,
// and the listing says it is not a complete answer. A bound of nothing reads
// nothing and says the same, rather than reporting an empty journal.
func TestABoundedListingIsUnmeasured(t *testing.T) {
	j := recorded(t, "req-1", "req-2", "req-3")
	bounded, err := j.List(ctx(), 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if bounded.Complete || len(bounded.Held) != 2 {
		t.Errorf("a bounded List = %+v; want two entries and an unmeasured pass", bounded)
	}
	none, err := j.List(ctx(), 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if none.Complete || len(none.Held) != 0 {
		t.Errorf("List of nothing = %+v; want an unmeasured pass over nothing", none)
	}
}

// TestAForgottenEntryLeavesTheListing: what a closed trail leaves behind is
// nothing, and forgetting it twice is not an error.
func TestAForgottenEntryLeavesTheListing(t *testing.T) {
	j := recorded(t, "req-1", "req-2")
	if err := j.Forget(ctx(), "req-1"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if err := j.Forget(ctx(), "req-1"); err != nil {
		t.Errorf("forgetting an entry it no longer holds = %v, want no error", err)
	}
	after, err := j.List(ctx(), 8)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(after.Held) != 1 || after.Held[0].IDs.RequestID != "req-2" {
		t.Errorf("List after a Forget = %+v; want req-2 alone", after.Held)
	}
}

// recorded is a journal holding one entry per request id.
func recorded(t *testing.T, requestIDs ...string) *gateway.MemoryHoldJournal {
	t.Helper()
	j := &gateway.MemoryHoldJournal{}
	for _, id := range requestIDs {
		if err := j.Record(ctx(), entry(id)); err != nil {
			t.Fatalf("Record %s: %v", id, err)
		}
	}
	return j
}
