package gateway_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

// expectOneChain asserts that the kept events of req-1, the held request,
// are the kinds want and read as one chain.
func expectOneChain(t *testing.T, h *harness, want []controlv1.EventKind) {
	t.Helper()
	trail := h.trailOf("req-1")
	expectKinds(t, kindsOf(trail), want)
	if err := evidence.ValidateChain(trail); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
}

// expectEntry asserts that the journal keeps the entry of req-1 in state and
// lists it once as interrupted.
func expectEntry(t *testing.T, j *journalDouble, state gateway.HoldState) {
	t.Helper()
	if got, kept := j.state("req-1"); !kept || got != state {
		t.Errorf("the entry of req-1 is %v, kept %v; want it kept in state %v", got, kept, state)
	}
	listing, err := j.List(context.Background(), 16)
	if err != nil || listing.Interrupted != 1 || len(listing.Held) != 0 || !listing.Complete {
		t.Errorf("List = %+v, %v; want the open trail's entry listed once", listing, err)
	}
}

// expectNoEntry asserts that the journal keeps nothing at all.
func expectNoEntry(t *testing.T, j *journalDouble) {
	t.Helper()
	if entries := j.Entries(); len(entries) != 0 {
		t.Errorf("the journal keeps %v; want nothing", entries)
	}
	listing, err := j.List(context.Background(), 16)
	if err != nil || listing.Interrupted != 0 || len(listing.Held) != 0 || !listing.Complete {
		t.Errorf("List = %+v, %v; want an empty, complete listing", listing, err)
	}
}

// accept stores every kind again.
func (s *failingSink) accept() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse = map[controlv1.EventKind]bool{}
}

// TestAHeldReadIsClosedStrictlyAtItsResume: closing a held trail runs
// nothing, so a read under AllowReadsUnrecorded is given no exemption there. A
// refused ACTION_BLOCKED leaves the trail open, with its entry and its request
// id, counts the plane's EVIDENCE_UNAVAILABLE and no read as unrecorded, and
// no later call writes on that trail again.
func TestAHeldReadIsClosedStrictlyAtItsResume(t *testing.T) {
	for name, journalled := range map[string]bool{"with a journal": true, "without a journal": false} {
		t.Run(name, func(t *testing.T) {
			store := newFakeStore()
			j := &journalDouble{}
			h := build(t, modeEnforce, snapshot(t, approveReads), overStore(store), func(cfg *gateway.Config) {
				cfg.AllowReadsUnrecorded = true
				if journalled {
					cfg.Journal = j
				}
			})
			if first := h.admit(readEnvelope(), []byte(`{}`)); first.Action != core.AwaitApproval {
				t.Fatalf("the first read: Action = %d, decision %+v", first.Action, first.Decision)
			}
			reportExpired(store)
			h.sink.refuseKind(kindBlocked)

			d := h.admit(requestNamed(readEnvelope(), "req-2"), []byte(`{}`))
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			open := []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired}
			expectOneChain(t, h, open)
			if journalled {
				expectEntry(t, j, gateway.HoldClosing)
			}
			if s := h.p.Stats(); s.Blocks[codeEvidenceUnavailable] != 1 || len(s.Blocks) != 1 || s.ReadsUnrecorded != 0 {
				t.Errorf("Stats = %+v; want EVIDENCE_UNAVAILABLE once and no read unrecorded", s)
			}

			store.found = nil
			h.sink.accept()
			again := h.admit(readEnvelope(), []byte(`{}`))
			expectBlock(t, again, verdictIndeterminate, codeInvalidFieldValue, gateway.PDPType)
			h.clock.set(base().Add(10 * time.Minute))
			h.admit(requestNamed(readEnvelope(), "req-3"), []byte(`{}`))
			expectOneChain(t, h, open)
		})
	}
}

// TestAnOpenHeldTrailKeepsItsRequestID: a trail past a request for approval
// that a refused record left open keeps its journal entry, and its request id
// stays reserved with it, so no later call under that id writes a second
// trail into it or forgets the entry at its Close.
func TestAnOpenHeldTrailKeepsItsRequestID(t *testing.T) {
	for name, tc := range map[string]struct {
		open  func(*testing.T, *harness, *fakeStore)
		kinds []controlv1.EventKind
		state gateway.HoldState
	}{
		"a refused hold whose block is refused": {
			open: func(t *testing.T, h *harness, store *fakeStore) {
				store.holdErr = errStore
				h.sink.refuseKind(kindBlocked)
				expectBlock(t, h.admit(refundEnvelope(t, refundArgs()), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			},
			kinds: []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired},
			state: gateway.HoldClosing,
		},
		"a resume whose approval record is refused": {
			open: func(t *testing.T, h *harness, store *fakeStore) {
				holdApproved(t, h, store)
				h.sink.refuseKind(kindApprovalDecided)
				expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			},
			kinds: []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested},
			state: gateway.HoldResuming,
		},
		"a resume whose start is refused": {
			open: func(t *testing.T, h *harness, store *fakeStore) {
				holdApproved(t, h, store)
				h.sink.refuseKind(kindStarted)
				expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			},
			kinds: []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided},
			state: gateway.HoldResuming,
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakeStore()
			j := &journalDouble{}
			h := build(t, modeEnforce, snapshot(t, approveRefunds, allowWrites), overStore(store),
				func(cfg *gateway.Config) { cfg.Journal = j })
			tc.open(t, h, store)
			expectEntry(t, j, tc.state)

			h.sink.accept()
			d := h.admit(writeEnvelope(), []byte(`{}`))
			if d.Action == core.Execute {
				if err := h.p.Close(context.Background(), d, d.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
					t.Errorf("Close: %v", err)
				}
			}
			expectBlock(t, d, verdictIndeterminate, codeInvalidFieldValue, gateway.PDPType)
			expectOneChain(t, h, tc.kinds)
			expectEntry(t, j, tc.state)
		})
	}
}

// TestAReadWhoseRequestForApprovalIsRefusedIsNeverHeld: under
// AllowReadsUnrecorded a read whose APPROVAL_REQUESTED the sink refuses is
// blocked rather than held, because an approved retry would resume a trail
// from an event nobody wrote. It is still a read whose event was refused, and
// is counted as one.
func TestAReadWhoseRequestForApprovalIsRefusedIsNeverHeld(t *testing.T) {
	j := &journalDouble{}
	h := build(t, modeEnforce, snapshot(t, approveReads), func(cfg *gateway.Config) {
		cfg.AllowReadsUnrecorded = true
		cfg.Journal = j
	})
	h.sink.refuseKind(kindApprovalRequested)
	d := h.admit(readEnvelope(), []byte(`{}`))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectOneChain(t, h, []controlv1.EventKind{kindProposed, kindDecided})
	expectNoEntry(t, j)
	s := h.p.Stats()
	if s.Held != 0 || s.Pending != 0 || s.ReadsUnrecorded != 1 || s.Blocks[codeEvidenceUnavailable] != 1 || len(s.Blocks) != 1 {
		t.Errorf("Stats = %+v; want nothing held, one read unrecorded, EVIDENCE_UNAVAILABLE once", s)
	}
}

// hookedHoldStore runs during inside Hold and then refuses the hold, so a
// test can act while a hold is on its way to the store.
type hookedHoldStore struct {
	*fakeStore
	during func()
}

func (s *hookedHoldStore) Hold(context.Context, gateway.Held, time.Time) error {
	if run := s.during; run != nil {
		s.during = nil
		run()
	}
	return errStore
}

// TestARefusedHoldTheSweepClosedIsNotClosedTwice: a hold still on its way to
// the store can expire under another call's sweep, which closes its trail and
// counts its block. The store's refusal then writes nothing on that trail and
// counts nothing more, and the call is still answered as blocked.
func TestARefusedHoldTheSweepClosedIsNotClosedTwice(t *testing.T) {
	for name, journalled := range map[string]bool{"with a journal": true, "without a journal": false} {
		t.Run(name, func(t *testing.T) {
			store := &hookedHoldStore{fakeStore: newFakeStore()}
			j := &journalDouble{}
			h := build(t, modeEnforce, snapshot(t, approveRefunds, allowWrites), overStore(store), func(cfg *gateway.Config) {
				if journalled {
					cfg.Journal = j
				}
			})
			store.during = func() {
				h.clock.set(base().Add(10 * time.Minute))
				if other := h.admit(requestNamed(writeEnvelope(), "req-9"), []byte(`{}`)); other.Action != core.Execute {
					t.Errorf("the call that sweeps: Action = %d, decision %+v", other.Action, other.Decision)
				}
			}
			d := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			expectOneChain(t, h, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
			if s := h.p.Stats(); s.Blocks[codeApprovalExpired] != 1 || len(s.Blocks) != 1 {
				t.Errorf("Stats().Blocks = %v; want the sweep's APPROVAL_EXPIRED once and nothing else", s.Blocks)
			}
			if journalled {
				expectNoEntry(t, j)
			}
		})
	}
}

// TestAResumedTrailBlockedAtMaxOpenForgetsItsEntry: a resumed trail the bound
// on open executions blocks is closed by its ACTION_BLOCKED, so its entry is
// forgotten there and no start reports that trail interrupted; when the sink
// refuses that record the trail stays open, and its entry stays with it.
func TestAResumedTrailBlockedAtMaxOpenForgetsItsEntry(t *testing.T) {
	for name, refused := range map[string]bool{"the block written": false, "the block refused": true} {
		t.Run(name, func(t *testing.T) {
			j := &journalDouble{}
			h := build(t, modeEnforce, snapshot(t, approveRefunds, allowWrites),
				func(cfg *gateway.Config) { cfg.Journal = j; cfg.MaxOpen = 1 })
			first := hold(t, h)
			if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
				t.Fatalf("Answer: %v", err)
			}
			if filler := h.admit(requestNamed(writeEnvelope(), "req-9"), []byte(`{}`)); filler.Action != core.Execute {
				t.Fatalf("the write that fills the bound: Action = %d, decision %+v", filler.Action, filler.Decision)
			}
			if refused {
				h.sink.refuseKind(kindBlocked)
			}
			d := h.admit(retry(t, "req-2"), refundArgs())
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			resumed := []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided}
			if refused {
				expectOneChain(t, h, resumed)
				expectEntry(t, j, gateway.HoldResuming)
			} else {
				expectOneChain(t, h, append(resumed, kindBlocked))
				expectNoEntry(t, j)
			}
			if s := h.p.Stats(); s.Blocks[codeEvidenceUnavailable] != 1 || len(s.Blocks) != 1 {
				t.Errorf("Stats().Blocks = %v; want EVIDENCE_UNAVAILABLE once", s.Blocks)
			}
		})
	}
}

// TestAResumedReadIsNeverRunUnrecorded: a call that would be held never runs
// unrecorded, and neither does one resuming a hold, so under
// AllowReadsUnrecorded a held read whose APPROVAL_DECIDED the sink refuses is
// blocked, its trail left open with its entry.
func TestAResumedReadIsNeverRunUnrecorded(t *testing.T) {
	j := &journalDouble{}
	h := build(t, modeEnforce, snapshot(t, approveReads), func(cfg *gateway.Config) {
		cfg.AllowReadsUnrecorded = true
		cfg.Journal = j
	})
	first := h.admit(readEnvelope(), []byte(`{}`))
	if first.Action != core.AwaitApproval {
		t.Fatalf("the first read: Action = %d, decision %+v", first.Action, first.Decision)
	}
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	h.sink.refuseKind(kindApprovalDecided)
	d := h.admit(requestNamed(readEnvelope(), "req-2"), []byte(`{}`))
	if d.Action == core.Execute {
		if err := h.p.Close(context.Background(), d, d.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectOneChain(t, h, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	expectEntry(t, j, gateway.HoldResuming)
	if s := h.p.Stats(); s.ReadsUnrecorded != 0 || s.Executed != 0 {
		t.Errorf("Stats = %+v; want no read unrecorded and nothing executed", s)
	}
}

// closeRun closes d with a success when it was handed to execution.
func closeRun(t *testing.T, h *harness, d gateway.Disposition) {
	t.Helper()
	if d.Action != core.Execute {
		return
	}
	if err := h.p.Close(context.Background(), d, d.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestALostHoldLeavesItsRequestIDToTheNextOwner: the sweep closed and
// released a hold still on its way to the store, and the next call under that
// id reserved it and runs. The store's refusal then releases nothing, so no
// third call starts a second trail under that id while the second runs.
func TestALostHoldLeavesItsRequestIDToTheNextOwner(t *testing.T) {
	store := &hookedHoldStore{fakeStore: newFakeStore()}
	h := build(t, modeEnforce, snapshot(t, approveRefunds, allowWrites), overStore(store))
	var running gateway.Disposition
	store.during = func() {
		h.clock.set(base().Add(10 * time.Minute))
		running = h.admit(writeEnvelope(), []byte(`{}`))
	}
	d := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	if running.Action != core.Execute {
		t.Fatalf("the call that took req-1 over: Action = %d, decision %+v", running.Action, running.Decision)
	}
	third := h.admit(writeEnvelope(), []byte(`{}`))
	closeRun(t, h, third)
	expectBlock(t, third, verdictIndeterminate, codeInvalidFieldValue, gateway.PDPType)
	closeRun(t, h, running)
	s := h.p.Stats()
	if s.HeldTrailsLeftOpen != 0 || s.Blocks[codeApprovalExpired] != 1 || s.Blocks[codeInvalidFieldValue] != 1 || len(s.Blocks) != 2 {
		t.Errorf("Stats = %+v; want the sweep's block and the refused third call, and no trail left open", s)
	}
}

// TestAHeldTrailClosedAtItsResumeFreesItsRequestID: a retry that finds the
// approval expired closes the held trail, and its id is free for the next
// call under it.
func TestAHeldTrailClosedAtItsResumeFreesItsRequestID(t *testing.T) {
	store := newFakeStore()
	h := build(t, modeEnforce, snapshot(t, approveRefunds, allowWrites), overStore(store))
	holdApproved(t, h, store)
	reportExpired(store)
	expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictDeny, codeApprovalExpired, gateway.PDPType)
	d := h.admit(writeEnvelope(), []byte(`{}`))
	closeRun(t, h, d)
	if d.Action != core.Execute {
		t.Errorf("a new call under the closed req-1: Action = %d, decision %+v; want it run", d.Action, d.Decision)
	}
	if s := h.p.Stats(); s.HeldTrailsLeftOpen != 0 {
		t.Errorf("Stats().HeldTrailsLeftOpen = %d; want 0", s.HeldTrailsLeftOpen)
	}
}

// TestAResumeTheSweepBeatIsNotClosedTwice: the sweep takes a hold while the
// retry's lookup runs. The retry is answered as blocked and writes and counts
// nothing on that trail, which carries the sweep's closing once.
func TestAResumeTheSweepBeatIsNotClosedTwice(t *testing.T) {
	store := newFakeStore()
	h := build(t, modeEnforce, snapshot(t, approveRefunds, allowWrites), overStore(store))
	holdApproved(t, h, store)
	store.found = func(a *controlv1.Approval) {
		store.found = nil
		h.clock.set(base().Add(10 * time.Minute))
		closeRun(t, h, h.admit(requestNamed(writeEnvelope(), "req-9"), []byte(`{}`)))
		a.ExpiresAt = timestamppb.New(base())
	}
	d := h.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectOneChain(t, h, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
	if s := h.p.Stats(); s.Blocks[codeApprovalExpired] != 1 || len(s.Blocks) != 1 || s.HeldTrailsLeftOpen != 0 {
		t.Errorf("Stats = %+v; want the sweep's APPROVAL_EXPIRED once and nothing else", s)
	}
}

// TestEveryHeldTrailLeftOpenIsCounted: each place a refused write leaves a
// trail past its request for approval open counts that trail once, and its
// request id stays reserved; a trail closed, or never held, counts nothing
// and frees its id.
func TestEveryHeldTrailLeftOpenIsCounted(t *testing.T) {
	for name, tc := range map[string]struct {
		open func(*testing.T, *harness, *fakeStore, *journalDouble)
		left bool
	}{
		"a refused hold whose block is refused": {
			open: func(t *testing.T, h *harness, store *fakeStore, _ *journalDouble) {
				store.holdErr = errStore
				h.sink.refuseKind(kindBlocked)
				expectBlock(t, h.admit(refundEnvelope(t, refundArgs()), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			},
			left: true,
		},
		"a resume whose approval record is refused": {
			open: func(t *testing.T, h *harness, store *fakeStore, _ *journalDouble) {
				holdApproved(t, h, store)
				h.sink.refuseKind(kindApprovalDecided)
				expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			},
			left: true,
		},
		"a resume whose journal flip is refused": {
			open: func(t *testing.T, h *harness, store *fakeStore, j *journalDouble) {
				holdApproved(t, h, store)
				j.refuse(false, true)
				expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			},
			left: true,
		},
		"a resume whose closing block is refused": {
			open: func(t *testing.T, h *harness, store *fakeStore, _ *journalDouble) {
				holdApproved(t, h, store)
				reportExpired(store)
				h.sink.refuseKind(kindBlocked)
				expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			},
			left: true,
		},
		"a sweep whose closing record is refused": {
			open: func(t *testing.T, h *harness, _ *fakeStore, _ *journalDouble) {
				hold(t, h)
				h.sink.refuseKind(kindApprovalExpired)
				h.clock.set(base().Add(10 * time.Minute))
				closeRun(t, h, h.admit(requestNamed(writeEnvelope(), "req-9"), []byte(`{}`)))
			},
			left: true,
		},
		"a hold the sweep closed": {
			open: func(t *testing.T, h *harness, _ *fakeStore, _ *journalDouble) {
				hold(t, h)
				h.clock.set(base().Add(10 * time.Minute))
				closeRun(t, h, h.admit(requestNamed(writeEnvelope(), "req-9"), []byte(`{}`)))
			},
		},
		"a call whose request for approval is refused": {
			open: func(t *testing.T, h *harness, _ *fakeStore, _ *journalDouble) {
				h.sink.refuseKind(kindApprovalRequested)
				expectBlock(t, h.admit(refundEnvelope(t, refundArgs()), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakeStore()
			j := &journalDouble{}
			h := build(t, modeEnforce, snapshot(t, approveRefunds, allowWrites), overStore(store),
				func(cfg *gateway.Config) { cfg.Journal = j })
			tc.open(t, h, store, j)
			h.sink.accept()
			j.refuse(false, false)

			want := uint64(0)
			if tc.left {
				want = 1
			}
			if got := h.p.Stats().HeldTrailsLeftOpen; got != want {
				t.Errorf("Stats().HeldTrailsLeftOpen = %d; want %d", got, want)
			}
			d := h.admit(writeEnvelope(), []byte(`{}`))
			closeRun(t, h, d)
			if tc.left {
				expectBlock(t, d, verdictIndeterminate, codeInvalidFieldValue, gateway.PDPType)
			} else if d.Action != core.Execute {
				t.Errorf("a new call under req-1: Action = %d, decision %+v; want it run", d.Action, d.Decision)
			}
			if got := h.p.Stats().HeldTrailsLeftOpen; got != want {
				t.Errorf("after the next call, Stats().HeldTrailsLeftOpen = %d; want %d", got, want)
			}
		})
	}
}

// reportExpired makes f hand back every record expired at base(), which is
// what a store answers about an approval whose window has passed.
func reportExpired(f *fakeStore) {
	f.found = func(a *controlv1.Approval) { a.ExpiresAt = timestamppb.New(base()) }
}
