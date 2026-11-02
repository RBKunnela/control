package gateway_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

// claimedApprovers are approver ids a store may answer with: plain claims the
// plane records, the longest of them at the approver id's bound, and ids it
// never takes from a store: one byte over that bound, and three that read as
// the reserved authn: prefix.
var claimedApprovers = []struct {
	id       string
	reserved bool
}{
	{"night-officer", false},
	{strings.Repeat("a", 128), false},
	{strings.Repeat("a", 129), true},
	{"authn:roster/x:mallory", true},
	{"AUTHN:roster/x:mallory", true},
	{"\u0430uthn:x", true},
}

// TestTheResumeHoldsTheStoresApproverToTheClaimRule: a store that spends the
// held approval and answers it as approved by an id the claim rule refuses
// runs nothing. The held trail closes with the plane's own approval, expired,
// and never records that id; the same answer naming a plain claim runs and
// records it, so the reserved prefix is what changes the outcome.
func TestTheResumeHoldsTheStoresApproverToTheClaimRule(t *testing.T) {
	for _, c := range claimedApprovers {
		t.Run(c.id, func(t *testing.T) {
			f := newFakeStore()
			h := withStore(t, f)
			holdApproved(t, h, f)
			f.answer = func(a *controlv1.Approval, err error) (*controlv1.Approval, error) {
				if err != nil {
					t.Fatalf("the genuine Consume failed: %v", err)
				}
				a.ApproverId = c.id
				return a, nil
			}
			d := h.admit(retry(t, "req-2"), refundArgs())
			trail := h.trailOf("req-1")
			if err := evidence.ValidateChain(trail); err != nil {
				t.Errorf("ValidateChain: %v", err)
			}
			if !c.reserved {
				if d.Action != core.Execute || recordedApprover(trail) != c.id {
					t.Fatalf("a plain claim: Action %d, APPROVAL_DECIDED by %q; want Execute by %q", d.Action, recordedApprover(trail), c.id)
				}
				return
			}
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
			if len(trail) == 5 {
				expectPlanesApprovalExpired(t, trail[2].GetApproval(), trail[3].GetApproval())
			}
			if s := h.p.Stats(); s.Executed != 0 || s.Held != 0 || s.Blocks[codeEvidenceUnavailable] != 1 {
				t.Errorf("Stats: %d executed, %d held, blocks %v", s.Executed, s.Held, s.Blocks)
			}
		})
	}
}

// TestARejectionByAReservedApproverIsNeverRecorded: a rejection the store
// answers under an id the claim rule refuses is not written as
// APPROVAL_DECIDED either; the window closes with the plane's own approval.
func TestARejectionByAReservedApproverIsNeverRecorded(t *testing.T) {
	f := newFakeStore()
	h := withStore(t, f)
	first := hold(t, h)
	if err := f.Answer(first.Pending.ApprovalID, rejected, "bob", "not today", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	f.answer = func(a *controlv1.Approval, err error) (*controlv1.Approval, error) {
		if !errors.Is(err, gateway.ErrApprovalRejected) || a == nil {
			t.Fatalf("the genuine Consume: %v, %v; want the rejected record", a, err)
		}
		a.ApproverId = "authn:roster/x:mallory"
		return a, err
	}
	d := h.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	trail := h.trailOf("req-1")
	expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
	if len(trail) == 5 {
		expectPlanesApprovalExpired(t, trail[2].GetApproval(), trail[3].GetApproval())
	}
}

// TestTheReconciliationHoldsTheStoresApproverToTheClaimRule: a lost hold whose
// record the store reports approved by an id the claim rule refuses closes
// APPROVAL_STATE_UNKNOWN with the plane's own approval, as a record a store
// refuses to read does, never APPROVAL_NOT_RESUMED naming that id. A plain
// claim closes APPROVAL_NOT_RESUMED.
func TestTheReconciliationHoldsTheStoresApproverToTheClaimRule(t *testing.T) {
	for _, c := range claimedApprovers {
		t.Run(c.id, func(t *testing.T) {
			store := newFakeStore()
			first, pending, next := lostUnder(t, store, base().Add(time.Minute), func(pending gateway.Disposition) {
				answeredThen(t, store, pending, func(a *controlv1.Approval) { a.ApproverId = c.id })
			})
			if !c.reserved {
				trail := expectClosedLostHold(t, first, kindApprovalDecided, verdictDeny, codeApprovalNotResumed)
				if got := trail[3].GetApproval().GetApproverId(); got != c.id {
					t.Errorf("APPROVAL_DECIDED names %q, want %q", got, c.id)
				}
				return
			}
			trail := expectClosedLostHold(t, first, kindApprovalExpired, verdictIndeterminate, codeApprovalStateUnknown)
			expectOwnApprovalExpired(t, trail, pending)
			if s := next.p.Stats(); s.Blocks[codeApprovalStateUnknown] != 1 || len(s.Blocks) != 1 || s.Executed != 0 {
				t.Errorf("Stats = %+v; want the one close counted as APPROVAL_STATE_UNKNOWN", s)
			}
		})
	}
}

// recordedApprover is the approver APPROVAL_DECIDED names on trail, or "".
func recordedApprover(trail []*controlv1.Event) string {
	for _, e := range trail {
		if e.GetKind() == kindApprovalDecided {
			return e.GetApproval().GetApproverId()
		}
	}
	return ""
}

// editingJournal hands back the entries it lists with their approval edited.
type editingJournal struct {
	*journalDouble
	edit func(*controlv1.Approval)
}

func (j editingJournal) List(ctx context.Context, most int) (gateway.HoldListing, error) {
	l, err := j.journalDouble.List(ctx, most)
	for _, e := range l.Held {
		j.edit(e.Approval)
	}
	return l, err
}

// TestAJournalEntryNotAsMintedIsNeverClosed: the plane closes a lost hold with
// the approval its journal entry carries, so an entry whose approval carries
// an approver, a decision time or a state other than pending is not one the
// plane minted. The pass counts it unreadable, writes nothing on its trail and
// asks the store nothing; the entry as written is closed.
func TestAJournalEntryNotAsMintedIsNeverClosed(t *testing.T) {
	for _, c := range []struct {
		name   string
		edit   func(*controlv1.Approval)
		closes bool
	}{
		{"as minted", func(*controlv1.Approval) {}, true},
		{"a reserved approver", func(a *controlv1.Approval) { a.ApproverId = "authn:roster/x:mallory" }, false},
		{"a plain approver", func(a *controlv1.Approval) { a.ApproverId = "night-officer" }, false},
		{"approved", func(a *controlv1.Approval) { a.State = approved }, false},
		{"decided", func(a *controlv1.Approval) { a.DecidedAt = a.GetRequestedAt() }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			snap := snapshot(t, approveRefunds)
			jd := &journalDouble{}
			store := newFakeStore()
			first := build(t, modeEnforce, snap, func(cfg *gateway.Config) {
				cfg.Journal = jd
				cfg.Approvals = store
			})
			hold(t, first)
			next := build(t, modeApprove, snap, func(cfg *gateway.Config) {
				cfg.Journal = editingJournal{journalDouble: jd, edit: c.edit}
				cfg.Approvals = store
				cfg.Sink = first.sink
				cfg.NewID = restartIDs()
			})
			next.clock.set(base().Add(time.Minute))
			r := next.p.Reconcile(context.Background())
			trail := first.trailOf("req-1")
			if c.closes {
				if r.Closed != 1 || r.Unreadable != 0 || len(trail) != 5 {
					t.Fatalf("the entry as minted: %+v, a trail of %d event(s); want it closed", r, len(trail))
				}
				return
			}
			if r.Closed != 0 || r.Unreadable != 1 || r.Complete {
				t.Errorf("Reconcile = %+v; want the entry counted unreadable and the pass incomplete", r)
			}
			expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
			if got := store.resolves.Load(); got != 0 {
				t.Errorf("the store was asked to resolve %d time(s)", got)
			}
		})
	}
}
