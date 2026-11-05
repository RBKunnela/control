package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/operators"
)

// signedRig is a plane under the signed kind over the standard roster, with
// one refund held.
func signedRig(t *testing.T, mut ...func(*gateway.Config)) (*harness, *answerBox, *controlv1.Approval) {
	t.Helper()
	box := newAnswerBox(gateway.AuthoritySigned)
	var h *harness
	w := newRosterWorld(t, func() time.Time { return clockOf(h) }, "roster-a", "roster-a", standardRoster(), "roster-a")
	h = build(t, modeEnforce, snapshot(t, approveRefunds), append([]func(*gateway.Config){signedTo(box, w)}, mut...)...)
	hold(t, h)
	h.clock.set(base().Add(2 * time.Minute))
	return h, box, requestedOf(t, h, "req-1")
}

// TestBobsAnswerResumesNothingAndAlicesOnce: bob operates another project and
// only reads this one, so his approval leaves the hold pending; alice's runs
// it once, under her authenticated id, and the next identical call is told
// the approval was used.
func TestBobsAnswerResumesNothingAndAlicesOnce(t *testing.T) {
	h, box, requested := signedRig(t)
	id := requested.GetApprovalId()
	box.file(id, signedBy(t, "bob", answerTo(requested, approvals.DecisionApprove, nil)))
	if d := h.admit(retry(t, "req-2"), refundArgs()); d.Action != core.AwaitApproval {
		t.Fatalf("bob's approval: Action = %d, decision %v", d.Action, d.Decision.GetReasonCodes())
	}
	if got := h.p.Stats().Answers[gateway.AnswerUnauthorized]; got != 1 {
		t.Errorf("Stats().Answers[unauthorized] = %d, want bob's one", got)
	}
	box.file(id, signedBy(t, "alice", answerTo(requested, approvals.DecisionApprove, nil)))
	run := h.admit(retry(t, "req-3"), refundArgs())
	if run.Action != core.Execute {
		t.Fatalf("alice's approval: Action = %d, decision %v", run.Action, run.Decision.GetReasonCodes())
	}
	var decided *controlv1.Approval
	for _, e := range h.trailOf("req-1") {
		if e.GetKind() == controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED {
			decided = e.GetApproval()
		}
	}
	if decided.GetApproverId() != "authn:roster/roster-a:alice" || decided.GetState() != approved || decided.GetReason() != "checked" {
		t.Errorf("APPROVAL_DECIDED carries %+v; want alice's authenticated approval", decided)
	}
	expectUsed(t, h, "req-4")
}

// TestSixteenConcurrentRetriesRunOnce: one signed approval, sixteen retries
// at once: exactly one runs.
func TestSixteenConcurrentRetriesRunOnce(t *testing.T) {
	h, box, requested := signedRig(t)
	box.file(requested.GetApprovalId(), signedBy(t, "alice", answerTo(requested, approvals.DecisionApprove, nil)))
	var wg sync.WaitGroup
	runs := make(chan gateway.Disposition, 16)
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runs <- h.admit(retry(t, fmt.Sprintf("req-r%02d", i)), refundArgs())
		}()
	}
	wg.Wait()
	close(runs)
	executed := 0
	for d := range runs {
		if d.Action == core.Execute {
			executed++
		}
	}
	if executed != 1 || h.spent() < 1 {
		t.Fatalf("%d of 16 retries ran, %d spend(s) asked; want exactly one run", executed, h.spent())
	}
}

// TestASignedSpendRecordsTheAuthenticatedApproverAndTheAnswer: the proof a
// spend records is the authenticated id and the digest of the answer it
// rests on, so two answers give two proofs; no store holds either.
func TestASignedSpendRecordsTheAuthenticatedApproverAndTheAnswer(t *testing.T) {
	var proofs []string
	for _, reason := range []string{"checked", "checked twice"} {
		h, box, requested := signedRig(t)
		box.file(requested.GetApprovalId(), signedBy(t, "alice", answerTo(requested, approvals.DecisionApprove, func(a *approvals.Answer) { a.Reason = reason })))
		if d := h.admit(retry(t, "req-2"), refundArgs()); d.Action != core.Execute {
			t.Fatalf("Action = %d", d.Action)
		}
		got := h.ledger.spentProofs()
		if len(got) != 1 {
			t.Fatalf("%d spend(s) recorded", len(got))
		}
		approver, digest, ok := strings.Cut(got[0], " ")
		hex, isDigest := strings.CutPrefix(digest, "sha256:")
		if !ok || approver != "authn:roster/roster-a:alice" || !isDigest || len(hex) != 64 {
			t.Fatalf("the proof is %q; want alice's authenticated id and a sha256 digest", got[0])
		}
		proofs = append(proofs, got[0])
	}
	if proofs[0] == proofs[1] {
		t.Errorf("two answers recorded one proof %q", proofs[0])
	}
}

// TestADecisionOutsideTheWindowIsNoAnswer: an answer decided before the hold
// was requested or after the clock is left out; one at the request's own
// instant runs.
func TestADecisionOutsideTheWindowIsNoAnswer(t *testing.T) {
	for name, at := range map[string]time.Duration{
		"before the request": -time.Nanosecond,
		"after the clock":    2*time.Minute + time.Nanosecond,
	} {
		t.Run(name, func(t *testing.T) {
			h, box, requested := signedRig(t)
			box.file(requested.GetApprovalId(), signedBy(t, "alice", answerTo(requested, approvals.DecisionApprove, func(a *approvals.Answer) {
				a.DecidedAt = requested.GetRequestedAt().AsTime().Add(at)
			})))
			if d := h.admit(retry(t, "req-2"), refundArgs()); d.Action == core.Execute {
				t.Fatal("an answer outside the window ran the call")
			}
			if got := h.p.Stats().Answers[gateway.AnswerWindow]; got != 1 {
				t.Errorf("Stats().Answers[window] = %d", got)
			}
		})
	}
	h, box, requested := signedRig(t)
	box.file(requested.GetApprovalId(), signedBy(t, "alice", answerTo(requested, approvals.DecisionApprove, func(a *approvals.Answer) {
		a.DecidedAt = requested.GetRequestedAt().AsTime()
	})))
	if d := h.admit(retry(t, "req-2"), refundArgs()); d.Action != core.Execute {
		t.Fatalf("an answer at the request's own instant: Action = %d", d.Action)
	}
}

// silentFor is an authorizer that answers nothing for one subject and leaves
// every other answer to the authorizer it wraps.
type silentFor struct {
	operators.Authorizer
	subject string
}

func (s silentFor) Authorize(ctx context.Context, who operators.Authentication, req operators.Request) operators.Permission {
	if who.Subject() == s.subject {
		return operators.Permission{}
	}
	return s.Authorizer.Authorize(ctx, who, req)
}

// TestAnAnswerNobodyCouldJudgeIsNeverNoRejection: carol's rejection beside
// alice's approval, with the authorizer silent about carol, blocks the call
// INDETERMINATE and leaves the hold; with the authorizer answering, the
// rejection wins. A batch the authority could not read is the same.
func TestAnAnswerNobodyCouldJudgeIsNeverNoRejection(t *testing.T) {
	for _, silent := range []bool{true, false} {
		h, box, requested := signedRig(t, func(cfg *gateway.Config) {
			if silent {
				cfg.Authorizer = silentFor{Authorizer: cfg.Authorizer, subject: "carol"}
			}
		})
		box.file(requested.GetApprovalId(), signedBy(t, "alice", answerTo(requested, approvals.DecisionApprove, nil)))
		box.file(requested.GetApprovalId(), signedBy(t, "carol", answerTo(requested, approvals.DecisionReject, nil)))
		d := h.admit(retry(t, "req-2"), refundArgs())
		if !silent {
			expectBlock(t, d, verdictDeny, codeApprovalRejected, gateway.PDPType)
			continue
		}
		expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		if trail := h.trailOf("req-1"); len(trail) != 3 {
			t.Errorf("the held trail holds %d events; the hold should stand", len(trail))
		}
		if got := h.p.Stats().Answers[gateway.AnswerAuthzUnavailable]; got != 1 {
			t.Errorf("Stats().Answers[authorization_unavailable] = %d", got)
		}
	}
	h, box, requested := signedRig(t)
	box.file(requested.GetApprovalId(), signedBy(t, "alice", answerTo(requested, approvals.DecisionApprove, nil)))
	box.setState(gateway.BatchUnavailable)
	expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	if got := h.p.Stats().Answers[gateway.AnswerBatchUnavailable]; got != 1 {
		t.Errorf("Stats().Answers[batch_unavailable] = %d", got)
	}
}

// TestNewRefusesAnAuthorityThatDoesNotFitItsKind: no authority, the signed
// kind without its ports, and the directory kind with them are refused; each
// kind with what it takes is accepted.
func TestNewRefusesAnAuthorityThatDoesNotFitItsKind(t *testing.T) {
	var clockAt = func() time.Time { return base() }
	w := newRosterWorld(t, clockAt, "roster-a", "roster-a", standardRoster(), "roster-a")
	for name, c := range map[string]struct {
		edit func(*gateway.Config)
		want error
	}{
		"no authority":                    {func(c *gateway.Config) { c.Authority = nil }, gateway.ErrNoAuthority},
		"another kind":                    {func(c *gateway.Config) { c.AuthorityKind = "file" }, gateway.ErrAuthorityKind},
		"signed with no authorizer":       {func(c *gateway.Config) { c.AuthorityKind, c.Authenticator = gateway.AuthoritySigned, w.authn }, gateway.ErrAuthorityConfig},
		"signed with no authenticator":    {func(c *gateway.Config) { c.AuthorityKind, c.Authorizer = gateway.AuthoritySigned, w.authz }, gateway.ErrAuthorityConfig},
		"directory with an authenticator": {func(c *gateway.Config) { c.Authenticator = w.authn }, gateway.ErrAuthorityConfig},
		"directory with an authorizer":    {func(c *gateway.Config) { c.Authorizer = w.authz }, gateway.ErrAuthorityConfig},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			c.edit(&cfg)
			if _, err := gateway.New(cfg); !errors.Is(err, c.want) {
				t.Fatalf("New = %v, want %v", err, c.want)
			}
		})
	}
	for name, edit := range map[string]func(*gateway.Config){
		"directory": func(*gateway.Config) {},
		"signed": func(c *gateway.Config) {
			c.AuthorityKind, c.Authenticator, c.Authorizer = gateway.AuthoritySigned, w.authn, w.authz
		},
	} {
		cfg := validConfig(t)
		edit(&cfg)
		if _, err := gateway.New(cfg); err != nil {
			t.Errorf("%s with its ports was refused: %v", name, err)
		}
	}
}

// TestASignedReconciliationSaysWhatTheRosterVouchesFor: after a restart the
// plane closes a lost hold with alice's authenticated approval, carol's
// rejection, and with nothing answered before the minted expiry, under
// either kind, the state unknown.
func TestASignedReconciliationSaysWhatTheRosterVouchesFor(t *testing.T) {
	for name, c := range map[string]struct {
		kind  gateway.AuthorityKind
		setup string
		code  string
	}{
		"signed, approved":       {gateway.AuthoritySigned, "alice", codeApprovalNotResumed},
		"signed, rejected":       {gateway.AuthoritySigned, "carol", codeApprovalRejected},
		"signed, nothing signed": {gateway.AuthoritySigned, "", codeApprovalStateUnknown},
		"directory, no record":   {gateway.AuthorityDirectory, "", codeApprovalStateUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			r := newAuthorityRig(t, c.kind, "")
			switch c.setup {
			case "alice":
				r.box.file(r.requested.GetApprovalId(), signedBy(t, "alice", answerTo(r.requested, approvals.DecisionApprove, nil)))
			case "carol":
				r.box.file(r.requested.GetApprovalId(), signedBy(t, "carol", answerTo(r.requested, approvals.DecisionReject, nil)))
			}
			r.expectReconciled(c.code)
			if c.setup == "alice" {
				trail := r.h.trailOf("req-1")
				if a := trail[3].GetApproval(); a.GetApproverId() != "authn:roster/roster-a:alice" {
					t.Errorf("the closing names approver %q", a.GetApproverId())
				}
			}
		})
	}
}

// TestARejectionOutsideItsWindowStillWins: carol's rejection decided after the
// clock, or before the request, beside alice's approval, closes the hold
// rejected; the same rejection by bob, who may not approve, leaves alice's
// approval to run.
func TestARejectionOutsideItsWindowStillWins(t *testing.T) {
	for name, at := range map[string]time.Duration{"ahead": 3 * time.Minute, "behind": -time.Second} {
		for rejector, wins := range map[string]bool{"carol": true, "bob": false} {
			t.Run(name+"/"+rejector, func(t *testing.T) {
				h, box, requested := signedRig(t)
				box.file(requested.GetApprovalId(), signedBy(t, rejector, answerTo(requested, approvals.DecisionReject, func(a *approvals.Answer) {
					a.DecidedAt = requested.GetRequestedAt().AsTime().Add(at)
				})))
				box.file(requested.GetApprovalId(), signedBy(t, "alice", answerTo(requested, approvals.DecisionApprove, nil)))
				d := h.admit(retry(t, "req-2"), refundArgs())
				if !wins {
					if d.Action != core.Execute {
						t.Fatalf("a rejection by an operator who may not approve stopped the call: %d %v", d.Action, d.Decision.GetReasonCodes())
					}
					return
				}
				expectBlock(t, d, verdictDeny, codeApprovalRejected, gateway.PDPType)
				trail := h.trailOf("req-1")
				decided := trail[3].GetApproval()
				requestedAt, decidedAt := requested.GetRequestedAt().AsTime(), decided.GetDecidedAt().AsTime()
				if decided.GetState() != rejected || decidedAt.Before(requestedAt) || decidedAt.After(base().Add(2*time.Minute)) {
					t.Errorf("APPROVAL_DECIDED carries %+v; want carol's rejection inside the window", decided)
				}
			})
		}
	}
}

// TestASpentLostHoldClosesFromItsMark: an approval spent before a crash left
// its entry held closes APPROVAL_NOT_RESUMED from the ledger's mark, though
// alice was revoked since and her answer no longer counts; without the mark
// the same restart says nothing it cannot judge, and closes it unknown.
func TestASpentLostHoldClosesFromItsMark(t *testing.T) {
	for spent, code := range map[bool]string{true: codeApprovalNotResumed, false: codeApprovalStateUnknown} {
		r := newAuthorityRig(t, gateway.AuthoritySigned, "")
		r.box.file(r.requested.GetApprovalId(), signedBy(t, "alice", answerTo(r.requested, approvals.DecisionApprove, nil)))
		if spent {
			if _, err := r.h.ledger.Spend(context.Background(), bindingOfHeld(t, r.requested), "req-1", r.requested.GetApprovalId(), "authn:roster/roster-a:alice", base().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
		r.world.write(t, "roster-a", 2, standardRoster()[1:])
		r.expectReconciledSpent(code, spent)
	}
}

// TestALostHoldOverAnUnreadableLedgerIsUnknown: a ledger that cannot be read
// may hold the spend, so a restart closes the hold unknown, whatever the
// authority answers; the same ledger read closes it from alice's approval.
func TestALostHoldOverAnUnreadableLedgerIsUnknown(t *testing.T) {
	for readable, code := range map[bool]string{false: codeApprovalStateUnknown, true: codeApprovalNotResumed} {
		r := newAuthorityRig(t, gateway.AuthorityDirectory, "")
		r.edited(nil, nil)
		if !readable {
			r.h.ledger.mu.Lock()
			r.h.ledger.lookupErr = errLedger
			r.h.ledger.mu.Unlock()
		}
		r.expectReconciled(code)
	}
}
