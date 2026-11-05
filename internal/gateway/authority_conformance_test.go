package gateway_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policykey"
)

const authorityCases = "../../testdata/ports/approval-authority/cases.json"

type authorityCase struct {
	Rule    string   `json:"rule"`
	Case    string   `json:"case"`
	Control bool     `json:"control"`
	Kinds   []string `json:"kinds"`
	Setup   string   `json:"setup"`
	Outcome string   `json:"outcome"`
	Code    string   `json:"code"`
	Cause   string   `json:"cause"`
}

func readAuthorityCases(t *testing.T) []authorityCase {
	t.Helper()
	raw, err := os.ReadFile(authorityCases)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Port   string          `json:"port"`
		Format string          `json:"format"`
		About  string          `json:"about"`
		Cases  []authorityCase `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		t.Fatal(err)
	}
	if file.Port != "approval-authority" || file.Format != "0.1" || len(file.Cases) == 0 {
		t.Fatalf("the file names port %q format %q with %d cases", file.Port, file.Format, len(file.Cases))
	}
	return file.Cases
}

// authorityRig is one case's plane: the hold it holds, the authority it
// files answers in, and the roster a signed case judges them over.
type authorityRig struct {
	t         *testing.T
	kind      gateway.AuthorityKind
	h         *harness
	box       *answerBox
	world     *rosterWorld
	journal   *gateway.MemoryHoldJournal
	requested *controlv1.Approval
	// order is the resource the retry names, the held refund's.
	order string
}

// TestEveryApprovalAuthorityCaseHolds runs each conformance case under each
// kind it lists, and the outcome it compares with is the file's.
func TestEveryApprovalAuthorityCaseHolds(t *testing.T) {
	for _, c := range readAuthorityCases(t) {
		if len(c.Kinds) == 0 {
			t.Fatalf("%s: %s lists no kind", c.Rule, c.Case)
		}
		for _, kind := range c.Kinds {
			t.Run(kind+"/"+c.Rule+"/"+c.Case, func(t *testing.T) {
				k, err := gateway.ParseAuthorityKind(kind)
				if err != nil {
					t.Fatal(err)
				}
				runAuthorityCase(t, k, c)
			})
		}
	}
}

func runAuthorityCase(t *testing.T, kind gateway.AuthorityKind, c authorityCase) {
	if c.Setup == "empty-kind" {
		cfg := validConfig(t)
		cfg.AuthorityKind = ""
		if _, err := gateway.New(cfg); !errors.Is(err, gateway.ErrAuthorityKind) || c.Outcome != "refused" {
			t.Fatalf("New with no kind: %v, the case wants %s", err, c.Outcome)
		}
		return
	}
	r := newAuthorityRig(t, kind, c.Setup)
	r.arrange(c.Setup)
	if c.Outcome == "reconciled" {
		r.expectReconciled(c.Code)
		return
	}
	r.h.clock.set(base().Add(2 * time.Minute))
	again := retry(t, "req-9")
	again.Resource.Id = r.order
	d := r.h.admit(again, refundArgs())
	if got := r.outcomeOf(d); got != c.Outcome {
		t.Fatalf("the retry came to %s (action %d, decision %s %v); the case wants %s",
			got, d.Action, d.Decision.GetVerdict(), d.Decision.GetReasonCodes(), c.Outcome)
	}
	if c.Outcome == "closed" {
		if codes := d.Decision.GetReasonCodes(); len(codes) == 0 || codes[0] != c.Code {
			t.Errorf("the held trail closed under %v; the case wants %s", codes, c.Code)
		}
	}
	if c.Cause != "" {
		if last := r.world.roster.Status(context.Background()).Last; string(last) != c.Cause {
			t.Errorf("the roster's last cause is %q; the case wants %q", last, c.Cause)
		}
	}
}

func newAuthorityRig(t *testing.T, kind gateway.AuthorityKind, setup string) *authorityRig {
	t.Helper()
	r := &authorityRig{t: t, kind: kind, box: newAnswerBox(kind), journal: &gateway.MemoryHoldJournal{}, order: "ord-1"}
	fileID, floorIDs := "roster-a", []string{"roster-a"}
	switch setup {
	case "other-roster":
		fileID, floorIDs = "roster-b", []string{"roster-a", "roster-b"}
	case "own-roster":
		floorIDs = []string{"roster-a", "roster-b"}
	}
	r.world = newRosterWorld(t, func() time.Time { return clockOf(r.h) }, "roster-a", fileID, standardRoster(), floorIDs...)
	wire := claimsTo(r.box)
	if kind == gateway.AuthoritySigned {
		wire = signedTo(r.box, r.world)
	}
	r.h = build(t, modeEnforce, snapshot(t, approveRefunds), wire, func(cfg *gateway.Config) { cfg.Journal = r.journal })
	first := hold(t, r.h)
	r.requested = requestedOf(t, r.h, "req-1")
	if r.requested.GetApprovalId() != first.Pending.ApprovalID {
		t.Fatalf("the trail announced %s and the agent was told %s", r.requested.GetApprovalId(), first.Pending.ApprovalID)
	}
	return r
}

// arrange files what setup names for the hold.
func (r *authorityRig) arrange(setup string) {
	do, ok := r.setups()[setup]
	if !ok {
		r.t.Fatalf("no setup %q", setup)
	}
	do()
}

// edited files alice's approval of the hold under the signed kind with edit
// applied, and her claim under the directory kind with claim applied.
func (r *authorityRig) edited(edit func(*approvals.Answer), claim func(*controlv1.Approval)) {
	id := r.requested.GetApprovalId()
	if r.kind == gateway.AuthoritySigned {
		r.box.file(id, signedBy(r.t, "alice", answerTo(r.requested, approvals.DecisionApprove, edit)))
		return
	}
	a := claimOf(r.requested, "alice")
	if claim != nil {
		claim(a)
	}
	r.box.claim(id, a)
}

// skewedRejection files name's rejection, decided after the retry's clock.
func (r *authorityRig) skewedRejection(name string) {
	r.box.file(r.requested.GetApprovalId(), signedBy(r.t, name, answerTo(r.requested, approvals.DecisionReject, func(a *approvals.Answer) {
		a.DecidedAt = base().Add(time.Hour)
	})))
}

// signedFrom files name's answer of decision to the hold.
func (r *authorityRig) signedFrom(name, decision string) {
	r.box.file(r.requested.GetApprovalId(), signedBy(r.t, name, answerTo(r.requested, decision, nil)))
}

func (r *authorityRig) setups() map[string]func() {
	t, id := r.t, r.requested.GetApprovalId()
	other := "sha256:" + string(bytes.Repeat([]byte("e"), 64))
	alice := func() { r.edited(nil, nil) }
	return map[string]func(){
		"alice": alice, "own-roster": alice, "other-roster": alice, "whole-restart": alice,
		"tenant":  func() { r.edited(func(a *approvals.Answer) { a.Tenant = "tenant-2" }, nil) },
		"project": func() { r.edited(func(a *approvals.Answer) { a.Project = "proj-2" }, nil) },
		"approval": func() {
			r.edited(func(a *approvals.Answer) { a.ApprovalID = "apr-other" }, func(a *controlv1.Approval) { a.ApprovalId = "apr-other" })
		},
		"request": func() {
			r.edited(func(a *approvals.Answer) { a.RequestID = "req-other" }, func(a *controlv1.Approval) { a.RequestId = "req-other" })
		},
		"digest": func() {
			r.edited(func(a *approvals.Answer) { a.ActionDigest = other }, func(a *controlv1.Approval) { a.ActionDigest = other })
		},
		"bundle": func() {
			r.edited(func(a *approvals.Answer) { a.BundleDigest = other }, func(a *controlv1.Approval) { a.PolicyBundleDigest = other })
		},
		"bob": func() { r.signedFrom("bob", approvals.DecisionApprove) },
		"plane-key": func() {
			plane := key()
			r.box.file(id, signedWith(t, plane, policykey.KeyID(plane.Public().(ed25519.PublicKey)), answerTo(r.requested, approvals.DecisionApprove, nil)))
		},
		"unsigned": func() {
			env := signedBy(t, "alice", answerTo(r.requested, approvals.DecisionApprove, nil))
			env.Signatures = nil
			r.box.file(id, env)
		},
		"authn-claim":     func() { r.box.claim(id, claimOf(r.requested, "authn:roster/roster-a:alice")) },
		"race":            func() { alice(); r.signedFrom("carol", approvals.DecisionReject) },
		"race-bob":        func() { alice(); r.signedFrom("bob", approvals.DecisionReject) },
		"race-skewed":     func() { alice(); r.skewedRejection("carol") },
		"race-bob-skewed": func() { alice(); r.skewedRejection("bob") },
		"revoked":         func() { alice(); r.world.write(t, "roster-a", 2, standardRoster()[1:]) },
		"renewed":         func() { alice(); r.world.write(t, "roster-a", 2, standardRoster()) },
		"second-hold": func() {
			first := r.requested
			r.box.file(r.secondHold(), signedBy(t, "alice", answerTo(first, approvals.DecisionApprove, nil)))
		},
		"second-hold-own": func() {
			second := r.secondHold()
			r.box.file(second, signedBy(t, "alice", answerTo(r.requested, approvals.DecisionApprove, nil)))
		},
		"truncated":         func() { alice(); r.box.setState(gateway.BatchTruncated) },
		"truncated-restart": func() { alice(); r.box.setState(gateway.BatchTruncated) },
	}
}

// secondHold holds a second refund, of another order and so of another
// digest, and points the retry at it; it returns its approval id.
func (r *authorityRig) secondHold() string {
	t := r.t
	env := refundEnvelope(t, refundArgs())
	env.RequestId, env.Resource.Id = "req-2", "ord-2"
	d := r.h.admit(env, refundArgs())
	if d.Action != core.AwaitApproval || d.Pending == nil {
		t.Fatalf("the second refund: Action = %d", d.Action)
	}
	r.requested, r.order = requestedOf(t, r.h, "req-2"), "ord-2"
	return d.Pending.ApprovalID
}

// outcomeOf names what a retry came to, from the disposition and the held
// trail.
func (r *authorityRig) outcomeOf(d gateway.Disposition) string {
	held := r.h.trailOf(r.requested.GetRequestId())
	closed := len(held) > 0 && held[len(held)-1].GetKind() == kindBlocked
	codes := d.Decision.GetReasonCodes()
	switch {
	case d.Action == core.Execute:
		return "runs"
	case d.Action == core.AwaitApproval:
		return "pending"
	case closed && len(codes) > 0 && codes[0] == codeApprovalRejected:
		return "rejected"
	case closed:
		return "closed"
	case d.Decision.GetVerdict() == verdictIndeterminate:
		return "indeterminate"
	}
	return "other"
}

// expectReconciled brings a plane back to the hold's journal and evidence,
// over the same authority, and holds the closing to code.
func (r *authorityRig) expectReconciled(code string) {
	t := r.t
	wire := claimsTo(r.box)
	if r.kind == gateway.AuthoritySigned {
		wire = signedTo(r.box, r.world)
	}
	next := build(t, modeEnforce, snapshot(t, approveRefunds), wire, func(cfg *gateway.Config) {
		cfg.Journal, cfg.Approvals, cfg.Ledger, cfg.Sink, cfg.NewID = r.journal, r.h.store, r.h.ledger, r.h.sink, restartIDs()
	})
	next.clock.set(base().Add(2 * time.Minute))
	if rec := next.p.Reconcile(context.Background()); rec.Closed != 1 {
		t.Fatalf("Reconcile = %+v; want the one hold closed", rec)
	}
	trail := r.h.trailOf("req-1")
	last := trail[len(trail)-1]
	if last.GetKind() != kindBlocked || len(last.GetDecision().GetReasonCodes()) == 0 || last.GetDecision().GetReasonCodes()[0] != code {
		t.Fatalf("the reconciled trail ends %s %v; want ACTION_BLOCKED under %s", last.GetKind(), last.GetDecision().GetReasonCodes(), code)
	}
	if r.h.spent() != 0 {
		t.Errorf("the reconciliation spent %d approval(s)", r.h.spent())
	}
}

// expectReconciledSpent is expectReconciled for a hold whose approval the
// test may have spent itself.
func (r *authorityRig) expectReconciledSpent(code string, spent bool) {
	want := 0
	if spent {
		want = 1
	}
	before := r.h.spent()
	if before != want {
		r.t.Fatalf("the ledger was asked %d spend(s) before the restart, want %d", before, want)
	}
	r.h.ledger.mu.Lock()
	r.h.ledger.spends = 0
	r.h.ledger.mu.Unlock()
	r.expectReconciled(code)
}
