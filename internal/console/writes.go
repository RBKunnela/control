package console

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/keytext"
	"github.com/guardana/control/internal/pause"
)

// pauseLockWait bounds how long a pause write waits for another writer's
// lock, as the pause commands wait.
const pauseLockWait = 10 * time.Second

// answerBody is one answer. ActionDigest is the digest the approver was shown
// when they confirmed, and the answer is filed only for the record that
// carries it.
type answerBody struct {
	ID           string `json:"id"`
	Reason       string `json:"reason"`
	ActionDigest string `json:"action_digest"`
}

type pauseBody struct {
	Scope  scopeReply `json:"scope"`
	Reason string     `json:"reason"`
}

type unpauseBody struct {
	ID string `json:"id"`
}

// answerReply is a filed answer. PlaneRunning false means nothing is waiting
// for it: the call it was held for will not run. Notice is what the page
// says about it, one sentence a line.
type answerReply struct {
	ApprovalID   string   `json:"approval_id"`
	Answer       string   `json:"answer"`
	PlaneRunning bool     `json:"plane_running"`
	Notice       []string `json:"notice"`
}

// noPlane is what an answer filed while no plane holds the directory comes to.
var noPlane = []string{
	"No plane holds this directory, so nothing is waiting for this answer.",
	"The call this approval was held for will not run: a hold does not survive the plane stopping.",
	"The answer is written to the directory all the same.",
	"A plane that keeps a hold journal records it on that call's trail, as a decision that came too late to resume it.",
}

// digestMismatch is the refusal of an answer whose digest is not the record's.
const digestMismatch = "the action digest sent is not this approval's, so nothing was written; " +
	"reload the page and read the call again before answering"

func (p *page) approve(w http.ResponseWriter, r *http.Request, body any) {
	p.answer(w, r, body.(*answerBody), controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approved")
}

func (p *page) reject(w http.ResponseWriter, r *http.Request, body any) {
	p.answer(w, r, body.(*answerBody), controlv1.ApprovalState_APPROVAL_STATE_REJECTED, "rejected")
}

// answer files one answer under the starter's approver id, at the page's
// clock, as the approvals commands do, and only for the record whose action
// digest the approver confirmed. The store never changes a record's digest
// once it is held, so the record compared is the record answered.
func (p *page) answer(w http.ResponseWriter, r *http.Request, b *answerBody, state controlv1.ApprovalState, word string) {
	rec, err := p.recordFor(r.Context(), b.ID)
	if err != nil {
		refuseStore(w, err)
		return
	}
	if b.ActionDigest != rec.Approval.GetActionDigest() {
		refuse(w, http.StatusConflict, digestMismatch)
		return
	}
	if !p.mayClaim(rec) {
		refuse(w, http.StatusConflict, p.noClaim(rec))
		return
	}
	done, err := p.o.Approvals.Answer(r.Context(), b.ID, state, p.o.ApproverID, b.Reason, p.now())
	if err != nil {
		refuseStore(w, err)
		return
	}
	reply(w, http.StatusOK, answerReply{
		ApprovalID: b.ID, Answer: word, PlaneRunning: done.PlaneRunning,
		Notice: answerNotice(b.ID, word, done.PlaneRunning),
	})
}

// unlisted is the refusal of an id an incomplete listing does not name: the
// record may be past the store's bound, so whether it is held is unknown.
const unlisted = "the listing of the directory was incomplete and does not name this approval, " +
	"so whether it is held is unknown and nothing was written"

// recordFor reads the record listed under approvalID, so no answer is filed
// without a digest to compare and an authority to judge. An id the store
// cannot hold, and one the listing names among its problems, are refused as
// the store words it; an id a complete listing does not name is no approval,
// and one an incomplete listing does not name is unknown.
func (p *page) recordFor(ctx context.Context, approvalID string) (approvals.Record, error) {
	if err := approvals.CheckApprovalID(approvalID); err != nil {
		return approvals.Record{}, err
	}
	l, err := p.list(ctx)
	if err != nil {
		return approvals.Record{}, err
	}
	for _, e := range l.Entries {
		if e.Record.ApprovalID == approvalID {
			return e.Record, nil
		}
	}
	// A record's names are its id and a suffix after a dot, which no id holds.
	for _, pr := range l.Problems {
		if strings.HasPrefix(pr.Name, approvalID+".") {
			return approvals.Record{}, listedProblem{pr.Err}
		}
	}
	if !l.Complete {
		return approvals.Record{}, listedProblem{errors.New(unlisted)}
	}
	return approvals.Record{}, approvals.ErrNoApproval
}

// noClaim is the refusal of an answer this page may not file: a hold under
// the signed authority names the commands that sign it, and a page over the
// reader files no claim at all.
func (p *page) noClaim(rec approvals.Record) string {
	if rec.HeldUnder() == approvals.HeldUnderSigned {
		return "this approval is held under the signed authority, and this page holds no operator key, so nothing was written; " +
			"sign the answer with: " + strings.Join(p.signCommands(rec.ApprovalID), " or ")
	}
	return "this page was started for signed answers and files no claim, so nothing was written; " +
		"answer it with " + brand.CLI + " approvals approve --approver-id <id> as the plane's account"
}

// listedProblem is what the listing says against an answer: what is wrong
// with a record it names among its problems, or that it was incomplete and
// did not name the record. An answer to it conflicts with what is on disk
// whether the store or the system said so, a file the page cannot open among
// them.
type listedProblem struct{ err error }

func (e listedProblem) Error() string { return e.err.Error() }

func (e listedProblem) Unwrap() error { return e.err }

// answerNotice says what a filed answer comes to.
func answerNotice(id, word string, planeRunning bool) []string {
	lines := []string{"Approval " + keytext.Printable(id) + ": " + word + "."}
	switch {
	case !planeRunning:
		lines = append(lines, noPlane...)
	case word == "approved":
		lines = append(lines, "The call can resume on the agent's retry before the approval expires.")
	}
	return lines
}

// pause adds one entry under an id it draws itself, as pause add does, and
// answers with that id.
func (p *page) pause(w http.ResponseWriter, r *http.Request, body any) {
	if p.o.PauseFile == "" {
		refuse(w, http.StatusNotFound, "this page was started without a pause file")
		return
	}
	b := body.(*pauseBody)
	e := pause.Entry{
		ID:        rand.Text(),
		Scope:     pause.Scope{Kind: pause.ScopeKind(b.Scope.Kind), Provider: b.Scope.Provider, Action: b.Scope.Action, Name: b.Scope.Name, ID: b.Scope.ID},
		CreatedAt: p.now().UTC(),
		Reason:    b.Reason,
	}
	if err := e.Check(); err != nil {
		refuse(w, http.StatusBadRequest, "the entry: "+err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), pauseLockWait)
	defer cancel()
	if err := pause.Add(ctx, p.o.PauseFile, e); err != nil {
		refuseStore(w, err)
		return
	}
	reply(w, http.StatusOK, struct {
		ID     string `json:"id"`
		Notice string `json:"notice"`
	}{e.ID, keytext.Printable("Paused " + scopeText(b.Scope) + ".")})
}

func (p *page) unpause(w http.ResponseWriter, r *http.Request, body any) {
	if p.o.PauseFile == "" {
		refuse(w, http.StatusNotFound, "this page was started without a pause file")
		return
	}
	b := body.(*unpauseBody)
	ctx, cancel := context.WithTimeout(r.Context(), pauseLockWait)
	defer cancel()
	if err := pause.Remove(ctx, p.o.PauseFile, b.ID); err != nil {
		refuseStore(w, err)
		return
	}
	reply(w, http.StatusOK, struct {
		ID     string `json:"id"`
		Notice string `json:"notice"`
	}{b.ID, "Lifted pause " + keytext.Printable(b.ID) + "."})
}

// refuseStore answers a refusal of the store or the pause file with its own
// sentence: a refusal either package names, and one the listing makes, is a
// conflict with what is on disk, and anything else
// is the page failing to reach it.
func refuseStore(w http.ResponseWriter, err error) {
	var ae approvals.Error
	var pe pause.Error
	var lp listedProblem
	if errors.As(err, &ae) || errors.As(err, &pe) || errors.As(err, &lp) {
		refuse(w, http.StatusConflict, err.Error())
		return
	}
	refuse(w, http.StatusInternalServerError, err.Error())
}
