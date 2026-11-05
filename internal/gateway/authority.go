package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/trust"
)

// ApprovalAuthority is the approval authority port: everything answered about
// one held approval, which the plane judges itself. An authority vouches for
// nothing it hands back; the plane authenticates, compares and authorizes
// every answer before any of it counts.
type ApprovalAuthority interface {
	// Answers returns the answers filed for approvalID. A batch it could not
	// read whole is unavailable or truncated, never complete.
	Answers(ctx context.Context, approvalID string) AnswerBatch
	// Status is what doctor and the health page show of the authority.
	Status(ctx context.Context) AuthorityStatus
}

// BatchState says how much of what was answered a batch holds. The zero
// value is BatchUnavailable, so a batch nobody filled in says nothing.
type BatchState uint8

// The batch states.
const (
	// BatchUnavailable is an authority that could not be read.
	BatchUnavailable BatchState = iota
	// BatchComplete is every answer filed for the approval.
	BatchComplete
	// BatchTruncated is a batch a bound stopped. It is read as unavailable:
	// what it left out may be the rejection that wins.
	BatchTruncated
)

// AnswerBatch is what an authority returns about one approval: signed
// answers under the signed kind, claims under the directory kind.
type AnswerBatch struct {
	State   BatchState
	Signed  []trust.Envelope
	Claimed []*controlv1.Approval
}

// AuthorityKind is how a plane takes an approver's answer. It is a closed
// set with no default.
type AuthorityKind string

// The kinds.
const (
	// AuthorityDirectory takes a claim from a directory an approver writes:
	// write access to it is the authority, and the approver id is an
	// unauthenticated claim.
	AuthorityDirectory AuthorityKind = "directory"
	// AuthoritySigned takes only an answer an operator of the trust roster
	// signed, whose grants let that operator approve the hold's project.
	AuthoritySigned AuthorityKind = "signed"
)

// ParseAuthorityKind reads a configured kind. The empty kind is refused: no
// kind is taken by default.
func ParseAuthorityKind(s string) (AuthorityKind, error) {
	switch k := AuthorityKind(s); k {
	case AuthorityDirectory, AuthoritySigned:
		return k, nil
	}
	return "", fmt.Errorf("%w: %q", ErrAuthorityKind, s)
}

// AuthorityHealth says whether an authority can be read now. The zero value
// is AuthorityUnavailable.
type AuthorityHealth uint8

// The health states.
const (
	AuthorityUnavailable AuthorityHealth = iota
	AuthorityUsable
)

// AuthorityStatus is an authority's kind, whether it can be read, and how
// often each cause of a refused answer or read was met.
type AuthorityStatus struct {
	Kind   AuthorityKind
	Health AuthorityHealth
	Counts map[string]uint64
}

// The causes the plane counts in Stats.Answers, one per answer or batch it
// did not take.
const (
	AnswerBatchUnavailable = "batch_unavailable"
	AnswerBatchTruncated   = "batch_truncated"
	AnswerUnauthenticated  = "unauthenticated"
	AnswerAuthnUnavailable = "authentication_unavailable"
	AnswerBody             = "body"
	AnswerOtherHold        = "other_hold"
	AnswerWindow           = "decided_outside_window"
	AnswerUnauthorized     = "unauthorized"
	AnswerAuthzUnavailable = "authorization_unavailable"
	AnswerApproverID       = "approver_id"
	AnswerClaimIgnored     = "claim_ignored"
)

// AnswerCauses is every cause Stats.Answers counts, in a fixed order.
func AnswerCauses() []string {
	return []string{
		AnswerBatchUnavailable, AnswerBatchTruncated, AnswerUnauthenticated, AnswerAuthnUnavailable, AnswerBody,
		AnswerOtherHold, AnswerWindow, AnswerUnauthorized, AnswerAuthzUnavailable, AnswerApproverID, AnswerClaimIgnored,
	}
}

// heldFacts is the plane's own record of a hold, which every answer about
// it is compared with.
type heldFacts struct {
	ids      evidence.IDs
	approval *controlv1.Approval
	expires  time.Time
}

func (r *heldRequest) facts() heldFacts {
	return heldFacts{ids: r.ids, approval: r.approval, expires: r.expires}
}

// judged is what the plane makes of the answers about one hold. With
// readable false the authority or a port an answer needed could not say,
// so the hold stays and the call is INDETERMINATE. approval is the answer
// the plane goes on to judge as it judges any, and nil where nothing was
// answered that it stands behind; proof is what a spend of it records.
type judged struct {
	readable bool
	approval *controlv1.Approval
	proof    string
}

// answerFor asks the authority about h and judges what comes back by the
// plane's kind.
func (p *Pipeline) answerFor(ctx context.Context, h heldFacts, now time.Time) judged {
	batch := p.cfg.Authority.Answers(ctx, h.approval.GetApprovalId())
	switch batch.State {
	case BatchComplete:
	case BatchTruncated:
		p.counts.answerRefused(AnswerBatchTruncated)
		return judged{}
	default:
		p.counts.answerRefused(AnswerBatchUnavailable)
		return judged{}
	}
	if p.cfg.AuthorityKind == AuthoritySigned {
		for range batch.Claimed {
			p.counts.answerRefused(AnswerClaimIgnored)
		}
		return p.judgeSigned(ctx, h, batch.Signed, now)
	}
	return claimed(h, batch.Claimed)
}

// claimed is the directory kind's answer: the one claim filed under the
// request id and the approval id the plane minted, judged later field by
// field. Two such claims, one in a state this
// build does not name, or one in no state at all, are not an answer the plane
// can judge.
func claimed(h heldFacts, claims []*controlv1.Approval) judged {
	var answer *controlv1.Approval
	for _, a := range claims {
		if a.GetRequestId() != h.approval.GetRequestId() || a.GetApprovalId() != h.approval.GetApprovalId() {
			continue
		}
		_, named := controlv1.ApprovalState_name[int32(a.GetState())]
		if answer != nil || !named || a.GetState() == controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED {
			return judged{}
		}
		answer = a
	}
	return judged{readable: true, approval: answer, proof: answer.GetApproverId()}
}

// judgeSigned is the signed kind's fold. Each answer is authenticated, read,
// compared member by member with the hold, and authorized for the hold's own
// tenant and project at the grant that approves; one that fails any step is
// counted and left out, save a rejection decided outside the window, which
// is authorized like any. A valid rejection wins over every approval. Where an
// answer could not be judged for want of the roster or the authorizer, and no
// valid rejection was found, the fold cannot say there is none, so it is
// unreadable.
func (p *Pipeline) judgeSigned(ctx context.Context, h heldFacts, signed []trust.Envelope, now time.Time) judged {
	var approve *judged
	unknown := false
	for _, env := range signed {
		j, decision, known := p.judgeEnvelope(ctx, h, env, now)
		switch {
		case !known:
			unknown = true
		case j == nil:
		case decision == approvals.DecisionReject:
			return *j
		case approve == nil:
			approve = j
		}
	}
	switch {
	case unknown:
		return judged{}
	case approve != nil:
		return *approve
	}
	return judged{readable: true}
}

// judgeEnvelope takes one signed answer through the four steps in order and
// returns what it answered, or nil where a step refused it. known is false
// where a step could not answer at all.
func (p *Pipeline) judgeEnvelope(ctx context.Context, h heldFacts, env trust.Envelope, now time.Time) (*judged, string, bool) {
	who := p.cfg.Authenticator.Authenticate(ctx, operators.ActApprove, env)
	switch who.State() {
	case operators.AuthAuthenticated:
	case operators.AuthRefused:
		p.counts.answerRefused(AnswerUnauthenticated)
		return nil, "", true
	default:
		p.counts.answerRefused(AnswerAuthnUnavailable)
		return nil, "", false
	}
	body, err := approvals.ReadAnswer(who.Body())
	if err != nil {
		p.counts.answerRefused(AnswerBody)
		return nil, "", true
	}
	cause := compareWithHold(h, body, now)
	skewed := cause == AnswerWindow && body.Decision == approvals.DecisionReject
	if cause != "" && !skewed {
		p.counts.answerRefused(cause)
		return nil, "", true
	}
	perm := p.cfg.Authorizer.Authorize(ctx, who, operators.Request{
		Act: operators.ActApprove, Tenant: h.ids.TenantID, Project: h.ids.ProjectID,
	})
	switch perm.State() {
	case operators.PermPermitted:
	case operators.PermDenied:
		p.counts.answerRefused(AnswerUnauthorized)
		return nil, "", true
	default:
		p.counts.answerRefused(AnswerAuthzUnavailable)
		return nil, "", false
	}
	approver, err := approval.AuthenticatedApproverID(who.Issuer(), who.Subject())
	if err != nil {
		// An operator the roster vouches for whose id cannot be spelled may
		// still have rejected.
		p.counts.answerRefused(AnswerApproverID)
		return nil, "", false
	}
	if skewed {
		// A rejection is never left out for its signer's clock: it wins, at
		// the edge of the window it falls outside.
		p.counts.answerRefused(AnswerWindow)
		body.DecidedAt = clamp(body.DecidedAt, h.approval.GetRequestedAt().AsTime(), now)
	}
	a := proto.CloneOf(h.approval)
	a.State = approvalApproved
	if body.Decision == approvals.DecisionReject {
		a.State = approvalRejected
	}
	a.ApproverId, a.Reason, a.DecidedAt = approver, body.Reason, timestampOf(body.DecidedAt)
	return &judged{readable: true, approval: a, proof: approver + " " + envelopeDigest(env)}, body.Decision, true
}

func clamp(t, from, to time.Time) time.Time {
	switch {
	case t.Before(from):
		return from
	case t.After(to):
		return to
	}
	return t
}

// compareWithHold names the first member of body that is not the hold's
// own, or a decision time before the request or after now, and "" when every
// one agrees. An expiry is the approval's to judge, as any answer's is.
func compareWithHold(h heldFacts, body approvals.Answer, now time.Time) string {
	a := h.approval
	switch {
	case body.Tenant != h.ids.TenantID, body.Project != h.ids.ProjectID,
		body.RequestID != a.GetRequestId(), body.ApprovalID != a.GetApprovalId(),
		body.ActionDigest != a.GetActionDigest(), body.BundleDigest != a.GetPolicyBundleDigest():
		return AnswerOtherHold
	case body.DecidedAt.Before(a.GetRequestedAt().AsTime()), body.DecidedAt.After(now):
		return AnswerWindow
	}
	return ""
}

// envelopeDigest names one signed answer: the SHA-256 of its payload type,
// its body and its signature, each length-prefixed, so a spend records which
// statement it rests on.
func envelopeDigest(env trust.Envelope) string {
	h := sha256.New()
	for _, part := range [][]byte{[]byte(env.PayloadType), env.Payload, signatureOf(env)} {
		_, _ = fmt.Fprintf(h, "%d:", len(part))
		_, _ = h.Write(part)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func signatureOf(env trust.Envelope) []byte {
	if len(env.Signatures) == 0 {
		return nil
	}
	return env.Signatures[0].Signature
}

// answerRefused counts an answer or a batch the plane did not take.
func (c *counters) answerRefused(cause string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stats.Answers == nil {
		c.stats.Answers = make(map[string]uint64)
	}
	c.stats.Answers[cause]++
}

// checkAuthority refuses an authority New could not judge answers from: none
// at all, a kind outside the closed set, the empty kind among them, and the
// ports the kind needs missing or the ports it does not read set.
func checkAuthority(cfg Config) error {
	if cfg.Authority == nil {
		return ErrNoAuthority
	}
	if _, err := ParseAuthorityKind(string(cfg.AuthorityKind)); err != nil {
		return err
	}
	operatorPorts := cfg.Authenticator != nil || cfg.Authorizer != nil
	switch {
	case cfg.AuthorityKind == AuthoritySigned && (cfg.Authenticator == nil || cfg.Authorizer == nil):
		return fmt.Errorf("%w: the signed kind needs an authenticator and an authorizer", ErrAuthorityConfig)
	case cfg.AuthorityKind == AuthorityDirectory && operatorPorts:
		return fmt.Errorf("%w: the directory kind authenticates nobody, so it takes no authenticator or authorizer", ErrAuthorityConfig)
	}
	return nil
}
