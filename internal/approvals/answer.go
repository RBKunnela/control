package approvals

import (
	"bytes"
	"fmt"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/pkg/contract"
)

// AnswerKind is the kind a signed approval answer names. A body of any other
// kind is refused whole: a reader that guessed at another version's members
// would compare the hold against fields it does not understand.
const AnswerKind = "approval-answer/v1alpha1"

// The decisions an answer takes.
const (
	DecisionApprove = "approve"
	DecisionReject  = "reject"
)

// MaxAnswerIDBytes bounds a tenant, a project and a request id in an answer.
const MaxAnswerIDBytes = 256

// Answer is the body of a signed approval answer, as an operator signs it
// under operators.AnswerPayloadType: what the answer is about, member for
// member the hold the plane keeps, and what the operator decided. Nothing in
// it is trusted until the signature verified and the plane compared every
// member with its own record of the hold.
type Answer struct {
	Alg          string
	KeyID        string
	Tenant       string
	Project      string
	RequestID    string
	ApprovalID   string
	ActionDigest string
	BundleDigest string
	Decision     string
	DecidedAt    time.Time
	Reason       string
}

// answerMembers is every member of the body, each required.
var answerMembers = []string{
	"kind", "alg", "keyId", "tenant", "project", "requestId", "approvalId",
	"actionDigest", "bundleDigest", "decision", "decidedAt", "reason",
}

// ReadAnswer reads body strictly: one canonical JSON object holding every
// member of the format and no other, each a string, kind AnswerKind, the
// decision approve or reject, decidedAt an RFC 3339 instant in UTC spelled as
// MarshalAnswer spells it, the ids within their bounds and the identifier
// rule, the digests sha256 digests, and the reason within MaxReasonBytes with
// no control character. It judges nothing about a hold.
func ReadAnswer(body []byte) (Answer, error) {
	if len(body) > MaxAnswerBodyBytes {
		return Answer{}, fmt.Errorf("%w: %d bytes, limit %d", ErrAnswerFormat, len(body), MaxAnswerBodyBytes)
	}
	canonical, err := canon.CanonicalizeJSON(body)
	if err != nil || !bytes.Equal(canonical, body) {
		return Answer{}, fmt.Errorf("%w: the body is not its own canonical form", ErrAnswerFormat)
	}
	members, err := strictjson.ReadObject(body)
	if err != nil {
		return Answer{}, fmt.Errorf("%w: %w", ErrAnswerFormat, err)
	}
	if err := members.Only(answerMembers...); err != nil {
		return Answer{}, fmt.Errorf("%w: %w", ErrAnswerFormat, err)
	}
	if err := members.Require(answerMembers...); err != nil {
		return Answer{}, fmt.Errorf("%w: %w", ErrAnswerFormat, err)
	}
	text := make(map[string]string, len(answerMembers))
	for _, name := range answerMembers {
		s, ok := strictjson.String(members[name])
		if !ok {
			return Answer{}, fmt.Errorf("%w: %s is not a string", ErrAnswerFormat, name)
		}
		text[name] = s
	}
	if text["kind"] != AnswerKind {
		return Answer{}, fmt.Errorf("%w: the kind is not %s", ErrAnswerKind, AnswerKind)
	}
	a := Answer{
		Alg: text["alg"], KeyID: text["keyId"], Tenant: text["tenant"], Project: text["project"],
		RequestID: text["requestId"], ApprovalID: text["approvalId"], ActionDigest: text["actionDigest"],
		BundleDigest: text["bundleDigest"], Decision: text["decision"], Reason: text["reason"],
	}
	decided, err := readInstant(text["decidedAt"])
	if err != nil {
		return Answer{}, err
	}
	a.DecidedAt = decided
	if err := a.check(); err != nil {
		return Answer{}, err
	}
	return a, nil
}

// MarshalAnswer is the canonical body of a, refused where ReadAnswer would
// not read it back.
func MarshalAnswer(a Answer) ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if a.DecidedAt.IsZero() {
		return nil, fmt.Errorf("%w: no decision time", ErrAnswerFormat)
	}
	body, err := canon.Canonicalize(map[string]any{
		"kind": AnswerKind, "alg": a.Alg, "keyId": a.KeyID, "tenant": a.Tenant, "project": a.Project,
		"requestId": a.RequestID, "approvalId": a.ApprovalID, "actionDigest": a.ActionDigest,
		"bundleDigest": a.BundleDigest, "decision": a.Decision,
		"decidedAt": a.DecidedAt.UTC().Format(time.RFC3339Nano), "reason": a.Reason,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAnswerFormat, err)
	}
	if _, err := ReadAnswer(body); err != nil {
		return nil, err
	}
	return body, nil
}

// MaxAnswerBodyBytes bounds an answer's body; it is the authenticator's own
// bound on a statement.
const MaxAnswerBodyBytes = 16384

// check holds every member but the time to its rule.
func (a Answer) check() error {
	switch {
	case a.Alg == "" || a.KeyID == "":
		return fmt.Errorf("%w: alg and keyId name the signing key", ErrAnswerFormat)
	case a.Decision != DecisionApprove && a.Decision != DecisionReject:
		return fmt.Errorf("%w: the decision is %s or %s", ErrAnswerFormat, DecisionApprove, DecisionReject)
	case !canon.ValidDigest(a.ActionDigest) || !canon.ValidDigest(a.BundleDigest):
		return fmt.Errorf("%w: a digest is sha256: and 64 lower-case hex digits", ErrAnswerFormat)
	}
	if err := a.checkIDs(); err != nil {
		return err
	}
	if err := checkApprovalID(a.ApprovalID); err != nil {
		return fmt.Errorf("%w: approvalId: %w", ErrAnswerFormat, err)
	}
	if err := checkReason(a.Reason); err != nil {
		return fmt.Errorf("%w: %w", ErrAnswerFormat, err)
	}
	return nil
}

// checkIDs holds the tenant, the project and the request id to the
// identifier rule within MaxAnswerIDBytes.
func (a Answer) checkIDs() error {
	for _, id := range []struct{ name, v string }{{"tenant", a.Tenant}, {"project", a.Project}, {"requestId", a.RequestID}} {
		if id.v == "" || len(id.v) > MaxAnswerIDBytes || contract.CheckIdentifier(id.v) != nil {
			return fmt.Errorf("%w: %s is not an identifier within %d bytes", ErrAnswerFormat, id.name, MaxAnswerIDBytes)
		}
	}
	return nil
}

// readInstant reads an RFC 3339 instant in UTC, spelled the one way
// MarshalAnswer spells it, so no two bodies differ only in a time's spelling.
func readInstant(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.UTC().Format(time.RFC3339Nano) != s {
		return time.Time{}, fmt.Errorf("%w: decidedAt is not an RFC 3339 instant in UTC", ErrAnswerFormat)
	}
	return t.UTC(), nil
}
