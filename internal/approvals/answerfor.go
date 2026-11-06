package approvals

import (
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
)

// AnswerFor is the answer the operator of keyID signs to rec at decidedAt.
// Every member the plane compares is the plane's own record of the hold;
// only the decision, the reason and the time are the operator's. It refuses
// a record held under another authority with ErrNotSigned, one no longer
// pending with ErrApprovalAnswered, one past its expiry at decidedAt with
// ErrApprovalExpired, and a zero decidedAt with ErrZeroTime.
func AnswerFor(rec Record, decision, reason string, decidedAt time.Time, keyID string) (Answer, error) {
	switch {
	case decidedAt.IsZero():
		return Answer{}, ErrZeroTime
	case rec.HeldUnder() != HeldUnderSigned:
		return Answer{}, ErrNotSigned
	case rec.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING:
		return Answer{}, ErrApprovalAnswered
	case approval.Expired(rec.Approval, decidedAt):
		return Answer{}, ErrApprovalExpired
	}
	a := Answer{
		Alg: "ed25519", KeyID: keyID, Tenant: rec.Tenant, Project: rec.Project,
		RequestID: rec.RequestID, ApprovalID: rec.ApprovalID, ActionDigest: rec.Approval.GetActionDigest(),
		BundleDigest: rec.Approval.GetPolicyBundleDigest(), Decision: decision, DecidedAt: decidedAt.UTC(), Reason: reason,
	}
	if err := a.check(); err != nil {
		return Answer{}, err
	}
	return a, nil
}

// AnswerLabel is the label an answer of a takes in the inbox: its key id and
// its decision. One operator's approval and rejection of one approval are
// two files, and a second answer of the same decision finds its name taken.
func AnswerLabel(a Answer) string {
	return a.KeyID + "-" + a.Decision
}
