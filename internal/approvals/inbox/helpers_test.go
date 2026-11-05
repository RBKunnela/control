package inbox_test

import (
	"time"

	"github.com/guardana/control/internal/approvals"
)

// sampleAnswer is one answer every member of which is set, approving
// APPROVAL1.
func sampleAnswer() approvals.Answer {
	return approvals.Answer{
		Alg: "ed25519", KeyID: "key-1", Tenant: "acme", Project: "orders", RequestID: "req-1", ApprovalID: "APPROVAL1",
		ActionDigest: "sha256:abababababababababababababababababababababababababababababababab",
		BundleDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Decision:     approvals.DecisionApprove, DecidedAt: time.Date(2026, 3, 1, 12, 1, 0, 500, time.UTC), Reason: "checked",
	}
}
