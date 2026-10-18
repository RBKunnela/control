package gateway

import (
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// PDPType names this enforcement point in the pdp_type of every decision it
// mints for a block of its own, so a reader tells it from the kernel's
// "builtin" (ADR-0013).
const PDPType = "gateway"

// The reason codes the enforcement point emits, as literals: nothing on the
// decision path reads the registry, and codes_test.go holds each one to its
// entry and to the verdict it is minted with. The kernel and the matcher
// never emit the first seven.
const (
	codePaused                 = "PAUSED"
	codePauseStateUnavailable  = "PAUSE_STATE_UNAVAILABLE"
	codeRunStopped             = "RUN_STOPPED"
	codeStopStateUnavailable   = "STOP_STATE_UNAVAILABLE"
	codeLockdown               = "LOCKDOWN"
	codeEvidenceUnavailable    = "EVIDENCE_UNAVAILABLE"
	codeActionUnclassified     = "ACTION_UNCLASSIFIED"
	codeExecutedArgsMismatch   = "EXECUTED_ARGS_MISMATCH"
	codeApprovalExpired        = "APPROVAL_EXPIRED"
	codeApprovalRejected       = "APPROVAL_REJECTED"
	codeApprovalAlreadyUsed    = "APPROVAL_ALREADY_USED"
	codeApprovalNotResumed     = "APPROVAL_NOT_RESUMED"
	codeApprovalStateUnknown   = "APPROVAL_STATE_UNKNOWN"
	codeApprovalDigestMismatch = "APPROVAL_DIGEST_MISMATCH"
	codeApprovalBundleMismatch = "APPROVAL_BUNDLE_MISMATCH"
	codeObligationNotApplied   = "OBLIGATION_NOT_UNDERSTOOD"
	codeInvalidFieldValue      = "INVALID_FIELD_VALUE"
	codeExecutionAbandoned     = "EXECUTION_ABANDONED"
	codePolicyStale            = "POLICY_STALE"
	decisionSchemaVersion      = "1.0"
	approvalSchemaVersion      = "1.0"
	resultSchemaVersion        = "1.0"
	verdictDeny                = controlv1.Verdict_VERDICT_DENY
	verdictIndeterminate       = controlv1.Verdict_VERDICT_INDETERMINATE
	approvalPending            = controlv1.ApprovalState_APPROVAL_STATE_PENDING
	approvalApproved           = controlv1.ApprovalState_APPROVAL_STATE_APPROVED
	approvalExpired            = controlv1.ApprovalState_APPROVAL_STATE_EXPIRED
	approvalRejected           = controlv1.ApprovalState_APPROVAL_STATE_REJECTED
	resultSuccess              = controlv1.ResultStatus_RESULT_STATUS_SUCCESS
	resultBlocked              = controlv1.ResultStatus_RESULT_STATUS_BLOCKED
	resultUnknown              = controlv1.ResultStatus_RESULT_STATUS_UNKNOWN
	modeObserve                = controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	modeApprove                = controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE
	modeLockdown               = controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN
	modeEnforce                = controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE
	freshnessStale             = controlv1.PolicyFreshness_POLICY_FRESHNESS_STALE
	statusExecutedArgsMismatch = codeExecutedArgsMismatch
)

// mint makes the enforcement point's own decision about the request the
// kernel decided as from: the same request, digest and bundle, this plane's
// verdict, codes in the order given, mode and clock, and no rule: a cause of
// the plane's own is no rule of the bundle the decision names. The kernel's
// decision stays untouched in POLICY_DECIDED; this one goes on ACTION_BLOCKED.
func (p *Pipeline) mint(from *controlv1.Decision, now time.Time, verdict controlv1.Verdict, codes ...string) *controlv1.Decision {
	freshness := from.GetPolicyFreshness()
	if freshness == controlv1.PolicyFreshness_POLICY_FRESHNESS_UNSPECIFIED || slices.Contains(codes, codePolicyStale) {
		freshness = freshnessStale
	}
	return &controlv1.Decision{
		SchemaVersion:      decisionSchemaVersion,
		DecisionId:         p.cfg.NewID(),
		RequestId:          from.GetRequestId(),
		ActionDigest:       from.GetActionDigest(),
		PolicyBundleDigest: from.GetPolicyBundleDigest(),
		Verdict:            verdict,
		ReasonCodes:        slices.Clone(codes),
		PdpType:            PDPType,
		EnforcementMode:    p.cfg.Mode,
		PolicyFreshness:    freshness,
		PolicyLoadedAt:     proto.CloneOf(from.GetPolicyLoadedAt()),
		DecidedAt:          timestampOf(now),
	}
}

func timestampOf(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }
