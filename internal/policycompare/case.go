package policycompare

import (
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/pkg/contract"
)

// MaxCases bounds the cases of one run, explicit and evidence together.
const MaxCases = 4096

// Error is a refusal by this package, matched with errors.Is.
type Error string

func (e Error) Error() string { return string(e) }

const (
	// ErrInput is a run this package refuses as a whole.
	ErrInput Error = "policycompare: input refused"
	// ErrLabels is a labels file refused for its content.
	ErrLabels Error = "policycompare: labels refused"
	// ErrLabelsKind is a labels file of a kind this build does not read.
	ErrLabelsKind Error = "policycompare: labels kind refused"
)

// Source is where a case came from.
type Source string

const (
	// SourceCase is a case file an operator wrote.
	SourceCase Source = "case"
	// SourceEvidence is a request read from an evidence export.
	SourceEvidence Source = "evidence"
)

// Reason is why a case is unknown.
type Reason string

// The reasons, in the order the report lists them.
const (
	ReasonExportNotWhole          Reason = "export_not_whole"
	ReasonIncompleteRequest       Reason = "incomplete_request"
	ReasonVersionNotRead          Reason = "version_not_read"
	ReasonSeveralDecisions        Reason = "several_decisions"
	ReasonHistoricPolicyMissing   Reason = "historic_policy_missing"
	ReasonRecordedStale           Reason = "recorded_stale"
	ReasonNotEvaluated            Reason = "not_evaluated"
	ReasonExternalAnswerNeeded    Reason = "external_answer_needed"
	ReasonMissingFacts            Reason = "missing_facts"
	ReasonFreshnessNotHeld        Reason = "freshness_not_held"
	ReasonObligationApplicability Reason = "obligation_applicability_unknown"
	ReasonDisagreesWithRecord     Reason = "disagrees_with_record"
)

// Reasons is every reason, in the order the report lists them.
func Reasons() []Reason {
	return []Reason{
		ReasonExportNotWhole, ReasonIncompleteRequest, ReasonVersionNotRead, ReasonSeveralDecisions, ReasonHistoricPolicyMissing,
		ReasonRecordedStale, ReasonNotEvaluated, ReasonExternalAnswerNeeded, ReasonMissingFacts,
		ReasonFreshnessNotHeld, ReasonObligationApplicability, ReasonDisagreesWithRecord,
	}
}

// Input is what the kernel is handed for one case, on either side.
type Input struct {
	Envelope       *controlv1.ActionEnvelope
	Refusal        error
	AuthorizedArgs []byte
	Flow           contract.FlowState
	External       core.External
	Options        core.Options
	LoadedAt       time.Time
	DecidedAt      time.Time
}

// Case is one case of a run. A case the builder already knows to be unknown
// carries its Reason and no Input, and is never evaluated.
type Case struct {
	ID      string
	Source  Source
	Input   Input
	Unknown Reason
	Detail  string
	// recorded is the decision an evidence case's plane recorded: a
	// cross-check of today's kernel on the current policy, never the before.
	recorded *controlv1.Decision
}

// Policy is a signed bundle and the keys it verifies under, loaded at each
// case's loaded_at.
type Policy struct {
	Bundle *controlv1.PolicyBundle
	Keys   bundle.Keyring
}
