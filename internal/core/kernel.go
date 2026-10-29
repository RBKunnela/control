package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// EnforcementAction is what the enforcement point does about a decision. The
// zero value is Block, so an action nobody set blocks.
type EnforcementAction uint8

const (
	// Block stops the call.
	Block EnforcementAction = iota
	// Execute lets the call proceed.
	Execute
	// ExecuteWithObligations lets the call proceed only with its obligations
	// applied.
	ExecuteWithObligations
	// AwaitApproval holds the call until an approval bound to its exact digest
	// arrives.
	AwaitApproval
)

// Options configure a Kernel once, at construction.
type Options struct {
	// Mode is ENFORCE; every other mode is planned and refused by New.
	Mode controlv1.EnforcementMode
	// FailOpenRead is the operator's explicit risk setting for reads the policy's
	// availability left undecided. The zero value fails closed.
	FailOpenRead bool
	// MaxStale is the operator's staleness budget; it has to be positive.
	MaxStale time.Duration
	// Applicable are the obligation types this enforcement point can apply.
	Applicable []string
	// DecisionPoint is the configured external decision point's identifier,
	// with no '@', '?' or '#', written as pdp_instance on a decision that
	// consulted its answer. Empty when none is configured.
	DecisionPoint string
}

// Kernel decides one request at a time against a snapshot, and is safe for
// concurrent use: it writes to nothing after New.
type Kernel struct {
	failOpenRead  bool
	maxStale      time.Duration
	applicable    map[string]bool
	decisionPoint string
	clock         func() time.Time
	newID         func() string
}

// New checks opts once and returns a kernel, or refuses the configuration.
// Only ENFORCE is implemented (ADR-0012); the other declared modes are
// planned, and the zero value and an undeclared number are no mode at all.
// Every Decide calls clock and newID, so both have to be safe for concurrent
// use when the kernel is.
func New(opts Options, clock func() time.Time, newID func() string) (*Kernel, error) {
	if err := checkMode(opts.Mode); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, ErrNoClock
	}
	if newID == nil {
		return nil, ErrNoIDSource
	}
	if opts.MaxStale <= 0 {
		return nil, fmt.Errorf("%w: %v", ErrMaxStale, opts.MaxStale)
	}
	applicable := make(map[string]bool, len(opts.Applicable))
	for i, name := range opts.Applicable {
		if !rules.KnownObligation(name) {
			return nil, fmt.Errorf("%w: Applicable[%d]", ErrApplicable, i)
		}
		applicable[name] = true
	}
	if err := checkDecisionPoint(opts.DecisionPoint); err != nil {
		return nil, err
	}
	return &Kernel{
		failOpenRead:  opts.FailOpenRead,
		maxStale:      opts.MaxStale,
		applicable:    applicable,
		decisionPoint: opts.DecisionPoint,
		clock:         clock,
		newID:         newID,
	}, nil
}

// checkDecisionPoint refuses an identifier a decision could not carry into
// evidence. pdp_instance is written verbatim, so an '@', '?' or '#', behind
// which a URL's userinfo, query or fragment could hold a credential, is
// refused; the refusal never repeats the identifier.
func checkDecisionPoint(id string) error {
	if id == "" {
		return nil
	}
	if len(id) > contract.MaxStringBytes || contract.CheckIdentifier(id) != nil {
		return ErrDecisionPoint
	}
	if strings.ContainsAny(id, "@?#") {
		return fmt.Errorf("%w: it carries an '@', '?' or '#'", ErrDecisionPoint)
	}
	return nil
}

func checkMode(mode controlv1.EnforcementMode) error {
	if mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE {
		return nil
	}
	if mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
		return fmt.Errorf("%w: the zero value names no mode", ErrMode)
	}
	if value := mode.Descriptor().Values().ByNumber(mode.Number()); value != nil {
		return fmt.Errorf("%w: %s is planned", ErrMode, value.Name())
	}
	return fmt.Errorf("%w: mode %d is not declared in this build", ErrMode, mode)
}

// Request is one proposed action as the kernel receives it.
type Request struct {
	// Envelope is nil when nothing parsed, or when the input was over the size
	// bound. An envelope built in memory is trusted not to have been decoded
	// with DiscardUnknown, which Validate cannot detect.
	Envelope *controlv1.ActionEnvelope
	// Refusal is what a decoder returned; nil makes Decide run
	// contract.Validate itself.
	Refusal        error
	AuthorizedArgs []byte
	Flow           contract.FlowState
	// External is the external decision point's answer; the zero value is
	// "not asked". It changes a decision only where Outcome.NeedsExternal is
	// true.
	External External
}

// Outcome is a decision and what to enforce for it.
type Outcome struct {
	// Decision is never nil, and complete on every path but a kernel nobody
	// built: that path has no id source and no clock, so its decision_id and
	// decided_at are empty.
	Decision *controlv1.Decision
	Action   EnforcementAction
	// NeedsExternal is whether the decision turns on the external decision
	// point's answer: evaluation ran and a rule's value depends on it. It is
	// the same whatever answer the request carried, and when it is false no
	// answer changes the decision.
	NeedsExternal bool
	// Basis is what the decision stood on, for Recheck at hand-out; the zero
	// value on a kernel nobody built.
	Basis Basis
	// RefusedInput is whether the decision stopped on the request itself,
	// before any rule ran: the refusal handed in, Validate's refusal of the
	// envelope, arguments that cannot be digested, or a hash naming other
	// bytes. A cause found later, an undetermined rule or a one-sided tenant,
	// leaves it unset. A kernel nobody built reads no request and leaves it
	// unset too; it blocks whatever it is asked.
	RefusedInput bool
}

// Decide returns a decision for req against snap, and what to enforce
// (ADR-0012). It has no error return: whatever it cannot do
// becomes an INDETERMINATE decision with a reason code. It reads the clock
// once on entry for every comparison and once more for the latency, clones
// the envelope before reading it, and returns nothing that aliases the
// request, the snapshot or an earlier decision. A first reading before 1970,
// the zero time among them, after 9999, or earlier than the snapshot's
// NotBefore judges nothing: the decision is INDETERMINATE with POLICY_STALE
// and blocks on every effect class.
//
// A kernel nobody built, nil or the zero value, has no clock and no id
// source; it decides INDETERMINATE and Block rather than crash.
func (k *Kernel) Decide(_ context.Context, req Request, snap *policy.Snapshot) Outcome {
	return k.decide(req, snap, nil)
}

// decide is the one decision Decide and Explain share; e is nil in Decide.
func (k *Kernel) decide(req Request, snap *policy.Snapshot, e *Explanation) Outcome {
	if k == nil || k.clock == nil || k.newID == nil {
		return unbuilt()
	}
	d := newDecision(k, req, snap)
	d.explain = e
	d.run(k)
	return d.outcome(k)
}

// unbuilt is the answer of a kernel that was never constructed: the stub's,
// with the one code that says nothing evaluated the call.
func unbuilt() Outcome {
	return Outcome{
		Decision: &controlv1.Decision{
			SchemaVersion:   schemaVersion,
			Verdict:         controlv1.Verdict_VERDICT_INDETERMINATE,
			ReasonCodes:     []string{codePolicyUnavailable},
			PdpType:         pdpType,
			EnforcementMode: controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
			PolicyFreshness: controlv1.PolicyFreshness_POLICY_FRESHNESS_STALE,
		},
		Action: Block,
	}
}
