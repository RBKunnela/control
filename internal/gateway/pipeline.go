package gateway

import (
	"context"
	"sync"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/reaction"
)

// Admission is one proposed action as the adapter translated it.
type Admission struct {
	// Envelope is nil when nothing parsed.
	Envelope *controlv1.ActionEnvelope
	// Refusal is what the decoder returned, if anything. ErrUnclassified in
	// it names a call nothing classifies.
	Refusal error
	// Arguments are the proposed arguments, as the bytes the digest covers.
	Arguments []byte
	// ResultTrust is the trust zone of what the call's result contains, as
	// the operator declared it; the zero value is untrusted.
	ResultTrust controlv1.TrustZone
	// ResultSensitivity is the highest sensitivity the call's result can
	// hold, as the operator declared it; the zero value is unknown.
	ResultSensitivity controlv1.Sensitivity
	// Run is the opened run the listener resolved for this call; nil on a
	// plane without a runs directory.
	Run *OpenedRun
}

// Disposition is what the plane does about an admission. The zero value
// blocks: an action nobody set is Block, with no arguments to send.
type Disposition struct {
	// Action is what to do; Block unless something said otherwise.
	Action core.EnforcementAction
	// Decision is the one to record and to answer with: the one on the
	// trail's POLICY_DECIDED, or the enforcement point's own when the block
	// is its own.
	Decision *controlv1.Decision
	// AuthorizedArgs are the bytes to send upstream, obligations applied; nil
	// unless Action executes. An adapter sends exactly these.
	AuthorizedArgs []byte
	// AuthorizedDigest is canon.ArgumentsHashV1 of AuthorizedArgs. An adapter
	// digests what it is about to send and aborts on a mismatch.
	AuthorizedDigest string
	// ExecutionID names the execution ACTION_STARTED recorded; empty unless
	// Action executes. The closing record carries it whatever the adapter's
	// result says.
	ExecutionID string
	// Obligations are what execution has to honour, when Action is
	// ExecuteWithObligations.
	Obligations []*controlv1.Obligation
	// Pending is the state to answer with when Action is AwaitApproval.
	Pending *Pending
	// Unrecorded says the execution is a read handed out under
	// AllowReadsUnrecorded after the sink refused its trail: no record of it
	// is written, its closing included.
	Unrecorded bool
	// handle names the execution in the pipeline's own record; Close and
	// Abort resolve it there and trust nothing else in this value.
	handle string
}

// Pending is what an agent is told about a held request, and what it needs to
// retry it.
type Pending struct {
	ApprovalID   string
	ActionDigest string
	ExpiresAt    time.Time
	RetryAfter   time.Duration
}

// Pipeline is one plane's enforcement pipeline. New is the only way to make a
// usable one; a nil or zero Pipeline blocks every admission.
type Pipeline struct {
	cfg    Config
	kernel *core.Kernel
	counts counters

	mu     sync.Mutex
	open   map[string]*execution
	trails map[string]openTrail
	runs   map[runKey]*run
}

// execution is what the pipeline keeps about a call it handed to execution,
// keyed by the recorded decision's id, until Close or Abort.
type execution struct {
	trail *evidence.Builder
	// requestID is the trail's, which on a resume is the held request's.
	requestID   string
	executionID string
	// envelope is the authorized envelope and digest the recorded decision's
	// action digest; Close digests the sent bytes under the one and compares
	// with the other.
	envelope *controlv1.ActionEnvelope
	digest   string
	// runID is the opened run the call ran under; empty for a local run.
	runID string
	// unrecorded: the sink refused the trail and the read ran anyway under
	// AllowReadsUnrecorded, so the closing record is not written either.
	unrecorded bool
}

// openTrail is a request id whose trail was started and has not concluded.
// held is the pipeline's own record of a request awaiting an approval, and is
// nil once that request runs; a hold stops counting at its expiry, when
// nothing can resume it any more.
type openTrail struct {
	held *heldRequest
}

// New checks cfg once and returns a pipeline, or refuses the configuration
// with the first of New's refusals in errors.go it meets, or with the kernel's
// refusal of its options.
func New(cfg Config) (*Pipeline, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, err
	}
	if err := checkDecisionPoint(cfg); err != nil {
		return nil, err
	}
	opts := cfg.KernelOptions
	opts.Mode = modeEnforce
	opts.DecisionPoint = cfg.DecisionPointID
	opts.Applicable = append(append([]string(nil), rewriting...), cfg.Adapter.Capabilities().Obligations...)
	if cfg.Mode == modeLockdown {
		opts.FailOpenRead = false
	}
	kernel, err := core.New(opts, cfg.Clock, cfg.NewID)
	if err != nil {
		return nil, err
	}
	if cfg.MaxHeldPerRun == 0 {
		cfg.MaxHeldPerRun = DefaultMaxHeldPerRun
	}
	return &Pipeline{cfg: cfg, kernel: kernel, open: make(map[string]*execution), trails: make(map[string]openTrail), runs: make(map[runKey]*run)}, nil
}

// Admit decides one admission and says what to do about it. It has no error
// return: whatever the pipeline cannot do is a block that names its cause, and
// a nil or zero Pipeline answers INDETERMINATE, POLICY_UNAVAILABLE, Block.
//
// The order is fixed: the pause and stop states, then the clock, then one
// policy snapshot and the flow state of the call's run, which every decision of
// the call is made under and ACTION_PROPOSED records (ADR-0021). The plane's
// own causes, taken before the kernel decides and again after an ask, change
// the action and never the decision, and a call they block asks the decision
// point nothing (ADR-0019). Arguments a rewriting obligation changed are decided
// again, and that decision is the one recorded. The trail is written
// ACTION_PROPOSED and POLICY_DECIDED first, and whatever executes has
// ACTION_STARTED written, and its declared result taken into its run, before
// Admit returns. A request id whose trail is
// still open is refused before anything is written, unless the call resumes
// that trail (ADR-0013).
func (p *Pipeline) Admit(ctx context.Context, a Admission) Disposition {
	if p == nil || p.kernel == nil {
		return unbuilt(ctx, a)
	}
	return p.newCall(ctx, withArguments(a)).run()
}

// withArguments is a as the plane decides it: absent arguments are the empty
// object canon digests them as, so nothing downstream carries nil bytes and an
// execution always has bytes for Close to compare.
func withArguments(a Admission) Admission {
	if a.Arguments == nil {
		a.Arguments = []byte("{}")
	}
	return a
}

// Preview returns the decision Admit's decision step would reach for a: the
// kernel's, then the mode's and the halts', such as LOCKDOWN's DENY on a
// material call. It rewrites nothing, records nothing, holds nothing,
// executes nothing and asks the decision point nothing, which is what shaping
// a listing needs. It reads no pause or stop state: a paused tool stays
// listed, and a call to it reads PAUSED (ADR-0019); a stopped run's listing
// is the listing of any other run, and its call reads RUN_STOPPED (ADR-0046).
// It reads no run either: a listing is cached per principal and outlives any
// flow state, so a flow rule is undetermined here. A nil or zero Pipeline
// answers the decision of a kernel nobody built.
func (p *Pipeline) Preview(ctx context.Context, a Admission) *controlv1.Decision {
	if p == nil || p.kernel == nil {
		return unbuilt(ctx, a).Decision
	}
	c := &call{
		p: p, ctx: ctx, in: withArguments(a), now: p.cfg.Clock(),
		pause: pause.DisabledSnapshot(), stops: reaction.DisabledSnapshot(),
	}
	c.refuseFlowTags()
	c.stampFlow()
	c.causes = planeCauses(c.planeState())
	c.decideProposed(p.cfg.Policy.Current(), false)
	c.applyMode()
	c.refuseFlow()
	return c.decision
}

// Stats returns what the pipeline counted so far. A nil or zero Pipeline
// counted nothing and is halted, since it takes no material call.
func (p *Pipeline) Stats() Stats {
	if p == nil || p.kernel == nil {
		return Stats{Halted: true}
	}
	s := p.counts.snapshot()
	s.HoldJournal = p.cfg.Journal != nil
	now := p.cfg.Clock()
	p.mu.Lock()
	defer p.mu.Unlock()
	s.Open = len(p.open)
	s.Runs = len(p.runs)
	for _, t := range p.trails {
		if t.held != nil && now.Before(t.held.expires) {
			s.Held++
		}
	}
	return s
}

// unbuilt is the one fail-closed answer: the decision of a kernel nobody
// built, which the kernel itself defines.
func unbuilt(ctx context.Context, a Admission) Disposition {
	out := (*core.Kernel)(nil).Decide(ctx, core.Request{
		Envelope: a.Envelope, Refusal: a.Refusal, AuthorizedArgs: a.Arguments,
	}, nil)
	return Disposition{Action: out.Action, Decision: out.Decision}
}
