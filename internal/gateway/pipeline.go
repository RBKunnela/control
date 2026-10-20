package gateway

import (
	"context"
	"fmt"
	"sync"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/reaction"
)

// PolicySource serves the snapshot a call is decided against; a Holder is one.
type PolicySource interface {
	Current() *policy.Snapshot
}

// PauseSource serves the operator's pause state a call is decided under; a
// pause.Poller is one. A call reads it once, and once more after an ask to
// the decision point (ADR-0019).
type PauseSource interface {
	Current() pause.Snapshot
}

// PauseDisabled is the source of a plane configured with no pause file. It is
// a choice the caller states: a nil source is refused, never read as this.
func PauseDisabled() PauseSource { return disabledPause{} }

type disabledPause struct{}

func (disabledPause) Current() pause.Snapshot { return pause.DisabledSnapshot() }

// StopSource serves the stop state a call is decided under (ADR-0046); a stop
// list's poller is one. A call reads it each time it reads the pause source.
type StopSource interface {
	Current() reaction.Snapshot
}

// StopsDisabled is the source of a plane configured with no route. It is a
// choice the caller states: a nil source is refused, never read as this.
func StopsDisabled() StopSource { return disabledStops{} }

type disabledStops struct{}

func (disabledStops) Current() reaction.Snapshot { return reaction.DisabledSnapshot() }

// DefaultMaxHeldPerRun is how many requests one opened run may hold for an
// approval when Config.MaxHeldPerRun is zero.
const DefaultMaxHeldPerRun = 16

// Config configures a Pipeline once, at New.
type Config struct {
	// Mode is the plane's enforcement mode, applied after the decision to
	// what is done and never to what is decided.
	Mode controlv1.EnforcementMode
	// Adapter is the protocol the plane speaks.
	Adapter Adapter
	// KernelOptions configure the kernel New builds. Its mode is always
	// ENFORCE whatever Mode says, its applicable obligations are the ones
	// the pipeline applies itself plus the adapter's declared ones, its
	// decision point is DecisionPointID, and under LOCKDOWN its fail-open
	// reads are off.
	KernelOptions core.Options
	// DecisionPoint is the external decision point the pipeline asks when a
	// decision turns on its answer (ADR-0017). It is set exactly when the
	// policy reads that answer.
	DecisionPoint DecisionPoint
	// DecisionPointID names DecisionPoint on a decision that consulted its
	// answer; non-empty with a decision point and empty without one.
	DecisionPointID string
	// DecisionTimeout bounds one ask; positive with a decision point and zero
	// without one.
	DecisionTimeout time.Duration
	// Policy serves the snapshot.
	Policy PolicySource
	// Pause serves the operator's pause state; PauseDisabled where no pause
	// file is configured. A snapshot it serves that nobody read, or that is
	// older than it answers for, blocks every call.
	Pause PauseSource
	// Stops serves the stop state; StopsDisabled where no route is
	// configured, and any other source only with Runs, since a stop names an
	// opened run. A snapshot nobody read, or one older than it answers for,
	// blocks every call.
	Stops StopSource
	// Sink takes every event of every trail.
	Sink evidence.Sink
	// Approvals holds requests and consumes approvals.
	Approvals ApprovalStore
	// Runs is the runs directory, set exactly when the adapter presents runs.
	// Without it every run is local (ADR-0021); with it every call needs an
	// opened run (ADR-0034).
	Runs Runs
	// Journal is the plane's own durable record of its own holds. It is
	// optional: without one the plane holds and resumes as it otherwise
	// would and closes no hold it loses to a restart, which Stats reports
	// rather than leaves to be discovered.
	Journal HoldJournal
	// ReconcileMax bounds the journal entries one Reconcile reads; zero takes
	// a bound of its own, and a negative one is refused. A bound that bites
	// makes that pass unmeasured rather than done.
	ReconcileMax int
	// Clock is what the plane reads. A reading outside 1970 to 9999, or one
	// behind an instant the call already relied on, never passes an expiry.
	Clock func() time.Time
	// NewID names decisions, events, approvals and executions. It has to
	// return a unique, non-empty id on every call.
	NewID func() string
	// ApprovalTTL is how long a requested approval can be answered and
	// consumed; positive.
	ApprovalTTL time.Duration
	// RetryAfter is what an agent is told to wait before retrying a held
	// request; positive.
	RetryAfter time.Duration
	// MaxHeld bounds the requests held for an approval and not yet closed,
	// expired ones the sweep has not reached included; positive. A request past it is refused as a hold the store would not
	// keep.
	MaxHeld int
	// MaxHeldPerRun bounds the requests one opened run holds for an approval
	// and not yet expired, so no one run fills MaxHeld for every other; zero
	// takes DefaultMaxHeldPerRun. A request past it is refused as one past
	// MaxHeld is. Calls under no opened run are held to MaxHeld alone.
	MaxHeldPerRun int
	// MaxOpen bounds the executions handed out and not yet closed or aborted;
	// positive. A call past it is blocked with EVIDENCE_UNAVAILABLE, because
	// the plane would have nowhere to record its closing.
	MaxOpen int
	// MaxRuns bounds the runs the pipeline keeps a flow state for; positive.
	// A call whose run would be past it is decided with the state nobody
	// computed. No run is ever dropped, since that would wash away what it
	// took in (ADR-0021).
	MaxRuns int
	// AllowReadsUnrecorded is the explicit risk setting of invariant 5 for
	// evidence (ADR-0014): a read whose trail the sink will not take runs
	// unrecorded and counted. A material call never does, and neither does a
	// call that would be held for an approval.
	AllowReadsUnrecorded bool
}

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

// New checks cfg once and returns a pipeline, or refuses the configuration:
// a mode this build does not know or enforce, an adapter that lacks what the
// mode needs, an end-user binding on a listener that authenticates nobody,
// runs presented without a runs directory or a runs directory nobody presents
// runs to, a nil policy source, pause source, stop source, sink, approval
// store, clock or id source, a stop source other than StopsDisabled on a plane
// that serves no opened run,
// an id source that returns an empty id or one id twice, a lifetime, retry
// interval or bound that is not positive, a negative bound on one run's held
// requests, a decision point the current policy
// does not read or a policy that reads one none is configured for, a decision point
// without its identifier or a positive deadline, and kernel options the
// kernel refuses.
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

// checkConfig is New's refusals, in the order New documents them.
func checkConfig(cfg Config) error {
	if err := checkAdapter(cfg.Mode, cfg.Adapter); err != nil {
		return err
	}
	if err := checkRuns(cfg); err != nil {
		return err
	}
	if err := checkSources(cfg); err != nil {
		return err
	}
	if _, disabled := cfg.Stops.(disabledStops); !disabled && cfg.Runs == nil {
		return ErrStopsWithoutRuns
	}
	if err := checkBounds(cfg); err != nil {
		return err
	}
	if first, second := cfg.NewID(), cfg.NewID(); first == "" || second == "" || first == second {
		return ErrIDSource
	}
	return nil
}

// checkSources refuses a nil policy source, pause source, stop source, sink,
// approval store, clock or id source.
func checkSources(cfg Config) error {
	switch {
	case cfg.Policy == nil:
		return ErrNoPolicy
	case cfg.Pause == nil:
		return ErrNoPause
	case cfg.Stops == nil:
		return ErrNoStops
	case cfg.Sink == nil:
		return ErrNoSink
	case cfg.Approvals == nil:
		return ErrNoApprovals
	case cfg.Clock == nil:
		return ErrNoClock
	case cfg.NewID == nil:
		return ErrNoIDSource
	}
	return nil
}

// checkBounds refuses a lifetime, retry interval, hold bound, bound on open
// executions or bound on runs that is not positive, and a negative bound on
// one run's holds or on a reconciliation.
func checkBounds(cfg Config) error {
	switch {
	case cfg.ApprovalTTL <= 0:
		return fmt.Errorf("%w: %v", ErrApprovalTTL, cfg.ApprovalTTL)
	case cfg.RetryAfter <= 0:
		return fmt.Errorf("%w: %v", ErrRetryAfter, cfg.RetryAfter)
	case cfg.MaxHeld <= 0:
		return fmt.Errorf("%w: %d", ErrMaxHeld, cfg.MaxHeld)
	case cfg.MaxHeldPerRun < 0:
		return fmt.Errorf("%w: %d", ErrMaxHeldPerRun, cfg.MaxHeldPerRun)
	case cfg.MaxOpen <= 0:
		return fmt.Errorf("%w: %d", ErrMaxOpen, cfg.MaxOpen)
	case cfg.MaxRuns <= 0:
		return fmt.Errorf("%w: %d", ErrMaxRuns, cfg.MaxRuns)
	case cfg.ReconcileMax < 0:
		return fmt.Errorf("%w: %d", ErrReconcileMax, cfg.ReconcileMax)
	}
	return nil
}

// Admit decides one admission and says what to do about it. It has no error
// return: whatever the pipeline cannot do is a block that names its cause. A
// nil or zero Pipeline answers with the decision of a kernel nobody built:
// INDETERMINATE, POLICY_UNAVAILABLE, Block.
//
// The order is fixed: the pause and stop states are taken, then the clock, then the
// policy snapshot and the flow state of the call's run, which every decision
// of the call is made under and ACTION_PROPOSED records (ADR-0021), and which
// a refused call reads without minting a run unless the mode is OBSERVE; the
// plane's own causes to block the call are named; the
// kernel decides against that snapshot, and asks the decision point nothing
// when the plane named a cause (ADR-0019); after an ask the pause and stop states and
// the clock are taken again and the causes named once more; those causes and
// the mode are applied to the action, never to the decision; the rewriting obligations produce the authorized arguments,
// and when they changed them the kernel decides the authorized envelope again
// and that decision is the one recorded; a request awaiting approval is
// looked up, resumed or held;
// then the trail is written, ACTION_PROPOSED and POLICY_DECIDED first, and
// whatever executes has ACTION_STARTED written, and its declared result taken
// into its run, before this returns. A request
// id whose trail is still open in this pipeline is refused before anything is
// written, unless the call resumes that trail (ADR-0013).
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
// is the listing of any other run, and its call reads RUN_STOPPED (ADR-0046). It reads no run either: a listing is
// cached per principal and outlives any flow state, so a flow rule is
// undetermined here. A nil or zero Pipeline answers the decision of a kernel
// nobody built.
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
