package gateway

import (
	"fmt"
	"slices"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
)

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
	// expired ones the sweep has not reached included; positive. A request
	// past it is refused as a hold the store would not keep.
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

// checkConfig makes New's refusals of cfg but the decision point's. It asks
// the adapter for its name and capabilities once and returns both, so the
// pipeline keeps the values that were checked.
func checkConfig(cfg Config) (string, Capabilities, error) {
	if cfg.Adapter == nil {
		return "", Capabilities{}, ErrNoAdapter
	}
	name, caps := cfg.Adapter.Name(), cfg.Adapter.Capabilities()
	caps.Obligations = slices.Clone(caps.Obligations)
	if err := checkAdapter(cfg.Mode, name, caps); err != nil {
		return "", Capabilities{}, err
	}
	if err := checkRuns(cfg, caps.PresentsRuns); err != nil {
		return "", Capabilities{}, err
	}
	if err := checkSources(cfg); err != nil {
		return "", Capabilities{}, err
	}
	if _, disabled := cfg.Stops.(disabledStops); !disabled && cfg.Runs == nil {
		return "", Capabilities{}, ErrStopsWithoutRuns
	}
	if err := checkBounds(cfg); err != nil {
		return "", Capabilities{}, err
	}
	if first, second := cfg.NewID(), cfg.NewID(); first == "" || second == "" || first == second {
		return "", Capabilities{}, ErrIDSource
	}
	return name, caps, nil
}

// checkSources refuses a source cfg leaves nil.
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

// checkBounds refuses a bound outside the range its field documents.
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
