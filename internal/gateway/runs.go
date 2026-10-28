package gateway

import (
	"context"
	"fmt"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// Runs is the runs directory as a plane uses it (ADR-0034): it resolves a
// token, reads a root run's flow state and raises it. A plane configured
// without one serves the local runs of ADR-0021.
type Runs interface {
	RunResolver
	// State reads root's flow state. Any error, a missing or unreadable state
	// file included, blocks the call.
	State(ctx context.Context, root string) (RunState, error)
	// Raise reads root's state under an exclusive lock, applies join to it and
	// writes the result durably before it returns. Nothing else writes a
	// root's state, so join alone decides whether it rises.
	Raise(ctx context.Context, root string, join func(RunState) RunState) error
}

// RunResolver resolves a run token, which is all a listener may do with runs.
type RunResolver interface {
	// Resolve returns the open run token names, when it names one for who at
	// now. A refusal is a *RunRefusal; a zero now proves nothing unexpired.
	Resolve(ctx context.Context, token string, who RunIdentity, now time.Time) (OpenedRun, error)
}

// RunIdentity is who a run is for: the principal and agent a listener
// resolved, or the ones a run's record names.
type RunIdentity struct {
	TenantID, PrincipalType, PrincipalID, AgentID string
}

// OpenedRun is a run the operator opened, as a token resolved it.
type OpenedRun struct {
	// ID names the run on every event of its trails.
	ID string
	// Root is the run whose state the run shares: its own id, or the root of
	// the parent it was opened under.
	Root string
	// Who is the identity the run's record names.
	Who RunIdentity
	// Expires is when the run stops resolving; a call is handed out only
	// before it.
	Expires time.Time
}

// RunState is what a root run took in so far. The zero value is the most
// restrictive reading: something untrusted taken, and the highest sensitivity
// read unknown.
type RunState struct {
	// Trusted is true while nothing the run took in was untrusted.
	Trusted bool
	// MaxRead is the highest sensitivity read; UNSPECIFIED is unknown.
	MaxRead controlv1.Sensitivity
}

// RunCause is why a run token was refused. The values are the label set of
// the listener's refusal counter, so none ever names a run.
type RunCause string

// The causes, one per refusal Resolve or a listener can make.
const (
	// RunMissing: the request carried no token.
	RunMissing RunCause = "missing"
	// RunMalformed: the token is not a run id and a secret.
	RunMalformed RunCause = "malformed"
	// RunUnknown: no record holds the id, or its secret does not match.
	RunUnknown RunCause = "unknown"
	// RunOtherIdentity: the record is for another tenant, principal or agent.
	RunOtherIdentity RunCause = "identity"
	// RunClosed: the operator closed the run.
	RunClosed RunCause = "closed"
	// RunExpired: the run expired, or the clock proves nothing unexpired.
	RunExpired RunCause = "expired"
	// RunUnreadable: the record or the directory could not be read.
	RunUnreadable RunCause = "unreadable"
)

// RunCauses returns every cause, in the order a counter lists them.
func RunCauses() []RunCause {
	return []RunCause{RunMissing, RunMalformed, RunUnknown, RunOtherIdentity, RunClosed, RunExpired, RunUnreadable}
}

// RunRefusal is a refused run token and why.
type RunRefusal struct {
	Cause RunCause
	Err   error
}

// Error names the cause and what caused it.
func (r *RunRefusal) Error() string {
	if r.Err == nil {
		return "run refused: " + string(r.Cause)
	}
	return fmt.Sprintf("run refused: %s: %v", r.Cause, r.Err)
}

// Unwrap returns what caused the refusal.
func (r *RunRefusal) Unwrap() error { return r.Err }

// checkRuns refuses a plane whose adapter hands in opened runs without a runs
// directory to judge them, or one with a runs directory whose adapter hands in
// none: either way a call would run under a run nobody checked, or under none.
func checkRuns(cfg Config, presents bool) error {
	switch {
	case presents && cfg.Runs == nil:
		return fmt.Errorf("%w: %s presents runs and no runs directory is configured", ErrRunsMismatch, cfg.Adapter.Name())
	case !presents && cfg.Runs != nil:
		return fmt.Errorf("%w: a runs directory is configured and %s presents no run", ErrRunsMismatch, cfg.Adapter.Name())
	}
	return nil
}
