package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
)

// DecisionPoint is an external decision point whose answer the policy reads
// and can only veto with (ADR-0017). Ask asks about one envelope and has no
// error return: whatever it cannot do is an unanswered state naming its
// cause. It has to return by ctx's deadline, which carries the configured
// DecisionTimeout, and has to be safe for concurrent use; what it returns
// once ctx has ended is no answer.
type DecisionPoint interface {
	Ask(ctx context.Context, env *controlv1.ActionEnvelope) core.External
}

// checkDecisionPoint refuses a decision point and a policy that do not agree
// on whether one is read, and a decision point without its identifier or a
// positive deadline. A policy source with no snapshot yet reads none.
func checkDecisionPoint(cfg Config) error {
	reads := cfg.Policy.Current().ReadsExternal()
	if cfg.DecisionPoint == nil {
		switch {
		case reads:
			return ErrNoDecisionPoint
		case cfg.DecisionPointID != "":
			return fmt.Errorf("%w: an identifier with no decision point", ErrDecisionPointID)
		case cfg.DecisionTimeout != 0:
			return fmt.Errorf("%w: %v with no decision point", ErrDecisionTimeout, cfg.DecisionTimeout)
		}
		return nil
	}
	switch {
	case !reads:
		return ErrDecisionPointUnused
	case cfg.DecisionPointID == "":
		return ErrDecisionPointID
	case cfg.DecisionTimeout <= 0:
		return fmt.Errorf("%w: %v", ErrDecisionTimeout, cfg.DecisionTimeout)
	}
	return nil
}

// ask asks the decision point about env within the configured deadline, and
// counts the ask. With none configured there is nobody to ask, which is an
// unavailable decision point; a decision point that answers the zero value
// gave no answer either. An answer that comes back once ctx has ended, past
// the deadline or after the caller left, is no answer within it, whatever it
// says.
func (p *Pipeline) ask(ctx context.Context, env *controlv1.ActionEnvelope) core.External {
	if p.cfg.DecisionPoint == nil {
		return core.ExternalUnavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.DecisionTimeout)
	defer cancel()
	start := p.cfg.Clock()
	answer := p.cfg.DecisionPoint.Ask(ctx, proto.CloneOf(env))
	took := p.cfg.Clock().Sub(start)
	switch err := ctx.Err(); {
	case errors.Is(err, context.DeadlineExceeded):
		answer = core.ExternalTimeout()
	case err != nil, answer == (core.External{}):
		answer = core.ExternalUnavailable()
	}
	p.counts.asked(answer, took)
	return answer
}

// asked counts one ask by what came back and how long it took.
func (c *counters) asked(answer core.External, took time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a := &c.stats.Asks
	a.Made++
	*a.count(answer)++
	a.Micros += uint64(max(0, took.Microseconds()))
}

// count is the counter of answer's state.
func (a *Asks) count(answer core.External) *uint64 {
	switch answer {
	case core.ExternalAllowed():
		return &a.Allowed
	case core.ExternalDenied():
		return &a.Denied
	case core.ExternalDeniedObligations():
		return &a.DeniedObligations
	case core.ExternalTimeout():
		return &a.TimedOut
	case core.ExternalAnswerRefused():
		return &a.AnswerRefused
	}
	return &a.Unavailable
}
