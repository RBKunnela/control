package gateway

import (
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
