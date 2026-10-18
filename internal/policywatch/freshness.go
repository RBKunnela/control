package policywatch

import (
	"time"

	"github.com/guardana/control/internal/policy"
)

// State is how the snapshot a call is decided under stands.
type State uint8

const (
	// Unconfirmed is a snapshot no statement confirms, or none at all: every
	// call that reaches the kernel's freshness check is POLICY_STALE.
	Unconfirmed State = iota
	// Confirmed is a snapshot a statement confirmed within its budget.
	Confirmed
	// Expired is a snapshot whose confirmation is past its budget, or one
	// read at a clock the kernel refuses to judge by: outside 1970 to 9999,
	// or earlier than the snapshot's NotBefore. The kernel decides it stale
	// too.
	Expired
)

// States is every state, in order.
func States() []State { return []State{Unconfirmed, Confirmed, Expired} }

// String is the state as /healthz and /metrics spell it.
func (s State) String() string {
	switch s {
	case Unconfirmed:
		return "unconfirmed"
	case Confirmed:
		return "confirmed"
	case Expired:
		return "expired"
	}
	return "unknown"
}

// Budget is the staleness budget the kernel holds snap to: the smaller of the
// author's and the operator's.
func Budget(snap *policy.Snapshot, operator time.Duration) time.Duration {
	return policy.Budget(snap.MaxStale(), operator)
}

// ExpiresAt is when a confirmation issued at issued runs out for snap under
// the operator's budget.
func ExpiresAt(issued time.Time, snap *policy.Snapshot, operator time.Duration) time.Time {
	return issued.Add(Budget(snap, operator))
}

// Freshness is how snap stands at now under the operator's budget, and when
// its confirmation expires, the zero time where there is none. It judges by
// the kernel's rule, policy's FreshAt.
func Freshness(snap *policy.Snapshot, operator time.Duration, now time.Time) (State, time.Time) {
	confirmed := snap.ConfirmedAt()
	if snap == nil || confirmed.IsZero() {
		return Unconfirmed, time.Time{}
	}
	expires := ExpiresAt(confirmed, snap, operator)
	if !snap.FreshAt(now, operator) {
		return Expired, expires
	}
	return Confirmed, expires
}
