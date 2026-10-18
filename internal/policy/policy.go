// Package policy loads a signed policy bundle into a snapshot the kernel decides
// against, and holds the current one. What a bundle must be to load is
// ADR-0011's; what a snapshot promises is ADR-0012's.
package policy

import (
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/match"
)

// Snapshot is one verified, compiled bundle, confirmed current at one time. It
// is never changed after it is made; a refresh makes a new one. A nil Snapshot,
// and the zero value, hold no policy: they report nothing and evaluate as a
// program nobody compiled does.
type Snapshot struct {
	ref         *controlv1.PolicyBundleRef
	confirmedAt time.Time
	maxStale    time.Duration
	serial      int64
	program     *match.Program
	// verified is the latest issuedAt the holder verified when it published
	// this snapshot; NotBefore is the later of it and confirmedAt.
	verified time.Time
}

// Ref returns a clone of the bundle's reference: its id, version and digest.
// It never carries a creation time, since none is signed.
func (s *Snapshot) Ref() *controlv1.PolicyBundleRef {
	if s == nil {
		return nil
	}
	return proto.CloneOf(s.ref)
}

// ConfirmedAt is when the bundle was last confirmed current. On a snapshot a
// statement confirmed it is that statement's issuedAt, and on an unconfirmed
// one the zero time, which the kernel decides stale; on one Load made it is
// the time handed to it.
func (s *Snapshot) ConfirmedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.confirmedAt
}

// NotBefore is the latest time the plane verified when it published this
// snapshot, never earlier than ConfirmedAt: on a holder's snapshot the latest
// issuedAt of a statement the holder confirmed or of the floor it read, and
// on one Load made the time handed to it. A clock reading earlier than it is
// provably wrong. It never falls across one holder's snapshots.
func (s *Snapshot) NotBefore() time.Time {
	if s == nil {
		return time.Time{}
	}
	if s.verified.After(s.confirmedAt) {
		return s.verified
	}
	return s.confirmedAt
}

// MaxStale is the author's staleness budget.
func (s *Snapshot) MaxStale() time.Duration {
	if s == nil {
		return 0
	}
	return s.maxStale
}

// Budget is the staleness budget a snapshot is held to: the smaller of its
// author's and the operator's.
func Budget(author, operator time.Duration) time.Duration {
	return min(author, operator)
}

// FreshAt is the freshness rule of ADR-0012: s is fresh at now under the
// operator's budget when now is a usable reading no earlier than NotBefore,
// and s was confirmed no longer than the budget before it. No snapshot, and
// one no statement confirmed, is never fresh.
func (s *Snapshot) FreshAt(now time.Time, operator time.Duration) bool {
	if s == nil || s.confirmedAt.IsZero() || !UsableTime(now) || now.Before(s.NotBefore()) {
		return false
	}
	return now.Sub(s.confirmedAt) <= Budget(s.maxStale, operator)
}

// Serial is the bundle's serial, the rollback check's input.
func (s *Snapshot) Serial() int64 {
	if s == nil {
		return 0
	}
	return s.serial
}

// ReadsExternal reports whether a rule of the bundle reads the external
// decision point's answer.
func (s *Snapshot) ReadsExternal() bool {
	return s != nil && s.program.ReadsExternal()
}

// Evaluate decides one envelope against the bundle's program.
func (s *Snapshot) Evaluate(env *controlv1.ActionEnvelope, in match.Inputs) match.Result {
	var program *match.Program
	if s != nil {
		program = s.program
	}
	return program.Evaluate(env, in)
}

// Explain evaluates as Evaluate does and also says how each rule read the call.
func (s *Snapshot) Explain(env *controlv1.ActionEnvelope, in match.Inputs) (match.Result, []match.RuleTrace) {
	var program *match.Program
	if s != nil {
		program = s.program
	}
	return program.Explain(env, in)
}
