package gateway

import (
	"fmt"

	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/policy/rules"
)

// Capabilities is what an adapter declares it can do at the protocol it
// speaks. A capability that is not declared is one the plane never relies on,
// and a mode that needs one the adapter lacks is refused at start.
type Capabilities struct {
	// ObserveRequest: the adapter sees a call before the upstream does.
	ObserveRequest bool
	// ObserveResult: the adapter sees what the upstream answered.
	ObserveResult bool
	// Enforcement is how far the adapter can keep a call from its effect.
	Enforcement Enforcement
	// Authenticates: the adapter's listener establishes an end-user identity
	// before a call is translated. Without it there is no user to bind, only
	// a claim, so BindEndUser is refused.
	Authenticates bool
	// BindEndUser: the adapter carries an authenticated end-user identity into
	// the envelope's principal.
	BindEndUser bool
	// PresentsRuns: the adapter resolves a run token on every call, through
	// the runs directory the plane is configured with, and hands the run it
	// resolved in Admission.Run (ADR-0034).
	PresentsRuns bool
	// SeeDelegation: the adapter can read a delegation chain from the call.
	SeeDelegation bool
	// SeeResourceIDs: the adapter can name the resource a call touches.
	SeeResourceIDs bool
	// Obligations names the obligation types the adapter applies to the bytes
	// it sends upstream, each from the catalogue; they become the kernel's
	// applicable set, and an obligation outside them is a DENY per call.
	Obligations []string
}

// Enforcement is how far an adapter can keep a call from its effect, in the
// one vocabulary every reader takes it from; its zero value enforces nothing.
type Enforcement = channel.Strength

// The three strengths, under the names the adapters declare them by.
const (
	EnforcementNone        = channel.StrengthNone
	EnforcementCooperative = channel.StrengthCooperative
	EnforcementInline      = channel.StrengthInline
)

// Adapter is the seam between the pipeline and a protocol. It translates; the
// meaning of a call lives in the envelope it builds and in the policy, never
// here.
type Adapter interface {
	// Name is the protocol's, for evidence and health.
	Name() string
	// Capabilities is fixed for the adapter's lifetime.
	Capabilities() Capabilities
}

// covers reports whether every capability set in need is set in c, and c
// enforces at least as far as need does.
func (c Capabilities) covers(need Capabilities) bool {
	if c.Enforcement < need.Enforcement {
		return false
	}
	for _, pair := range [...]struct{ have, need bool }{
		{c.ObserveRequest, need.ObserveRequest},
		{c.ObserveResult, need.ObserveResult},
		{c.Authenticates, need.Authenticates},
		{c.BindEndUser, need.BindEndUser},
		{c.SeeDelegation, need.SeeDelegation},
		{c.SeeResourceIDs, need.SeeResourceIDs},
	} {
		if pair.need && !pair.have {
			return false
		}
	}
	return true
}

// checkObligations refuses a declared obligation type the catalogue does not
// know, naming its position.
func checkObligations(declared []string) error {
	for i, name := range declared {
		if !rules.KnownObligation(name) {
			return fmt.Errorf("%w: Obligations[%d]", ErrObligation, i)
		}
	}
	return nil
}
