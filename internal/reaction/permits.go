package reaction

import (
	"errors"
	"fmt"
	"time"

	"github.com/guardana/control/internal/policy"
)

// StopClaim is what a stop says of itself that a route judges: the tenant,
// the procedure and rule of the finding behind it, and its two times.
type StopClaim struct {
	TenantID                                       string
	ProcedureID, ProcedureVersion, ProcedureDigest string
	RuleID, RuleVersion                            string
	CreatedAt, ExpiresAt                           time.Time
}

// Permits returns nil when the route allows the stop c claims to be: its
// tenant is the route's, its procedure and rule are one rule of the route
// compared exactly, its times are usable with expires_at after created_at,
// and the span between them is within the rule's lifetime, or within
// MaxLifetime for a rule with none, since no run outlives it. The zero Route
// permits nothing.
func (r Route) Permits(c StopClaim) error {
	if c.TenantID == "" || c.TenantID != r.tenantID {
		return ErrClaimTenant
	}
	want := Rule{
		ProcedureID: c.ProcedureID, ProcedureVersion: c.ProcedureVersion, ProcedureDigest: c.ProcedureDigest,
		RuleID: c.RuleID, RuleVersion: c.RuleVersion,
	}.key()
	for _, rule := range r.rules {
		if rule.key() == want {
			return rule.permitsTimes(c.CreatedAt, c.ExpiresAt)
		}
	}
	return ErrClaimRule
}

// permitsListed is Permits for a stop line of a list: a stop naming a rule
// version StoppingRules superseded, which only a carry writes, is permitted
// as a stop of the version that replaced it, with that rule's lifetime.
func (r Route) permitsListed(c StopClaim) error {
	err := r.Permits(c)
	current, superseded := replacement(c.RuleID, c.RuleVersion)
	if !errors.Is(err, ErrClaimRule) || !superseded {
		return err
	}
	c.RuleVersion = current
	return r.Permits(c)
}

// CheckCurrent refuses, with ErrStopSuperseded, a stop naming a rule version
// StoppingRules superseded. The stop list's writers append no such stop; a
// list holds one only as a carry brought it.
func CheckCurrent(s Stop) error {
	if Superseded(s.RuleID, s.RuleVersion) {
		return fmt.Errorf("%w: rule_id %q rule_version %q", ErrStopSuperseded, s.RuleID, s.RuleVersion)
	}
	return nil
}

func (r Rule) permitsTimes(created, expires time.Time) error {
	if !policy.UsableTime(created) || !policy.UsableTime(expires) || !expires.After(created) {
		return ErrClaimTimes
	}
	limit := r.Lifetime
	if limit == 0 {
		limit = MaxLifetime
	}
	if span := expires.Sub(created); span > limit {
		return fmt.Errorf("%w: %s, limit %s", ErrClaimLifetime, span, limit)
	}
	return nil
}
