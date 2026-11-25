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
	TenantID string
	// ProjectID and Scope are a stop's under a route an operator signed,
	// and empty under a v1alpha1 one.
	ProjectID, Scope                               string
	ProcedureID, ProcedureVersion, ProcedureDigest string
	RuleID, RuleVersion                            string
	CreatedAt, ExpiresAt                           time.Time
}

// Permits returns nil when the route allows the stop c claims to be: its
// tenant and project are the route's, its procedure and rule are one rule of the route
// compared exactly, its scope is that rule's, its times are usable with expires_at after created_at,
// and the span between them is within the rule's lifetime, or within
// MaxLifetime for a rule with none, since no run outlives it. The zero Route
// permits nothing.
func (r Route) Permits(c StopClaim) error {
	if c.TenantID == "" || c.TenantID != r.tenantID {
		return ErrClaimTenant
	}
	if c.ProjectID != r.projectID {
		return ErrClaimProject
	}
	want := Rule{
		ProcedureID: c.ProcedureID, ProcedureVersion: c.ProcedureVersion, ProcedureDigest: c.ProcedureDigest,
		RuleID: c.RuleID, RuleVersion: c.RuleVersion,
	}.key()
	for _, rule := range r.rules {
		if rule.key() == want {
			if c.Scope != rule.Scope {
				return ErrClaimScope
			}
			return rule.permitsTimes(c.CreatedAt, c.ExpiresAt)
		}
	}
	return ErrClaimRule
}

// permitsListed is Permits for a stop line of a list: a stop naming a rule
// version StoppingRules superseded, which only a carry writes, is permitted
// as a stop of the version that replaced it, with that rule's lifetime, and
// one naming a retired version as permitsRetired says.
func (r Route) permitsListed(c StopClaim) error {
	err := r.Permits(c)
	if !errors.Is(err, ErrClaimRule) {
		return err
	}
	if current, superseded := replacement(c.RuleID, c.RuleVersion); superseded {
		c.RuleVersion = current
		return r.Permits(c)
	}
	if mayWiden, ok := retired(c.RuleID, c.RuleVersion); ok {
		return r.permitsRetired(c, mayWiden)
	}
	return err
}

// permitsRetired permits a stop naming a retired rule version, which only a
// carry writes and the route no longer names, only within what the route
// grants now: a rule of the route names its procedure at its scope, which is
// run (none under a v1alpha1 route) or, for a version a route could let stop
// an agent or a principal, one of those, and the stop lasts no longer than
// that rule's lifetime. Its tenant and project are the route's, as Permits
// found.
func (r Route) permitsRetired(c StopClaim, mayWiden bool) error {
	runScope := ScopeRun
	if r.format == FormatV1Alpha1 {
		runScope = ""
	}
	if c.Scope != runScope && (!mayWiden || !wider(c.Scope)) {
		return ErrClaimScope
	}
	var err error = ErrClaimRule
	for _, rule := range r.rules {
		if rule.ProcedureID != c.ProcedureID || rule.ProcedureVersion != c.ProcedureVersion ||
			rule.ProcedureDigest != c.ProcedureDigest {
			continue
		}
		if rule.Scope != c.Scope {
			if errors.Is(err, ErrClaimRule) {
				err = ErrClaimScope
			}
			continue
		}
		if err = rule.permitsTimes(c.CreatedAt, c.ExpiresAt); err == nil {
			return nil
		}
	}
	return err
}

// CheckCurrent refuses, with ErrStopSuperseded, a stop naming a rule version
// StoppingRules superseded, and with ErrStopRetired one naming a retired
// version. The stop list's writers append no such stop; a list holds one
// only as a carry brought it.
func CheckCurrent(s Stop) error {
	switch {
	case Superseded(s.RuleID, s.RuleVersion):
		return fmt.Errorf("%w: rule_id %q rule_version %q", ErrStopSuperseded, s.RuleID, s.RuleVersion)
	case Retired(s.RuleID, s.RuleVersion):
		return fmt.Errorf("%w: rule_id %q rule_version %q", ErrStopRetired, s.RuleID, s.RuleVersion)
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
