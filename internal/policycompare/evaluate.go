package policycompare

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/match"
)

// needsExternal is what a trace names for a rule that waits on the external
// decision point's answer.
const needsExternal = "external"

const codeTenantMismatch = "TENANT_MISMATCH"

// loader loads one policy once for each instant a case loads it at.
type loader struct {
	policy Policy
	loads  map[instant]loaded
}

// instant is a time without its location, which no load reads.
type instant struct {
	sec  int64
	nsec int
}

type loaded struct {
	snap *policy.Snapshot
	err  error
}

func newLoader(p Policy) *loader {
	return &loader{policy: p, loads: map[instant]loaded{}}
}

func (l *loader) load(at time.Time) (*policy.Snapshot, error) {
	key := instant{at.Unix(), at.Nanosecond()}
	got, ok := l.loads[key]
	if !ok {
		got.snap, got.err = policy.Load(l.policy.Bundle, l.policy.Keys, at)
		l.loads[key] = got
	}
	return got.snap, got.err
}

// evaluate loads the policy at the case's loaded_at and decides the case at
// its decided_at through Kernel.Explain, which decides as the plane's Decide
// does. A side that cannot be loaded or decided, or on which no rule was
// evaluated, is not evaluated: its decision says nothing about the policy.
func evaluate(l *loader, in Input) side {
	snap, err := l.load(in.LoadedAt)
	if err != nil {
		return side{err: "the policy did not load: " + err.Error()}
	}
	kernel, err := core.New(in.Options, func() time.Time { return in.DecidedAt }, func() string { return "policy-compare" })
	if err != nil {
		return side{err: "the kernel refused the case's options: " + err.Error()}
	}
	out, why := kernel.Explain(context.Background(), core.Request{
		Envelope:       in.Envelope,
		Refusal:        in.Refusal,
		AuthorizedArgs: in.AuthorizedArgs,
		Flow:           in.Flow,
		External:       in.External,
	}, snap)
	d := out.Decision
	if d == nil {
		return side{err: "the kernel returned no decision"}
	}
	if reason := ownDecision(why, d); reason != "" {
		return side{err: reason}
	}
	s := side{
		evaluated:   true,
		verdict:     d.GetVerdict(),
		action:      out.Action,
		codes:       slices.Clone(d.GetReasonCodes()),
		obligations: d.GetObligations(),
		stale:       d.GetPolicyFreshness() != controlv1.PolicyFreshness_POLICY_FRESHNESS_FRESH,
	}
	// One tenant named on a material call is undetermined whatever the rules
	// allow, so the tenant left out is a fact the case lacks.
	if why.TenantUnstated != "" {
		s.missing = append(s.missing, why.TenantUnstated)
	}
	s.readTraces(why.Rules)
	return s
}

// ownDecision names why the kernel decided a side without its rules, or
// regardless of them, or is empty when the rules decided it: no rule was
// evaluated, the delegation chain was refused, or the two tenants differ.
// The last two are DENYs of the kernel's own on every policy; a rule cannot
// name TENANT_MISMATCH, so the code is the kernel's.
func ownDecision(why core.Explanation, d *controlv1.Decision) string {
	switch {
	case why.Rules == nil:
		return fmt.Sprintf("no rule was evaluated: the kernel decided %s %v before the policy",
			verdictName(d.GetVerdict()), d.GetReasonCodes())
	case why.Delegation.State == core.DelegationRefused:
		return fmt.Sprintf("the kernel refused the delegation chain %s, a DENY of its own whatever the rules decide",
			strconv.Quote(why.Delegation.Code))
	case slices.Contains(d.GetReasonCodes(), codeTenantMismatch):
		return "the principal's and the resource's tenants differ, a DENY of the kernel's own whatever the rules decide"
	}
	return ""
}

// readTraces adds every input an undetermined rule lacked to s.missing.
func (s *side) readTraces(rules []match.RuleTrace) {
	for _, tr := range rules {
		// A rule a false constraint decided reads no unknown into the
		// decision, whatever else it could not read.
		if tr.Value != match.ValueUnknown {
			continue
		}
		for _, u := range tr.Unknown {
			for _, need := range u.Needs {
				s.external = s.external || need == needsExternal
				if !slices.Contains(s.missing, need) {
					s.missing = append(s.missing, need)
				}
			}
		}
	}
}
