package core_test

import (
	"slices"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/pkg/contract"
)

// allowOrder allows a READ of order ord-1 alone, so a call that names no
// resource id leaves it unknown.
const allowOrder = `{"id":"allow-order","effect":"ALLOW","when":{"action":{"effect":["READ"]},"resource":{"id":["ord-1"]}}}`

// TestAnUnknownAllowReachesTheOutcome: the ALLOW rules whose match is unknown
// travel on the outcome and nowhere on the decision, which stays the DENY of
// no matching rule; a call that names the id is decided by it.
func TestAnUnknownAllowReachesTheOutcome(t *testing.T) {
	withID := func(id string) func() *controlv1.ActionEnvelope {
		return func() *controlv1.ActionEnvelope {
			env := readEnvelope()
			env.Resource.Id = id
			return env
		}
	}
	for name, c := range map[string]struct {
		env     func() *controlv1.ActionEnvelope
		refusal error
		want    expect
		ruleIDs []string
		unknown []match.UnknownAllow
	}{
		"no resource id": {env: withID(""), want: expect{verdictDeny, core.Block, []string{codeNoMatchingRule}},
			unknown: []match.UnknownAllow{{ID: "allow-order", Needs: []string{"resource.id"}}}},
		"the allowed id": {env: withID("ord-1"), want: expect{verdictAllow, core.Execute, []string{codeRuleAllow}},
			ruleIDs: []string{"allow-order"}},
		"another id": {env: withID("ord-2"), want: expect{verdictDeny, core.Block, []string{codeNoMatchingRule}}},
		"a refused request": {env: withID(""), refusal: &contract.ValidationError{Field: "action.kind", Err: contract.ErrInvalidValue},
			want: expect{verdictIndeterminate, core.Block, []string{codeInvalidFieldValue}}},
	} {
		t.Run(name, func(t *testing.T) {
			req := request(c.env())
			req.Refusal = c.refusal
			out := decide(kernelAt(t, options()), req, snapshot(t, allowOrder))
			check(t, out, c.want)
			if !slices.EqualFunc(out.UnknownAllows, c.unknown, func(a, b match.UnknownAllow) bool { return a.ID == b.ID && slices.Equal(a.Needs, b.Needs) }) {
				t.Errorf("UnknownAllows = %+v, want %+v", out.UnknownAllows, c.unknown)
			}
			if got := out.Decision.GetPolicyRuleIds(); !slices.Equal(got, c.ruleIDs) {
				t.Errorf("PolicyRuleIds = %q, want %q", got, c.ruleIDs)
			}
		})
	}
}

// TestOnlyANoMatchDenyIsMarked: NoRuleMatched holds for the DENY of no
// matching rule alone. Every other DENY the kernel reaches, each beside no
// matching rule where it can be, leaves it false, and so does a decision that
// is not a DENY.
func TestOnlyANoMatchDenyIsMarked(t *testing.T) {
	const denyReads = `{"id":"deny-reads","effect":"DENY","when":{"action":{"effect":["READ"]}}}`
	tenants := readEnvelope()
	tenants.Resource.TenantId = "tenant-2"
	expired := readEnvelope()
	expired.Delegation = chain([]string{"read"}, base())
	oneTenant := writeEnvelope()
	oneTenant.Resource.TenantId = ""
	cases := []struct {
		name    string
		out     func(t *testing.T) core.Outcome
		verdict controlv1.Verdict
		marked  bool
	}{
		{"no rule matched", func(t *testing.T) core.Outcome {
			return decide(kernelAt(t, options()), request(readEnvelope()), snapshot(t, allowWrites))
		}, verdictDeny, true},
		{"a matched DENY", func(t *testing.T) core.Outcome {
			return decide(kernelAt(t, options()), request(readEnvelope()), snapshot(t, denyReads))
		}, verdictDeny, false},
		{"two tenants, and no rule matched", func(t *testing.T) core.Outcome {
			return decide(kernelAt(t, options()), request(tenants), snapshot(t, allowWrites))
		}, verdictDeny, false},
		{"one tenant on a material call, and no rule matched", func(t *testing.T) core.Outcome {
			return decide(kernelAt(t, options()), request(oneTenant), snapshot(t, allowReads))
		}, verdictDeny, false},
		{"a refused chain, and no rule matched", func(t *testing.T) core.Outcome {
			return decide(kernelAt(t, options()), request(expired), snapshot(t, allowWrites))
		}, verdictDeny, false},
		{"a stale bundle, and no rule matched", func(t *testing.T) core.Outcome {
			return decide(kernelAt(t, options()), request(readEnvelope()), snapshotAt(t, document(300, allowWrites), base().Add(-time.Hour)))
		}, verdictDeny, false},
		{"an answer consulted, and no rule matched", func(t *testing.T) core.Outcome {
			req := request(readEnvelope())
			req.External = core.ExternalAllowed()
			return decide(kernelAt(t, withDecisionPoint()), req, snapshot(t, vetoReads))
		}, verdictDeny, false},
		{"an obligation the kernel cannot apply", func(t *testing.T) core.Outcome {
			return decide(kernelAt(t, options()), request(readEnvelope()), snapshot(t, sandboxedReads))
		}, verdictDeny, false},
		{"no bundle", func(t *testing.T) core.Outcome {
			return decide(kernelAt(t, options()), request(readEnvelope()), nil)
		}, verdictIndeterminate, false},
		{"an undetermined rule", func(t *testing.T) core.Outcome {
			return decide(kernelAt(t, options()), request(readEnvelope()), snapshot(t, vetoReads))
		}, verdictIndeterminate, false},
		{"an ALLOW", func(t *testing.T) core.Outcome {
			return decide(kernelAt(t, options()), request(readEnvelope()), snapshot(t, allowReads))
		}, verdictAllow, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := c.out(t)
			if out.Decision.GetVerdict() != c.verdict || out.NoRuleMatched != c.marked {
				t.Errorf("%s %q, NoRuleMatched %t; want %s and %t", out.Decision.GetVerdict(), out.Decision.GetReasonCodes(), out.NoRuleMatched, c.verdict, c.marked)
			}
		})
	}
}
