package match_test

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/policy/rules"
)

// Short spellings of generated names, so that a table row fits on a line. Each
// is the generated constant itself, never a number, so none can be bound to the
// wrong value.
const (
	allow           = controlv1.Verdict_VERDICT_ALLOW
	deny            = controlv1.Verdict_VERDICT_DENY
	approval        = controlv1.Verdict_VERDICT_REQUIRE_APPROVAL
	withObligations = controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS
	indeterminate   = controlv1.Verdict_VERDICT_INDETERMINATE

	unlabelled   = controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED
	public       = controlv1.Sensitivity_SENSITIVITY_PUBLIC
	internal     = controlv1.Sensitivity_SENSITIVITY_INTERNAL
	confidential = controlv1.Sensitivity_SENSITIVITY_CONFIDENTIAL
	restricted   = controlv1.Sensitivity_SENSITIVITY_RESTRICTED
	secret       = controlv1.Sensitivity_SENSITIVITY_SECRET

	zoneUnset    = controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED
	zoneInternal = controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL
	zonePartner  = controlv1.TrustZone_TRUST_ZONE_PARTNER
	zoneExternal = controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL

	effectUnset = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
	read        = controlv1.EffectClass_EFFECT_CLASS_READ
	write       = controlv1.EffectClass_EFFECT_CLASS_WRITE
	remove      = controlv1.EffectClass_EFFECT_CLASS_DELETE
	communicate = controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE
	transact    = controlv1.EffectClass_EFFECT_CLASS_TRANSACT
)

// envelope is a READ call that sets every field a constraint can read, and one
// Validate accepts, so a row that clears one field tests that absence alone.
func envelope() *controlv1.ActionEnvelope {
	return &controlv1.ActionEnvelope{
		SchemaVersion: "1.0",
		RequestId:     "req-1",
		OccurredAt:    &timestamppb.Timestamp{Seconds: 1789128000},
		ProjectId:     "proj-1",
		TenantId:      "tenant-a",
		Environment:   "prod",
		Principal: &controlv1.Principal{
			Id: "alice", Type: "user", AuthnStrength: "mfa", TenantId: "tenant-a",
			Attributes: map[string]string{"team": "payments"},
		},
		Agent:  &controlv1.Agent{Id: "agent-7", Framework: "langgraph"},
		Action: &controlv1.Action{Kind: "tool_call", Name: "refund", Protocol: "mcp", Effect: read, Provider: "payments"},
		Resource: &controlv1.Resource{
			Type: "invoice", Id: "inv-1", TenantId: "tenant-a", Environment: "prod",
			Labels: map[string]string{"tier": "gold"},
		},
		Destination: &controlv1.Destination{TrustZone: zoneInternal, Host: "ledger.internal"},
		Data:        &controlv1.DataLabels{Sensitivities: []controlv1.Sensitivity{internal}},
	}
}

// with returns envelope() after one edit, so a row states the field it changes.
func with(edit func(*controlv1.ActionEnvelope)) *controlv1.ActionEnvelope {
	env := envelope()
	edit(env)
	return env
}

// document wraps rules in the document Parse returns around them.
func document(rs ...rules.Rule) *rules.Document {
	return &rules.Document{
		APIVersion: "agent-policy/v1alpha1",
		Bundle:     rules.Bundle{ID: "payments", Version: "2026-09-11.1", Serial: 1, MaxStaleSeconds: 300},
		Rules:      rs,
	}
}

func compile(t testing.TB, rs ...rules.Rule) *match.Program {
	t.Helper()
	p, err := match.Compile(document(rs...))
	if err != nil {
		t.Fatalf("Compile refused a document this test builds as valid: %v", err)
	}
	return p
}

func actionNamed(names ...string) rules.When {
	return rules.When{Action: &rules.ActionWhen{Name: names}}
}

func list(values ...string) []string { return values }

// want is an expected Result, written out by the test that uses it.
type want struct {
	verdict, determinate     controlv1.Verdict
	ids, undetermined, codes []string
	obligations              []*controlv1.Obligation
	external                 []string
	unknownAllows            []string
}

// assertResult compares; it never computes an expectation.
func assertResult(t testing.TB, got match.Result, w want) {
	t.Helper()
	if got.Verdict != w.verdict {
		t.Errorf("Verdict = %s, want %s", got.Verdict, w.verdict)
	}
	if got.Determinate != w.determinate {
		t.Errorf("Determinate = %s, want %s", got.Determinate, w.determinate)
	}
	if !slices.Equal(got.RuleIDs, w.ids) {
		t.Errorf("RuleIDs = %q, want %q", got.RuleIDs, w.ids)
	}
	if !slices.Equal(got.Indeterminate, w.undetermined) {
		t.Errorf("Indeterminate = %q, want %q", got.Indeterminate, w.undetermined)
	}
	if !slices.Equal(got.ReasonCodes, w.codes) {
		t.Errorf("ReasonCodes = %q, want %q", got.ReasonCodes, w.codes)
	}
	if !sameObligations(got.Obligations, w.obligations) {
		t.Errorf("Obligations = %s, want %s", describe(got.Obligations), describe(w.obligations))
	}
	if !slices.Equal(got.ReadExternal, w.external) {
		t.Errorf("ReadExternal = %q, want %q", got.ReadExternal, w.external)
	}
	if got := unknownIDs(got); !slices.Equal(got, w.unknownAllows) {
		t.Errorf("UnknownAllows name %q, want %q", got, w.unknownAllows)
	}
}

// unknownIDs are the ids UnknownAllows lists, in its order.
func unknownIDs(r match.Result) []string {
	var out []string
	for _, u := range r.UnknownAllows {
		out = append(out, u.ID)
	}
	return out
}

func sameUnknownAllows(a, b []match.UnknownAllow) bool {
	return slices.EqualFunc(a, b, func(x, y match.UnknownAllow) bool { return x.ID == y.ID && slices.Equal(x.Needs, y.Needs) })
}

func sameObligations(a, b []*controlv1.Obligation) bool {
	return slices.EqualFunc(a, b, func(x, y *controlv1.Obligation) bool { return proto.Equal(x, y) })
}

func describe(obs []*controlv1.Obligation) string {
	parts := make([]string, 0, len(obs))
	for _, o := range obs {
		var params []string
		for _, k := range slices.Sorted(maps.Keys(o.GetParams())) {
			params = append(params, k+"="+o.GetParams()[k])
		}
		parts = append(parts, fmt.Sprintf("%s{%s advisory=%t}", o.GetType(), strings.Join(params, ","), o.GetAdvisory()))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func summary(r match.Result) string {
	return fmt.Sprintf("{%s determinate=%s ids=%q undetermined=%q codes=%q obligations=%s external=%q unknown-allows=%+v}",
		r.Verdict, r.Determinate, r.RuleIDs, r.Indeterminate, r.ReasonCodes, describe(r.Obligations), r.ReadExternal, r.UnknownAllows)
}

// failer is what *testing.T and *rapid.T both offer, so one assertion serves a
// table, a property and a fuzz target.
type failer interface {
	Helper()
	Fatalf(format string, args ...any)
}

func assertSame(f failer, what string, a, b match.Result) {
	f.Helper()
	if a.Verdict != b.Verdict || a.Determinate != b.Determinate ||
		!slices.Equal(a.RuleIDs, b.RuleIDs) || !slices.Equal(a.Indeterminate, b.Indeterminate) ||
		!slices.Equal(a.ReasonCodes, b.ReasonCodes) || !sameObligations(a.Obligations, b.Obligations) ||
		!slices.Equal(a.ReadExternal, b.ReadExternal) || !sameUnknownAllows(a.UnknownAllows, b.UnknownAllows) {
		f.Fatalf("%s: %s, and before it %s", what, summary(b), summary(a))
	}
}

// inOrder checks that ids appear in order, each once.
func inOrder(f failer, what string, ids, order []string) {
	f.Helper()
	last := -1
	for _, id := range ids {
		at := slices.Index(order, id)
		if at <= last {
			f.Fatalf("%s %q is not a list of the program's rules in document order %q", what, ids, order)
		}
		last = at
	}
}

// assertWellFormed holds a Result to what Result's fields and ADR-0012
// promise of every one, whatever the inputs. order is the program's rule ids
// in document order, and effects the effect of each of them.
func assertWellFormed(f failer, order []string, effects map[string]controlv1.Verdict, got match.Result) {
	f.Helper()
	switch got.Verdict {
	case allow, deny, approval, withObligations, indeterminate:
	default:
		f.Fatalf("Verdict %s is not one of the five", got.Verdict)
	}
	switch got.Determinate {
	case allow, deny, approval, withObligations:
	default:
		f.Fatalf("Determinate %s: it leaves every indeterminate rule out, so it is never INDETERMINATE or unset", got.Determinate)
	}
	inOrder(f, "RuleIDs", got.RuleIDs, order)
	inOrder(f, "Indeterminate", got.Indeterminate, order)
	inOrder(f, "ReadExternal", got.ReadExternal, order)
	assertUnknownAllowsWellFormed(f, order, effects, got)
	for _, id := range got.ReadExternal {
		if effects[id] != deny {
			f.Fatalf("%s rule %s reads the external answer; only a DENY rule may", effects[id], id)
		}
	}
	for _, id := range got.Indeterminate {
		if effects[id] == allow {
			f.Fatalf("ALLOW rule %s is listed indeterminate; an unknown ALLOW is no match", id)
		}
		if slices.Contains(got.RuleIDs, id) {
			f.Fatalf("rule %s is both matched and indeterminate", id)
		}
	}
	if matchedDeny(effects, got) && (got.Verdict != deny || got.Determinate != deny) {
		f.Fatalf("a matched DENY rule decides, yet %s", summary(got))
	}
	assertCodesWellFormed(f, effects, got)
	assertObligationsWellFormed(f, got)
}

// assertUnknownAllowsWellFormed: UnknownAllows lists ALLOW rules alone, in
// document order, none of them matched or indeterminate, each lacking at
// least one input and naming each once.
func assertUnknownAllowsWellFormed(f failer, order []string, effects map[string]controlv1.Verdict, got match.Result) {
	f.Helper()
	inOrder(f, "UnknownAllows", unknownIDs(got), order)
	for _, u := range got.UnknownAllows {
		if effects[u.ID] != allow {
			f.Fatalf("%s rule %s is listed as an unknown ALLOW", effects[u.ID], u.ID)
		}
		if slices.Contains(got.RuleIDs, u.ID) || slices.Contains(got.Indeterminate, u.ID) {
			f.Fatalf("unknown ALLOW rule %s is also matched or indeterminate: %s", u.ID, summary(got))
		}
		if len(u.Needs) == 0 || len(slices.Compact(slices.Sorted(slices.Values(u.Needs)))) != len(u.Needs) {
			f.Fatalf("unknown ALLOW rule %s lacked %q: none, or one twice", u.ID, u.Needs)
		}
	}
}

func matchedDeny(effects map[string]controlv1.Verdict, got match.Result) bool {
	return slices.ContainsFunc(got.RuleIDs, func(id string) bool { return effects[id] == deny })
}

func assertCodesWellFormed(f failer, effects map[string]controlv1.Verdict, got match.Result) {
	f.Helper()
	codes := got.ReasonCodes
	if len(codes) == 0 {
		f.Fatalf("no reason code in %s: every result names its cause", summary(got))
	}
	for i, c := range codes {
		if slices.Contains(codes[:i], c) {
			f.Fatalf("reason %s appears twice in %q", c, codes)
		}
	}
	assertMatcherCodes(f, effects, got)
}

// assertMatcherCodes holds the two codes the matcher adds of its own to the
// results that carry them, and to their place, and INDETERMINATE to the
// indeterminate rules both ways.
func assertMatcherCodes(f failer, effects map[string]controlv1.Verdict, got match.Result) {
	f.Helper()
	codes := got.ReasonCodes
	undetermined := len(got.Indeterminate) > 0
	if slices.Contains(codes, "RULE_UNDETERMINED") != undetermined || (undetermined && codes[len(codes)-1] != "RULE_UNDETERMINED") {
		f.Fatalf("RULE_UNDETERMINED belongs last exactly when a rule is indeterminate: %s", summary(got))
	}
	nothing := len(got.RuleIDs) == 0 && !undetermined
	if slices.Contains(codes, "NO_MATCHING_RULE") != nothing || (nothing && len(codes) != 1) {
		f.Fatalf("NO_MATCHING_RULE belongs alone exactly when no rule matched or was indeterminate: %s", summary(got))
	}
	assertIndeterminateBothWays(f, effects, got)
}

// assertIndeterminateBothWays: INDETERMINATE names an indeterminate rule, and
// an indeterminate rule with no matched DENY beside it makes the verdict
// INDETERMINATE, whatever else matched.
func assertIndeterminateBothWays(f failer, effects map[string]controlv1.Verdict, got match.Result) {
	f.Helper()
	undetermined := len(got.Indeterminate) > 0
	if got.Verdict == indeterminate && !undetermined {
		f.Fatalf("INDETERMINATE names no indeterminate rule: %s", summary(got))
	}
	if undetermined && !matchedDeny(effects, got) && got.Verdict != indeterminate {
		f.Fatalf("an indeterminate rule and no matched DENY, yet %s", summary(got))
	}
}

func assertObligationsWellFormed(f failer, got match.Result) {
	f.Helper()
	switch got.Verdict {
	case withObligations:
		if len(got.Obligations) == 0 {
			f.Fatalf("ALLOW_WITH_OBLIGATIONS with no obligation is never produced: %s", summary(got))
		}
	case approval:
	default:
		if len(got.Obligations) != 0 {
			f.Fatalf("obligations bind only a call that proceeds, and %s does not: %s", got.Verdict, summary(got))
		}
	}
	for i, o := range got.Obligations {
		for _, earlier := range got.Obligations[:i] {
			if proto.Equal(o, earlier) {
				f.Fatalf("obligation %s is kept twice: %s", describe([]*controlv1.Obligation{o}), summary(got))
			}
		}
	}
}
