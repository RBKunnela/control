package match_test

import (
	"slices"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"
	"pgregory.net/rapid"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// Each property below also holds one rule whose value it fixes by
// construction, its anchor, to what ADR-0012 makes of that value. An
// evaluator that gives one answer to every call, or that reads a rule's value
// wrongly, then fails the property itself, and not only the tables.

// TestAddingADenyRuleNeverPermitsMore: a DENY rule inserted anywhere, built to
// hold, to be unknown or to fail, is the anchor. Held, it is matched and the
// verdict is DENY; unknown, it is indeterminate, the call is blocked, and
// Determinate does not change; failed, nothing about the result changes. The
// other rules read as they did, and neither the verdict nor Determinate
// becomes more permissive.
func TestAddingADenyRuleNeverPermitsMore(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		base := drawDocument(rt)
		added := drawAnchor(rt, "added", deny)
		grown := slices.Insert(slices.Clone(base), rapid.IntRange(0, len(base)).Draw(rt, "position"), added.spec)
		env, in := drawEnvelope(rt), drawInputs(rt)
		added.set(env)

		before := mustCompile(rt, base.build()).Evaluate(env, in)
		after := mustCompile(rt, grown.build()).Evaluate(env, in)

		added.check(rt, after)
		others := func(ids []string) []string {
			return slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return id == added.spec.id })
		}
		if !slices.Equal(others(after.RuleIDs), before.RuleIDs) || !slices.Equal(others(after.Indeterminate), before.Indeterminate) {
			rt.Fatalf("adding a rule changed what the others read as: %s, and before it %s", summary(after), summary(before))
		}
		switch added.value {
		case unknown:
			if after.Determinate != before.Determinate {
				rt.Fatalf("Determinate leaves an indeterminate rule out, yet it changed: %s, and before it %s", summary(after), summary(before))
			}
		case fails:
			assertSame(rt, "with a DENY rule built to fail", before, after)
		}
		assertNoMorePermissive(rt, before, after)
	})
}

// TestAddingAnUnknownAllowMovesNoVerdict: an ALLOW rule inserted anywhere and
// built to be unknown is no match. Every list but UnknownAllows is what it was
// without it, and UnknownAllows is what it was with the rule's id at its place
// in document order (invariant 4: an unknown never becomes a permit).
func TestAddingAnUnknownAllowMovesNoVerdict(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		base := drawDocument(rt)
		added := drawAnchor(rt, "unknown-allow", allow)
		added.value = unknown
		at := rapid.IntRange(0, len(base)).Draw(rt, "position")
		grown := slices.Insert(slices.Clone(base), at, added.spec)
		env, in := drawEnvelope(rt), drawInputs(rt)
		added.set(env)

		before := mustCompile(rt, base.build()).Evaluate(env, in)
		after := mustCompile(rt, grown.build()).Evaluate(env, in)

		withAdded := after
		withAdded.UnknownAllows = before.UnknownAllows
		assertSame(rt, "an unknown ALLOW moved the result", before, withAdded)
		var want []string
		for _, s := range grown {
			if s.id == added.spec.id || slices.Contains(unknownIDs(before), s.id) {
				want = append(want, s.id)
			}
		}
		if got := unknownIDs(after); !slices.Equal(got, want) {
			rt.Fatalf("UnknownAllows name %q, want %q: the earlier ones and %s at its place", got, want, added.spec.id)
		}
		at = slices.Index(unknownIDs(after), added.spec.id)
		if u := after.UnknownAllows[at]; !slices.Equal(u.Needs, []string{"principal.type"}) {
			rt.Fatalf("the added rule lacked %q, want only principal.type", u.Needs)
		}
	})
}

// TestRemovingAnAllowRuleNeverPermitsMore: without one of its ALLOW rules a
// document permits no more, and an ALLOW rule that did not match changes
// nothing when it goes but its place among the unknown allows. The anchor is
// an ALLOW rule, which may be the one removed.
func TestRemovingAnAllowRuleNeverPermitsMore(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		base := drawDocument(rt)
		extra := drawAnchor(rt, "extra-allow", allow)
		base = slices.Insert(base, rapid.IntRange(0, len(base)).Draw(rt, "position"), extra.spec)
		var allows []int
		for i, s := range base {
			if s.effect == allow {
				allows = append(allows, i)
			}
		}
		at := rapid.SampledFrom(allows).Draw(rt, "removed")
		removed := base[at].id
		shrunk := slices.Delete(slices.Clone(base), at, at+1)
		env, in := drawEnvelope(rt), drawInputs(rt)
		extra.set(env)

		before := mustCompile(rt, base.build()).Evaluate(env, in)
		after := mustCompile(rt, shrunk.build()).Evaluate(env, in)

		extra.check(rt, before)
		if !slices.Contains(before.RuleIDs, removed) {
			before.UnknownAllows = slices.DeleteFunc(before.UnknownAllows, func(u match.UnknownAllow) bool { return u.ID == removed })
			assertSame(rt, "without an ALLOW rule that did not match", before, after)
		}
		assertNoMorePermissive(rt, before, after)
	})
}

// TestRuleOrderChangesOnlyTheOrderOfLists: the same rules in another order give
// the same verdicts, and lists that hold the same members in the new document
// order.
func TestRuleOrderChangesOnlyTheOrderOfLists(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		base, fixed := withAnchor(rt, drawDocument(rt))
		shuffled := rapid.Permutation(base).Draw(rt, "order")
		env, in := drawEnvelope(rt), drawInputs(rt)
		fixed.set(env)

		a := mustCompile(rt, base.build()).Evaluate(env, in)
		b := mustCompile(rt, shuffled.build()).Evaluate(env, in)

		fixed.check(rt, a)
		fixed.check(rt, b)
		if a.Verdict != b.Verdict || a.Determinate != b.Determinate {
			rt.Fatalf("reordering the rules changed a verdict: %s, and before %s", summary(b), summary(a))
		}
		for _, l := range []struct {
			name          string
			before, after []string
		}{
			{"RuleIDs", a.RuleIDs, b.RuleIDs},
			{"Indeterminate", a.Indeterminate, b.Indeterminate},
			{"ReasonCodes", a.ReasonCodes, b.ReasonCodes},
		} {
			if !sameMembers(l.before, l.after) {
				rt.Fatalf("reordering the rules changed what %s holds: %q, and before %q", l.name, l.after, l.before)
			}
		}
		inOrder(rt, "RuleIDs", b.RuleIDs, shuffled.ids())
		inOrder(rt, "Indeterminate", b.Indeterminate, shuffled.ids())
		assertCodesInDocumentOrder(rt, shuffled, b)
		assertObligationsInDocumentOrder(rt, shuffled, a, b)
	})
}

// TestEvaluationIsAPureFunction: the same program and inputs give the same
// result after any other calls, and so does a program compiled separately
// from the same document; nothing Evaluate is given changes.
func TestEvaluationIsAPureFunction(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		spec, fixed := withAnchor(rt, drawDocument(rt))
		env, in := drawEnvelope(rt), drawInputs(rt)
		fixed.set(env)
		others := rapid.SliceOfN(rapid.Custom(drawCall), 0, 8).Draw(rt, "others")

		first := mustCompile(rt, spec.build())
		second := mustCompile(rt, spec.build())
		envBefore := proto.Clone(env)
		scopesBefore := slices.Clone(in.Scopes)

		want := first.Evaluate(env, in)
		fixed.check(rt, want)
		for _, o := range others {
			first.Evaluate(o.env, o.in)
			second.Evaluate(o.env, o.in)
		}
		assertSame(rt, "the same program after other calls", want, first.Evaluate(env, in))
		assertSame(rt, "a program compiled separately", want, second.Evaluate(env, in))
		if !proto.Equal(env, envBefore) {
			rt.Fatalf("Evaluate changed the envelope it was given")
		}
		if !slices.Equal(in.Scopes, scopesBefore) {
			rt.Fatalf("Evaluate changed the caller's scopes from %q to %q", scopesBefore, in.Scopes)
		}
	})
}

// TestEveryResultIsWellFormed holds every result to assertWellFormed, over
// documents and calls nobody chose.
func TestEveryResultIsWellFormed(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		spec, fixed := withAnchor(rt, drawDocument(rt))
		env := drawEnvelope(rt)
		fixed.set(env)
		got := mustCompile(rt, spec.build()).Evaluate(env, drawInputs(rt))
		assertWellFormed(rt, spec.ids(), spec.effects(), got)
		fixed.check(rt, got)
	})
}

// anchor is a rule whose value a property fixes by construction. It reads
// principal.type alone, which no drawn rule reads and no drawn envelope sets,
// so the envelope it is set into decides whether it holds, is unknown or
// fails, whatever else the document and the call hold.
type anchor struct {
	spec  ruleSpec
	value truth
}

func drawAnchor(rt *rapid.T, id string, effect controlv1.Verdict) anchor {
	s := drawRuleHead(rt, id, effect)
	s.constraints = []constraintSpec{{kind: kindType, values: list("auditor")}}
	return anchor{spec: s, value: rapid.SampledFrom([]truth{holds, unknown, fails}).Draw(rt, id+".value")}
}

// withAnchor inserts an anchor of a drawn effect at a drawn place in spec.
func withAnchor(rt *rapid.T, spec docSpec) (docSpec, anchor) {
	a := drawAnchor(rt, "anchor", rapid.SampledFrom(fourEffects()).Draw(rt, "anchor.effect"))
	return slices.Insert(slices.Clone(spec), rapid.IntRange(0, len(spec)).Draw(rt, "anchor.position"), a.spec), a
}

// set gives the envelope the principal.type that makes the anchor hold, fail
// or be unknown.
func (a anchor) set(env *controlv1.ActionEnvelope) {
	switch a.value {
	case holds:
		env.Principal.Type = "auditor"
	case fails:
		env.Principal.Type = "contractor"
	default:
		env.Principal.Type = ""
	}
}

// check holds a result to what ADR-0012 makes of the anchor. Held, it is
// matched, and a matched DENY decides. Unknown and restrictive, it is
// indeterminate, and the call is blocked. An unknown ALLOW is no match and is
// listed among the unknown allows alone. A failed rule is listed nowhere.
func (a anchor) check(f failer, got match.Result) {
	f.Helper()
	id := a.spec.id
	matched := a.value == holds
	undetermined := a.value == unknown && a.spec.effect != allow
	unknownAllow := a.value == unknown && a.spec.effect == allow
	if slices.Contains(got.RuleIDs, id) != matched || slices.Contains(got.Indeterminate, id) != undetermined ||
		slices.Contains(unknownIDs(got), id) != unknownAllow {
		f.Fatalf("%s rule %s, built to %s, gave %s", a.spec.effect, id, map[truth]string{holds: "hold", unknown: "be unknown", fails: "fail"}[a.value], summary(got))
	}
	if matched && a.spec.effect == deny && (got.Verdict != deny || got.Determinate != deny) {
		f.Fatalf("a DENY rule built to hold decides, yet %s", summary(got))
	}
	if undetermined && rank(f, got.Verdict) != 0 {
		f.Fatalf("%s rule %s, built to be unknown, blocks the call, yet %s", a.spec.effect, id, summary(got))
	}
}

// assertNoMorePermissive compares what two results let a call do.
func assertNoMorePermissive(f failer, before, after match.Result) {
	f.Helper()
	if rank(f, after.Verdict) > rank(f, before.Verdict) {
		f.Fatalf("the verdict became more permissive: %s, and before %s", summary(after), summary(before))
	}
	if rank(f, after.Determinate) > rank(f, before.Determinate) {
		f.Fatalf("Determinate became more permissive: %s, and before %s", summary(after), summary(before))
	}
}

// rank orders verdicts by what ADR-0012's enforcement table lets a call do,
// most restrictive first. DENY blocks, and so does INDETERMINATE out of the
// matcher: its only cause here is RULE_UNDETERMINED, an input cause, which
// blocks every class. REQUIRE_APPROVAL waits; the other two run, with
// obligations and without.
func rank(f failer, v controlv1.Verdict) int {
	f.Helper()
	switch v {
	case deny, indeterminate:
		return 0
	case approval:
		return 1
	case withObligations:
		return 2
	case allow:
		return 3
	}
	f.Fatalf("%s is not one of the five verdicts", v)
	return -1
}

// assertCodesInDocumentOrder: the codes matched rules contribute come first, in
// the order of the first matched rule carrying each; the matcher's own two
// follow them.
func assertCodesInDocumentOrder(f failer, spec docSpec, got match.Result) {
	f.Helper()
	first := make(map[string]int)
	for i, s := range spec {
		if _, seen := first[s.code()]; !seen && slices.Contains(got.RuleIDs, s.id) {
			first[s.code()] = i
		}
	}
	last, own, fromRules := -1, false, 0
	for _, code := range got.ReasonCodes {
		at, fromRule := first[code]
		switch {
		case !fromRule:
			own = true
		case own:
			f.Fatalf("rule reason %s follows the matcher's own codes in %q", code, got.ReasonCodes)
		case at <= last:
			f.Fatalf("reason codes %q are not in the order of document %q", got.ReasonCodes, spec.ids())
		default:
			last, fromRules = at, fromRules+1
		}
	}
	if fromRules != len(first) {
		f.Fatalf("reason codes %q leave out a matched rule's reason (%d of %d)", got.ReasonCodes, fromRules, len(first))
	}
}

// assertObligationsInDocumentOrder: the same obligations as before, each at the
// place of its first carrier among the matched rules of the new order.
func assertObligationsInDocumentOrder(f failer, spec docSpec, before, got match.Result) {
	f.Helper()
	if len(before.Obligations) != len(got.Obligations) {
		f.Fatalf("reordering the rules changed the obligations: %s, and before %s", describe(got.Obligations), describe(before.Obligations))
	}
	for _, o := range got.Obligations {
		if !slices.ContainsFunc(before.Obligations, func(x *controlv1.Obligation) bool { return proto.Equal(x, o) }) {
			f.Fatalf("reordering the rules changed the obligations: %s, and before %s", describe(got.Obligations), describe(before.Obligations))
		}
	}
	lastRule, lastIndex := -1, -1
	for _, o := range got.Obligations {
		rule, index, ok := firstCarrier(spec, got.RuleIDs, o)
		if !ok {
			f.Fatalf("obligation %s is carried by no matched rule", describe([]*controlv1.Obligation{o}))
		}
		if rule < lastRule || (rule == lastRule && index <= lastIndex) {
			f.Fatalf("obligations %s are not in document order", describe(got.Obligations))
		}
		lastRule, lastIndex = rule, index
	}
}

func firstCarrier(spec docSpec, matched []string, o *controlv1.Obligation) (rule, index int, ok bool) {
	for i, s := range spec {
		if !slices.Contains(matched, s.id) {
			continue
		}
		for j, carried := range s.obligations {
			if proto.Equal(carried.proto(), o) {
				return i, j, true
			}
		}
	}
	return 0, 0, false
}

func sameMembers(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

func mustCompile(f failer, doc *rules.Document) *match.Program {
	f.Helper()
	p, err := match.Compile(doc)
	if err != nil {
		f.Fatalf("Compile refused a drawn document: %v", err)
	}
	return p
}

// Kinds of constraint the properties draw, and one they never draw.
const (
	kindPrincipal = iota
	kindTenant
	kindTeam
	kindAgent
	kindName
	kindEffect
	kindEnvironment
	kindTier
	kindZone
	kindData
	kindFlow
	kindScopes
	constraintKinds

	// kindType is principal.type, which no drawn rule reads and no drawn
	// envelope sets; only an anchor reads it.
	kindType = constraintKinds
	allKinds = constraintKinds + 1
)

// vocabulary is small on purpose, so that drawn rules hold, fail and cannot be
// told against drawn calls in roughly equal measure.
func vocabulary(kind int) []string {
	switch kind {
	case kindPrincipal:
		return list("alice", "bob")
	case kindTenant:
		return list("t1", "t2")
	case kindTeam:
		return list("payments", "legal")
	case kindAgent:
		return list("agent-1", "agent-2")
	case kindName:
		return list("refund", "export")
	case kindEnvironment:
		return list("prod", "staging")
	case kindTier:
		return list("gold", "silver")
	case kindScopes:
		return list("read", "admin")
	}
	return nil
}

func scale() []controlv1.Sensitivity {
	return []controlv1.Sensitivity{public, internal, confidential, restricted, secret}
}

func fourEffects() []controlv1.Verdict {
	return []controlv1.Verdict{allow, deny, approval, withObligations}
}

// A document, a rule, a constraint and an obligation as plain drawn values.
// build makes a fresh document from them each time, so two documents built
// from one spec share nothing.
type (
	docSpec  []ruleSpec
	ruleSpec struct {
		id          string
		effect      controlv1.Verdict
		reason      string
		obligations []obligationSpec
		constraints []constraintSpec
		// external is whether a DENY rule also reads the external answer.
		external bool
	}
	constraintSpec struct {
		kind    int
		values  []string
		effects []controlv1.EffectClass
		zones   []controlv1.TrustZone
		floor   controlv1.Sensitivity
	}
	obligationSpec struct {
		typ, key, val string
		advisory      bool
	}
)

func (d docSpec) build() *rules.Document {
	rs := make([]rules.Rule, len(d))
	for i, s := range d {
		rs[i] = s.build()
	}
	return document(rs...)
}

func (d docSpec) ids() []string {
	ids := make([]string, len(d))
	for i, s := range d {
		ids[i] = s.id
	}
	return ids
}

func (d docSpec) effects() map[string]controlv1.Verdict {
	effects := make(map[string]controlv1.Verdict, len(d))
	for _, s := range d {
		effects[s.id] = s.effect
	}
	return effects
}

func (s ruleSpec) build() rules.Rule {
	r := rules.Rule{ID: s.id, Effect: s.effect, Reason: s.reason}
	for _, o := range s.obligations {
		r.Obligations = append(r.Obligations, rules.Obligation{Type: o.typ, Params: o.proto().GetParams(), Advisory: o.advisory})
	}
	apply := appliers()
	for _, c := range s.constraints {
		apply[c.kind](c, &r.When)
	}
	if s.external {
		r.When.External = &rules.ExternalWhen{Denies: true}
	}
	return r
}

// code is what the rule contributes when it matches: its reason, or its
// effect's own when it names none.
func (s ruleSpec) code() string {
	if s.reason != "" {
		return s.reason
	}
	switch s.effect {
	case allow:
		return ruleAllow
	case deny:
		return ruleDeny
	case approval:
		return approvalRequired
	}
	return attached
}

func (o obligationSpec) proto() *controlv1.Obligation {
	ob := &controlv1.Obligation{Type: o.typ, Advisory: o.advisory}
	if o.key != "" {
		ob.Params = map[string]string{o.key: o.val}
	}
	return ob
}

// appliers write each kind of constraint into a When, indexed by kind, with
// slices of their own.
func appliers() [allKinds]func(constraintSpec, *rules.When) {
	principal := func(w *rules.When) *rules.PrincipalWhen {
		if w.Principal == nil {
			w.Principal = &rules.PrincipalWhen{}
		}
		return w.Principal
	}
	action := func(w *rules.When) *rules.ActionWhen {
		if w.Action == nil {
			w.Action = &rules.ActionWhen{}
		}
		return w.Action
	}
	resource := func(w *rules.When) *rules.ResourceWhen {
		if w.Resource == nil {
			w.Resource = &rules.ResourceWhen{}
		}
		return w.Resource
	}
	return [allKinds]func(constraintSpec, *rules.When){
		kindPrincipal: func(c constraintSpec, w *rules.When) { principal(w).ID = slices.Clone(c.values) },
		kindTenant:    func(c constraintSpec, w *rules.When) { principal(w).TenantID = slices.Clone(c.values) },
		kindTeam: func(c constraintSpec, w *rules.When) {
			principal(w).Attributes = map[string][]string{"team": slices.Clone(c.values)}
		},
		kindAgent:       func(c constraintSpec, w *rules.When) { w.Agent = &rules.AgentWhen{ID: slices.Clone(c.values)} },
		kindName:        func(c constraintSpec, w *rules.When) { action(w).Name = slices.Clone(c.values) },
		kindEffect:      func(c constraintSpec, w *rules.When) { action(w).Effect = slices.Clone(c.effects) },
		kindEnvironment: func(c constraintSpec, w *rules.When) { resource(w).Environment = slices.Clone(c.values) },
		kindTier: func(c constraintSpec, w *rules.When) {
			resource(w).Labels = map[string][]string{"tier": slices.Clone(c.values)}
		},
		kindZone: func(c constraintSpec, w *rules.When) {
			w.Destination = &rules.DestinationWhen{TrustZone: slices.Clone(c.zones)}
		},
		kindData: func(c constraintSpec, w *rules.When) { w.Data = &rules.DataWhen{SensitivityAtLeast: c.floor} },
		kindFlow: func(c constraintSpec, w *rules.When) { w.Flow = &rules.FlowWhen{ToxicAtLeast: c.floor} },
		kindScopes: func(c constraintSpec, w *rules.When) {
			w.Delegation = &rules.DelegationWhen{Scopes: slices.Clone(c.values)}
		},
		kindType: func(c constraintSpec, w *rules.When) { principal(w).Type = slices.Clone(c.values) },
	}
}

// authorable is the reasons a rule of each effect may name, and none.
func authorable(effect controlv1.Verdict) []string {
	switch effect {
	case allow:
		return list("", ruleAllow)
	case deny:
		return list("", ruleDeny, "ENVIRONMENT_BOUNDARY", "OUT_OF_SCOPE_ACTION", "TOXIC_FLOW_SENSITIVE_TO_EXTERNAL")
	case approval:
		return list("", approvalRequired)
	}
	return list("", attached)
}

// obligationPool holds pairs that differ only in a parameter's value, in its
// name or in the advisory flag, and draws with repetition, so the union meets
// duplicates.
func obligationPool() []obligationSpec {
	return []obligationSpec{
		{typ: "cap_amount", key: "max", val: "100"},
		{typ: "cap_amount", key: "max", val: "200"},
		{typ: "cap_amount", key: "limit", val: "100"},
		{typ: "cap_amount", key: "max", val: "100", advisory: true},
		{typ: "second_approver"},
		{typ: "emit_alert", advisory: true},
	}
}

func drawDocument(rt *rapid.T) docSpec {
	spec := make(docSpec, rapid.IntRange(0, 6).Draw(rt, "rules"))
	for i := range spec {
		spec[i] = drawRuleOf(rt, "r"+strconv.Itoa(i), rapid.SampledFrom(fourEffects()).Draw(rt, "effect"))
	}
	return spec
}

func drawRuleOf(rt *rapid.T, id string, effect controlv1.Verdict) ruleSpec {
	s := drawRuleHead(rt, id, effect)
	s.constraints = rapid.SliceOfNDistinct(rapid.Custom(drawConstraint), 1, 3,
		func(c constraintSpec) int { return c.kind }).Draw(rt, id+".when")
	s.external = effect == deny && rapid.Bool().Draw(rt, id+".external")
	return s
}

// drawRuleHead draws a rule's reason and obligations; its constraints are the
// caller's to give.
func drawRuleHead(rt *rapid.T, id string, effect controlv1.Verdict) ruleSpec {
	s := ruleSpec{id: id, effect: effect, reason: rapid.SampledFrom(authorable(effect)).Draw(rt, id+".reason")}
	switch effect {
	case withObligations:
		s.obligations = rapid.SliceOfN(rapid.SampledFrom(obligationPool()), 1, 3).Draw(rt, id+".obligations")
	case approval:
		s.obligations = rapid.SliceOfN(rapid.SampledFrom(obligationPool()), 0, 2).Draw(rt, id+".obligations")
	}
	return s
}

func drawConstraint(rt *rapid.T) constraintSpec {
	c := constraintSpec{kind: rapid.IntRange(0, constraintKinds-1).Draw(rt, "kind")}
	switch c.kind {
	case kindEffect:
		c.effects = rapid.SliceOfNDistinct(rapid.SampledFrom([]controlv1.EffectClass{read, write, transact}), 1, 2,
			rapid.ID[controlv1.EffectClass]).Draw(rt, "effects")
	case kindZone:
		c.zones = rapid.SliceOfNDistinct(rapid.SampledFrom([]controlv1.TrustZone{zoneInternal, zonePartner, zoneExternal}), 1, 2,
			rapid.ID[controlv1.TrustZone]).Draw(rt, "zones")
	case kindData, kindFlow:
		c.floor = rapid.SampledFrom(scale()).Draw(rt, "floor")
	default:
		c.values = rapid.SliceOfNDistinct(rapid.SampledFrom(vocabulary(c.kind)), 1, 2, rapid.ID[string]).Draw(rt, "values")
	}
	return c
}

// drawEnvelope draws from the same vocabularies and from absence, and draws
// enum numbers this build cannot name and labels that say nothing, which
// Validate refuses: purity and order hold for those too. It leaves
// principal.type to an anchor.
func drawEnvelope(rt *rapid.T) *controlv1.ActionEnvelope {
	maybe := func(kind int, label string) string {
		return rapid.SampledFrom(append(list(""), vocabulary(kind)...)).Draw(rt, label)
	}
	env := &controlv1.ActionEnvelope{
		Principal: &controlv1.Principal{Id: maybe(kindPrincipal, "principal.id"), TenantId: maybe(kindTenant, "principal.tenant_id")},
		Agent:     &controlv1.Agent{Id: maybe(kindAgent, "agent.id")},
		Action: &controlv1.Action{
			Name:   maybe(kindName, "action.name"),
			Effect: rapid.SampledFrom([]controlv1.EffectClass{effectUnset, read, write, transact, 42}).Draw(rt, "action.effect"),
		},
		Resource: &controlv1.Resource{Environment: maybe(kindEnvironment, "resource.environment")},
		Data: &controlv1.DataLabels{
			Sensitivities: rapid.SliceOfN(rapid.SampledFrom(append([]controlv1.Sensitivity{unlabelled, 6, -1}, scale()...)), 0, 2).
				Draw(rt, "data.sensitivities"),
			ContainsSecrets: rapid.Bool().Draw(rt, "data.contains_secrets"),
		},
	}
	if rapid.Bool().Draw(rt, "principal.attributes") {
		env.Principal.Attributes = map[string]string{"team": maybe(kindTeam, "principal.attributes.team")}
	}
	if rapid.Bool().Draw(rt, "resource.labels") {
		env.Resource.Labels = map[string]string{"tier": maybe(kindTier, "resource.labels.tier")}
	}
	if rapid.Bool().Draw(rt, "destination") {
		env.Destination = &controlv1.Destination{TrustZone: rapid.SampledFrom([]controlv1.TrustZone{
			zoneUnset, zoneInternal, zonePartner, zoneExternal, controlv1.TrustZone_TRUST_ZONE_USER_CONTROLLED, 42,
		}).Draw(rt, "destination.trust_zone")}
	}
	return env
}

func drawInputs(rt *rapid.T) match.Inputs {
	var in match.Inputs
	if rapid.Bool().Draw(rt, "flow.computed") {
		in.Flow = contract.NewFlowState(rapid.Bool().Draw(rt, "flow.untrusted_influence"),
			rapid.SampledFrom(append([]controlv1.Sensitivity{unlabelled}, scale()...)).Draw(rt, "flow.max_sensitivity_read"))
	}
	in.Delegated = rapid.Bool().Draw(rt, "delegated")
	in.Scopes = rapid.SliceOfNDistinct(rapid.SampledFrom(list("read", "write", "admin")), 0, 3, rapid.ID[string]).Draw(rt, "scopes")
	in.External = rapid.SampledFrom(answers()).Draw(rt, "external")
	return in
}

// answers is every answer the external constraint can be handed, and a number
// this build does not declare.
func answers() []match.External {
	return []match.External{match.ExternalUnknown, match.ExternalAllows, match.ExternalDenies, 9}
}

type call struct {
	env *controlv1.ActionEnvelope
	in  match.Inputs
}

func drawCall(rt *rapid.T) call {
	return call{env: drawEnvelope(rt), in: drawInputs(rt)}
}
