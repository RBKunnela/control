package supervise

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestASeqCountsAndWalksPastTheDenialsKey: in a range a seq counts and
// visits the calls of another key than the denial's, or every call but the
// denial when it has none, and a walk stops at the number asked.
func TestASeqCountsAndWalksPastTheDenialsKey(t *testing.T) {
	keys := []string{"h1", "h1", "h2", "", "h1", "h2", "h1"}
	calls := make([]*request, len(keys))
	for i := range keys {
		calls[i] = &request{id: fmt.Sprint("c", i)}
	}
	key := map[*request]string{}
	for i, rq := range calls {
		key[rq] = keys[i]
	}
	s := newSeq(calls, make([]ord, len(calls)), func(rq *request) string { return key[rq] })
	d := calls[1]
	for _, c := range []struct {
		k            string
		lo, hi, self int
		most         int
		count        uint64
		visited      string
	}{
		{"h1", 0, 7, -1, 10, 3, "c2 c3 c5"},
		{"h1", 3, 7, -1, 10, 2, "c3 c5"},
		{"h1", 0, 7, -1, 2, 3, "c2 c3"},
		{"", 0, 7, 1, 10, 6, "c0 c2 c3 c4 c5 c6"},
		{"", 2, 7, 1, 10, 5, "c2 c3 c4 c5 c6"},
	} {
		var got []string
		s.each(c.lo, c.hi, c.k, d, c.most, func(r *request) { got = append(got, r.id) })
		if n := s.count(c.lo, c.hi, c.k, c.self); n != c.count || strings.Join(got, " ") != c.visited {
			t.Errorf("key %q in [%d, %d): counts %d visiting %q, want %d visiting %q", c.k, c.lo, c.hi, n, got, c.count, c.visited)
		}
	}
}

// fuzzRuns is a root, its child, the child's child and the root's other
// child.
var fuzzRuns = []Run{
	{ID: "run-00000000000000000000000000000000", Tenant: "t"},
	{ID: "run-11111111111111111111111111111111", Tenant: "t", Parent: "run-00000000000000000000000000000000"},
	{ID: "run-22222222222222222222222222222222", Tenant: "t", Parent: "run-11111111111111111111111111111111"},
	{ID: "run-33333333333333333333333333333333", Tenant: "t", Parent: "run-00000000000000000000000000000000"},
}

// lcg is a fixed sequence of choices, so every run of the test reads the
// same inputs.
type lcg int

func (g *lcg) pick(n int) int {
	*g = (*g*1103515245 + 12345) & 0x7fffffff
	return int(*g>>8) % n
}

// fuzzTrail is one request's trail: its run, tool, resource, hash and effect
// drawn from small sets so that keys, near keys, ties, times a nanosecond
// apart and missing times repeat.
func fuzzTrail(g *lcg, i int) []*controlv1.Event {
	req := fmt.Sprintf("q%03d", i)
	run := fuzzRuns[g.pick(len(fuzzRuns))].ID
	hash := []string{"", "sha256:1", "sha256:2", "sha256:3"}[g.pick(4)]
	effect := []controlv1.EffectClass{controlv1.EffectClass_EFFECT_CLASS_READ, controlv1.EffectClass_EFFECT_CLASS_WRITE,
		controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED, controlv1.EffectClass(99)}[g.pick(4)]
	env := &controlv1.ActionEnvelope{SchemaVersion: "1.0", RequestId: req, TenantId: "t", ProjectId: "p",
		Action:    &controlv1.Action{Kind: "tool", Name: []string{"issue_refund", "refund_manual"}[g.pick(2)], Provider: "pay", Effect: effect},
		Resource:  fuzzResource(g),
		Arguments: &controlv1.Arguments{CanonicalHash: hash}}
	kernel := &controlv1.Decision{SchemaVersion: "1.0", DecisionId: req + "-k", RequestId: req, Verdict: controlv1.Verdict_VERDICT_ALLOW}
	k := controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED
	kinds := []controlv1.EventKind{k, controlv1.EventKind_EVENT_KIND_POLICY_DECIDED}
	approval := controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED
	switch g.pick(5) {
	case 0, 1:
		kernel.Verdict, kernel.ReasonCodes = controlv1.Verdict_VERDICT_DENY, []string{"RULE_DENY"}
		kinds = append(kinds, controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED)
	case 2:
		kernel.Verdict = controlv1.Verdict_VERDICT_REQUIRE_APPROVAL
		kinds = append(kinds, controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED)
	case 3:
		kernel.Verdict = controlv1.Verdict_VERDICT_REQUIRE_APPROVAL
		approval = []controlv1.ApprovalState{controlv1.ApprovalState_APPROVAL_STATE_APPROVED, controlv1.ApprovalState_APPROVAL_STATE_REJECTED}[g.pick(2)]
		kinds = append(kinds, controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED, controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED)
	default:
		kinds = append(kinds, controlv1.EventKind_EVENT_KIND_ACTION_STARTED, controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED)
	}
	start := g.pick(12)
	var out []*controlv1.Event
	for j, kind := range kinds {
		ev := &controlv1.Event{EventId: fmt.Sprintf("%s-e%d", req, j+1), Kind: kind, RequestId: req, RunId: run, TenantId: "t",
			ProjectId: "p", SchemaVersion: "1.0", EnforcementMode: controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
			OccurredAt: timestamppb.New(time.Unix(int64(start+j), fuzzNanos[g.pick(len(fuzzNanos))]))}
		if j > 0 {
			ev.PrevEventId = out[j-1].GetEventId()
		}
		switch kind {
		case k:
			ev.Payload = &controlv1.Event_Proposed{Proposed: env}
		case controlv1.EventKind_EVENT_KIND_POLICY_DECIDED, controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED:
			ev.Payload = &controlv1.Event_Decision{Decision: kernel}
		case controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED:
			ev.Payload = &controlv1.Event_Approval{Approval: &controlv1.Approval{SchemaVersion: "1.0", ApprovalId: req + "-a",
				RequestId: req, State: approval, ApproverId: "ops"}}
		}
		if g.pick(8) == 0 {
			ev.OccurredAt = nil
		}
		out = append(out, ev)
	}
	if g.pick(10) == 0 {
		out[len(out)-1].PrevEventId = "elsewhere"
	}
	return out
}

// fuzzNanos puts an event on its second, a nanosecond after it, or a
// nanosecond before the next, so a decision and a call fall a nanosecond
// apart within one second and across two.
var fuzzNanos = []int64{0, 0, 1, 999999999}

// fuzzResource is order 42 or 43 of the tenant's production environment,
// now and then of another type, tenant or environment, so that keys differ
// in one field only.
func fuzzResource(g *lcg) *controlv1.Resource {
	r := &controlv1.Resource{Type: "shop_order", Id: []string{"42", "43"}[g.pick(2)], TenantId: "t", Environment: "prod"}
	if g.pick(6) == 0 {
		r.Type = "shop_refund"
	}
	if g.pick(6) == 0 {
		r.TenantId = "u"
	}
	if g.pick(6) == 0 {
		r.Environment = "staging"
	}
	return r
}

// fuzzInput is n trails spread over one to three exports, each export's
// requests in an order of their own, some held by a second export too, and
// now and then one event under its id with other content.
func fuzzInput(t *testing.T, g *lcg, n int) Input {
	raw, err := os.ReadFile("testdata/procedure-0.2.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := ReadProcedure(raw)
	if err != nil {
		t.Fatal(err)
	}
	exports := make([]Export, 1+g.pick(3))
	for i := range n {
		trail := fuzzTrail(g, i)
		x := g.pick(len(exports))
		exports[x].Events = append(exports[x].Events, trail...)
		if y := g.pick(len(exports)); y != x && g.pick(3) == 0 {
			for _, ev := range trail {
				ev = proto.CloneOf(ev)
				if g.pick(20) == 0 {
					ev.OccurredAt = timestamppb.New(time.Unix(99, 0))
				}
				exports[y].Events = append(exports[y].Events, ev)
			}
		}
	}
	for i := range exports {
		evs := exports[i].Events
		for j := len(evs) - 1; j > 0; j-- {
			k := g.pick(j + 1)
			evs[j], evs[k] = evs[k], evs[j]
		}
	}
	return Input{Procedure: p, Run: fuzzRuns[0], Tree: fuzzRuns, Exports: exports}
}

// pairVerdict is what a call says as a retry of a denial, from every pair
// apart from the index: the form, the approvals store, the plane's times,
// which confirm only when one export holds both copies, and the scope.
func pairVerdict(in Input, form string, d, r *request) (controlv1.FindingVerdict, bool) {
	v, ok := pairForm(form, d, r)
	switch {
	case !ok || r.approval == controlv1.ApprovalState_APPROVAL_STATE_APPROVED && !r.doubt:
		return 0, false
	case r.waiting || r.doubt:
		v = indeterminate
	}
	td, tr := d.decided.GetOccurredAt(), r.proposal.GetOccurredAt()
	switch {
	case !td.IsValid() || !tr.IsValid() || tr.AsTime().Equal(td.AsTime()):
		v = indeterminate
	case tr.AsTime().Before(td.AsTime()):
		return 0, false
	case !heldTogether(in, d.decided, r.proposal):
		v = weaker(v, suspected)
	}
	if !descends(r.proposal.GetRunId(), d.proposal.GetRunId()) {
		v = weaker(v, suspected)
	}
	return v, true
}

// pairForm is what the form alone lets r say of d.
func pairForm(form string, d, r *request) (controlv1.FindingVerdict, bool) {
	if form == "args" {
		switch hd, hr := hashOf(d), hashOf(r); {
		case hd != "" && hd == hr:
			return 0, false
		case hd == "" || hr == "":
			return indeterminate, true
		}
		return confirmed, true
	}
	dc, rc := d.proposal.GetProposed().GetAction().GetEffect(), r.proposal.GetProposed().GetAction().GetEffect()
	known := func(c controlv1.EffectClass) bool {
		return c == controlv1.EffectClass_EFFECT_CLASS_READ || c == controlv1.EffectClass_EFFECT_CLASS_WRITE
	}
	switch {
	case toolOf(d) == toolOf(r):
		return 0, false
	case dc == controlv1.EffectClass_EFFECT_CLASS_READ || rc == controlv1.EffectClass_EFFECT_CLASS_WRITE:
		return confirmed, true
	case known(dc) && known(rc):
		return 0, false
	}
	return indeterminate, true
}

func heldTogether(in Input, a, b *controlv1.Event) bool {
	for _, x := range in.Exports {
		var hasA, hasB bool
		for _, ev := range x.Events {
			hasA = hasA || ev.GetEventId() == a.GetEventId() && proto.Equal(ev, a)
			hasB = hasB || ev.GetEventId() == b.GetEventId() && proto.Equal(ev, b)
		}
		if hasA && hasB {
			return true
		}
	}
	return false
}

func descends(run, of string) bool {
	parent := map[string]string{}
	for _, r := range fuzzRuns {
		parent[r.ID] = r.Parent
	}
	for ; run != ""; run = parent[run] {
		if run == of {
			return true
		}
	}
	return false
}

// TestIndexedRetriesAgreeWithEveryPair: on generated trees, exports and
// trails, each finding of the two plane forms has the verdict and the
// retries that weighing every pair of a denial and a call gives, cites the
// same calls when they all fit, and no finding is missing or extra.
func TestIndexedRetriesAgreeWithEveryPair(t *testing.T) {
	g := lcg(1)
	seen := map[controlv1.FindingVerdict]int{}
	for round := range 400 {
		in := fuzzInput(t, &g, 6+g.pick(30))
		rd := newRead(judged(in), "t", "")
		if err := rd.takeEvents(in.Exports); err != nil {
			t.Fatal(err)
		}
		e := newEvaluation(in, rd)
		for form, got := range map[string][]draft{"args": e.retriedArguments(), "resource": e.retriedResource()} {
			want := everyPair(in, e, form)
			if len(got) != len(want) {
				t.Fatalf("round %d %s: %d findings, want %d", round, form, len(got), len(want))
			}
			for i, dr := range got {
				if msg := differs(dr, want[i]); msg != "" {
					t.Fatalf("round %d %s finding %d: %s", round, form, i, msg)
				}
				seen[want[i].v]++
			}
		}
	}
	t.Logf("verdicts reached: %v", seen)
	if seen[confirmed] < 50 || seen[suspected] < 50 || seen[indeterminate] < 50 {
		t.Fatalf("the inputs reached too few verdicts: %v", seen)
	}
}

// differs says how a finding differs from the one every pair gives, or "".
func differs(dr draft, w pairFinding) string {
	cited, n := citedIDs(dr.refs[1:]), uint64(len(dr.refs[1:]))+dr.leftOut
	if dr.anchor[0] != w.denial || dr.run != w.run || dr.cap != w.v || n != uint64(len(w.retries)) ||
		len(w.retries) <= MaxFindingRefs && cited != strings.Join(w.retries, " ") {
		return fmt.Sprintf("%s by %s %v on %d citing %q; want %s by %s %v on %q", dr.anchor[0], dr.run, dr.cap, n, cited,
			w.denial, w.run, w.v, w.retries)
	}
	return ""
}

type pairFinding struct {
	denial, run string
	v           controlv1.FindingVerdict
	retries     []string
}

// everyPair is each denial's finding per run, in the order the rule makes
// them, from every call of the denial's group weighed on its own.
func everyPair(in Input, e *evaluation, form string) []pairFinding {
	pos := map[*controlv1.Event]int{}
	for i, ev := range e.rd.events {
		pos[ev] = i
	}
	var denials []*request
	for _, rq := range e.reqs {
		if _, ok := rq.tool(); ok && rq.denied() && (form == "args" || resourceOf(rq).id != "") {
			denials = append(denials, rq)
		}
	}
	slices.SortStableFunc(denials, func(a, b *request) int { return cmp.Compare(a.id, b.id) })
	var out []pairFinding
	for _, d := range denials {
		byRun := map[string]*pairFinding{}
		for _, r := range e.reqs {
			if v, ok := sameGroup(in, form, d, r); ok {
				byRun = strongerOf(byRun, d, r, v)
			}
		}
		for _, run := range slices.Sorted(maps.Keys(byRun)) {
			f := byRun[run]
			slices.SortFunc(f.retries, func(a, b string) int {
				return cmp.Compare(pos[e.byRequest[reqOf(a)].proposal], pos[e.byRequest[reqOf(b)].proposal])
			})
			out = append(out, *f)
		}
	}
	return out
}

// sameGroup weighs r as a retry of d when it is another tool call of d's
// group.
func sameGroup(in Input, form string, d, r *request) (controlv1.FindingVerdict, bool) {
	same := toolOf(r) == toolOf(d)
	if form == "resource" {
		same = resourceOf(r) == resourceOf(d)
	}
	if _, isTool := r.tool(); r == d || !isTool || !same {
		return 0, false
	}
	return pairVerdict(in, form, d, r)
}

// strongerOf keeps, per run, the retries of the strongest verdict.
func strongerOf(byRun map[string]*pairFinding, d, r *request, v controlv1.FindingVerdict) map[string]*pairFinding {
	run := r.proposal.GetRunId()
	switch f := byRun[run]; {
	case f == nil || rank(v) > rank(f.v):
		byRun[run] = &pairFinding{denial: d.id, run: run, v: v, retries: []string{r.proposal.GetEventId()}}
	case rank(v) == rank(f.v):
		f.retries = append(f.retries, r.proposal.GetEventId())
	}
	return byRun
}

func reqOf(eventID string) string { return eventID[:strings.LastIndex(eventID, "-")] }

func citedIDs(refs []ref) string {
	var out []string
	for _, r := range refs {
		out = append(out, r.r.GetEvent().GetEventId())
	}
	return strings.Join(out, " ")
}
