package main

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/scenario"
)

// compareCall is the one call every comparison case starts from: a blocked
// call whose decision carries one obligation.
const compareCall = `{"call":{"tool":"read_order","args":{"id":"ord-1"},
  "answer":{"kind":"blocked","codes":["RULE_DENY"]},
  "decided":{"verdict":"DENY","codes":["RULE_DENY"],"obligations":[{"type":"emit_alert","params":{"to":"ops","n":"1"},"advisory":true}]},
  "trail":{"request":"new","kinds":["ACTION_PROPOSED","POLICY_DECIDED","ACTION_BLOCKED"]}}}`

func compareScenario(t *testing.T, step string) *scenario.Call {
	t.Helper()
	s, err := scenario.Read("compare.json", []byte(`{"kind":"agent-scenario/v1alpha1","about":"a",
	  "plane":{"mode":"APPROVE","bundle":{"id":"b"}},"steps":[`+step+`]}`))
	if err != nil {
		t.Fatalf("reading the case: %v", err)
	}
	return s.Steps[0].Call
}

// compareSeen is what a plane that meets compareCall shows, built field by
// field and never from the scenario.
func compareSeen() (callSeen, planeFacts) {
	mode := controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE
	decision := &controlv1.Decision{SchemaVersion: "1.0", DecisionId: "d1", Verdict: controlv1.Verdict_VERDICT_DENY,
		ReasonCodes: []string{"RULE_DENY"}, PolicyBundleDigest: "sha256:bb",
		Obligations: []*controlv1.Obligation{{Type: "emit_alert", Params: map[string]string{"n": "1", "to": "ops"}, Advisory: true}}}
	trail := []*controlv1.Event{
		{Kind: controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, EnforcementMode: mode, Payload: &controlv1.Event_Proposed{
			Proposed: &controlv1.ActionEnvelope{
				Arguments: &controlv1.Arguments{CanonicalHash: "sha256:aa"},
				Context:   &controlv1.RunContext{Tags: []string{"mcp.client=x", "flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC"}},
			}}},
		{Kind: controlv1.EventKind_EVENT_KIND_POLICY_DECIDED, EnforcementMode: mode, Payload: &controlv1.Event_Decision{Decision: decision}},
		{Kind: controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED, EnforcementMode: mode, Payload: &controlv1.Event_Decision{
			Decision: proto.CloneOf(decision)}},
	}
	seen := callSeen{answer: answered{kind: scenario.AnswerBlocked, codes: []string{"RULE_DENY"}, requestID: "r1", decisionID: "d1"},
		trail: trail, request: "new"}
	return seen, planeFacts{mode: "APPROVE", digest: "sha256:bb", fresh: true, sentHash: "sha256:aa"}
}

// decisionOf is the decision the trail's POLICY_DECIDED carries.
func decisionOf(seen callSeen) *controlv1.Decision { return seen.trail[1].GetDecision() }

// TestEachMemberIsComparedOnItsOwn: every case changes one thing, on the
// plane's side or the scenario's, and exactly the member it changed is named,
// with both values.
func TestEachMemberIsComparedOnItsOwn(t *testing.T) {
	for _, c := range []struct {
		name   string
		step   string
		change func(*callSeen, *planeFacts)
		want   string
	}{
		{"answer.kind", compareCall, func(s *callSeen, _ *planeFacts) { s.answer.kind = scenario.AnswerResult },
			"step[3].answer.kind: want blocked, got result"},
		{"answer.codes", compareCall, func(s *callSeen, _ *planeFacts) { s.answer.codes = []string{"RULE_DENY", "PAUSED"} },
			"step[3].answer.codes: want [RULE_DENY], got [RULE_DENY, PAUSED]"},
		{"answer.codes one code holding two", strings.Replace(compareCall, `"blocked","codes":["RULE_DENY"]`, `"blocked","codes":["RULE_DENY","PAUSED"]`, 1),
			func(s *callSeen, _ *planeFacts) { s.answer.codes = []string{"RULE_DENY, PAUSED"} },
			`step[3].answer.codes: want ["RULE_DENY", "PAUSED"], got ["RULE_DENY, PAUSED"]`},
		{"decided", strings.Replace(compareCall, `{"verdict":"DENY","codes":["RULE_DENY"],"obligations":[{"type":"emit_alert","params":{"to":"ops","n":"1"},"advisory":true}]}`, `"none"`, 1),
			func(*callSeen, *planeFacts) {}, "step[3].decided: want none, got a decision of DENY"},
		{"decided.verdict", compareCall, func(s *callSeen, _ *planeFacts) { decisionOf(*s).Verdict = controlv1.Verdict_VERDICT_ALLOW },
			"step[3].decided.verdict: want DENY, got ALLOW"},
		{"decided.codes", compareCall, func(s *callSeen, _ *planeFacts) { decisionOf(*s).ReasonCodes = nil },
			"step[3].decided.codes: want [RULE_DENY], got []"},
		{"decided.codes one code holding two", strings.Replace(compareCall, `"verdict":"DENY","codes":["RULE_DENY"]`, `"verdict":"DENY","codes":["RULE_DENY","PAUSED"]`, 1),
			func(s *callSeen, _ *planeFacts) { decisionOf(*s).ReasonCodes = []string{"RULE_DENY, PAUSED"} },
			`step[3].decided.codes: want ["RULE_DENY", "PAUSED"], got ["RULE_DENY, PAUSED"]`},
		{"decided.obligations params", compareCall, func(s *callSeen, _ *planeFacts) { decisionOf(*s).Obligations[0].Params["to"] = "sec" },
			`step[3].decided.obligations: want [{"advisory":true,"params":{"n":"1","to":"ops"},"type":"emit_alert"}], got [{"advisory":true,"params":{"n":"1","to":"sec"},"type":"emit_alert"}]`},
		{"decided.obligations advisory", compareCall, func(s *callSeen, _ *planeFacts) { decisionOf(*s).Obligations[0].Advisory = false },
			`step[3].decided.obligations: want [{"advisory":true,"params":{"n":"1","to":"ops"},"type":"emit_alert"}], got [{"advisory":false,"params":{"n":"1","to":"ops"},"type":"emit_alert"}]`},
		{"decided.obligations a number", strings.Replace(compareCall, `"n":"1"`, `"n":1`, 1), func(*callSeen, *planeFacts) {},
			`step[3].decided.obligations: want [{"advisory":true,"params":{"n":1,"to":"ops"},"type":"emit_alert"}], got [{"advisory":true,"params":{"n":"1","to":"ops"},"type":"emit_alert"}]`},
		{"trail.request", compareCall, func(s *callSeen, _ *planeFacts) { s.request = "step[0]" },
			"step[3].trail.request: want new, got step[0]"},
		{"trail.kinds", compareCall, func(s *callSeen, _ *planeFacts) { s.trail = s.trail[:2] },
			"step[3].trail.kinds: want [ACTION_PROPOSED, POLICY_DECIDED, ACTION_BLOCKED], got [ACTION_PROPOSED, POLICY_DECIDED]"},
		{"plane.mode", compareCall, func(s *callSeen, _ *planeFacts) {
			s.trail[2].EnforcementMode = controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE
		}, "step[3].plane.mode: want APPROVE, got ENFORCE"},
		{"plane.bundle.digest", compareCall, func(_ *callSeen, p *planeFacts) { p.digest = "sha256:cc" },
			"step[3].plane.bundle.digest: want sha256:cc, got sha256:bb"},
		{"answer.decision_id", compareCall, func(s *callSeen, _ *planeFacts) { s.answer.decisionID = "d9" },
			"step[3].answer.decision_id: want one of [d1], got d9"},
		{"args", compareCall, func(_ *callSeen, p *planeFacts) { p.sentHash = "sha256:ab" },
			"step[3].args: want sha256:ab, got sha256:aa"},
		{"args canon cannot hash", compareCall, func(_ *callSeen, p *planeFacts) { p.sentHash = "" },
			"step[3].args: want none, got sha256:aa"},
		{"args the plane recorded none of", compareCall, func(s *callSeen, _ *planeFacts) { s.trail[0].GetProposed().Arguments = nil },
			"step[3].args: want sha256:aa, got none"},
		{"run", compareCall, func(s *callSeen, _ *planeFacts) {
			s.trail[0].GetProposed().Context.Tags[1] = "flow.v1.untrusted=true"
		}, "step[3].run: want fresh (flow.v1.untrusted=false, flow.v1.max_read=PUBLIC), got flow.v1.untrusted=true, flow.v1.max_read=PUBLIC"},
	} {
		t.Run(c.name, func(t *testing.T) {
			seen, facts := compareSeen()
			c.change(&seen, &facts)
			diffs, err := judgeCall(3, compareScenario(t, c.step), seen, facts)
			if err != nil {
				t.Fatalf("judgeCall: %v", err)
			}
			if got := rendered(diffs); !slices.Equal(got, []string{c.want}) {
				t.Errorf("differences %q, want exactly %q", got, c.want)
			}
		})
	}
}

// TestAPlaneThatMeetsTheCallShowsNoDifference: the starting point of every
// case above compares clean, the parameters canonicalized on both sides.
func TestAPlaneThatMeetsTheCallShowsNoDifference(t *testing.T) {
	seen, facts := compareSeen()
	diffs, err := judgeCall(3, compareScenario(t, compareCall), seen, facts)
	if err != nil || len(diffs) != 0 {
		t.Fatalf("judgeCall = %q, %v; want no difference", rendered(diffs), err)
	}
	// A retry's trail was proven fresh or not at its first call, and its
	// proposal is the held call's, which the retry's arguments must match.
	seen.request, facts.fresh = "step[0]", false
	withStep := strings.Replace(compareCall, `"request":"new"`, `"request":"step[0]"`, 1)
	s, err := scenario.Read("compare.json", []byte(`{"kind":"agent-scenario/v1alpha1","about":"a",
	  "plane":{"mode":"APPROVE","bundle":{"id":"b"}},"steps":[`+
		`{"call":{"tool":"t","args":{},"answer":{"kind":"pending","codes":["APPROVAL_PENDING"]},"decided":"none","trail":{"request":"new","kinds":[]}}},`+
		withStep+`]}`))
	if err != nil {
		t.Fatalf("reading the retry: %v", err)
	}
	if diffs, err := judgeCall(3, s.Steps[1].Call, seen, facts); err != nil || len(diffs) != 0 {
		t.Fatalf("a retry: %q, %v; want no difference", rendered(diffs), err)
	}
	facts.sentHash = "sha256:other"
	diffs, err = judgeCall(3, s.Steps[1].Call, seen, facts)
	if want := []string{"step[3].args: want sha256:other, got sha256:aa"}; err != nil || !slices.Equal(rendered(diffs), want) {
		t.Fatalf("a retry with other arguments: %q, %v; want %q", rendered(diffs), err, want)
	}
}

// TestATrailThatCannotBeComparedIsNotADifference: a trail with two decisions,
// and a first call whose trail holds no proposal to show a fresh run by, are
// errors, never a pass and never a difference.
func TestATrailThatCannotBeComparedIsNotADifference(t *testing.T) {
	seen, facts := compareSeen()
	seen.trail = append(seen.trail, seen.trail[1])
	if _, err := judgeCall(3, compareScenario(t, compareCall), seen, facts); err == nil || !strings.Contains(err.Error(), "2 POLICY_DECIDED") {
		t.Errorf("two decisions: err = %v", err)
	}
	seen, facts = compareSeen()
	seen.trail = seen.trail[1:]
	if _, err := judgeCall(3, compareScenario(t, compareCall), seen, facts); err == nil || !strings.Contains(err.Error(), "no ACTION_PROPOSED") {
		t.Errorf("no proposal on a fresh run: err = %v", err)
	}
	facts.fresh = false
	if _, err := judgeCall(3, compareScenario(t, compareCall), seen, facts); err != nil {
		t.Errorf("no proposal on a continued run: err = %v", err)
	}
}

// TestNoBundleDigestIsNeverEqual: a plane that reported no bundle digest
// cannot have its trail held to one, even a trail that records none either.
func TestNoBundleDigestIsNeverEqual(t *testing.T) {
	seen, facts := compareSeen()
	facts.digest = ""
	for _, ev := range seen.trail {
		if d := ev.GetDecision(); d != nil {
			d.PolicyBundleDigest = ""
		}
	}
	diffs, err := judgeCall(3, compareScenario(t, compareCall), seen, facts)
	if err == nil || !strings.Contains(err.Error(), "no policy bundle digest") {
		t.Fatalf("judgeCall = %q, %v; want an error naming the missing digest", rendered(diffs), err)
	}
	seen, facts = compareSeen()
	decisionOf(seen).PolicyBundleDigest = ""
	diffs, err = judgeCall(3, compareScenario(t, compareCall), seen, facts)
	if want := []string{"step[3].plane.bundle.digest: want sha256:bb, got "}; err != nil || !slices.Equal(rendered(diffs), want) {
		t.Fatalf("a decision with no digest: %q, %v; want %q", rendered(diffs), err, want)
	}
}

// TestADecisionOfAnotherMajorIsNotRead: the decision a step is judged by is
// read only on the major this build reads, whatever the event around it
// says; a later minor is read.
func TestADecisionOfAnotherMajorIsNotRead(t *testing.T) {
	for _, version := range []string{"2.0", "0.9", "", "1", "1.x", "+1.0"} {
		seen, facts := compareSeen()
		decisionOf(seen).SchemaVersion = version
		diffs, err := judgeCall(3, compareScenario(t, compareCall), seen, facts)
		if err == nil || !strings.Contains(err.Error(), "schema_version") {
			t.Errorf("a decision of version %q: %q, %v; want it refused", version, rendered(diffs), err)
		}
	}
	seen, facts := compareSeen()
	decisionOf(seen).SchemaVersion = strings.Repeat("9", 4096) + ".0\x1b[2J"
	_, err := judgeCall(3, compareScenario(t, compareCall), seen, facts)
	if err == nil || strings.Contains(err.Error(), strings.Repeat("9", 33)) || strings.ContainsRune(err.Error(), 0x1b) {
		t.Fatalf("a long version written with an escape: %v; want it refused, quoting at most 32 bytes and no escape", err)
	}
	seen, facts = compareSeen()
	decisionOf(seen).SchemaVersion = "1.7"
	if diffs, err := judgeCall(3, compareScenario(t, compareCall), seen, facts); err != nil || len(diffs) != 0 {
		t.Fatalf("a decision of a later minor: %q, %v; want no difference", rendered(diffs), err)
	}
}

// TestRequestOfNamesTheRequestAnAnswerNames holds each way a request id is
// named to a literal.
func TestRequestOfNamesTheRequestAnAnswerNames(t *testing.T) {
	earlier := []string{"r0", "", "r0", "r3"}
	before := map[string]bool{"old": true}
	for _, c := range []struct {
		id   string
		want int
		got  string
	}{
		{"r9", scenario.NewRequest, "new"},
		{"r0", scenario.NewRequest, "step[0]"},
		{"r0", 2, "step[2]"},
		{"r0", 3, "step[0]"},
		{"r3", 0, "step[3]"},
		{"old", scenario.NewRequest, "a request the trail file held before this scenario"},
		{"r9", 0, "new"},
	} {
		if got := requestOf(c.id, c.want, earlier, before); got != c.got {
			t.Errorf("requestOf(%q, %d) = %q, want %q", c.id, c.want, got, c.got)
		}
	}
}

func rendered(diffs []difference) []string {
	out := make([]string, len(diffs))
	for i, d := range diffs {
		out[i] = d.String()
	}
	return out
}
