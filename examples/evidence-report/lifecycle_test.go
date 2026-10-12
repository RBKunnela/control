package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// stagePrefixes reaches each stage with a request typed here, in the order
// of the reader's stages.
var stagePrefixes = []struct {
	state string
	steps []step
}{
	{"the start of a trail", nil},
	{"ACTION_PROPOSED", allowed[:1]},
	{"POLICY_DECIDED", allowed[:2]},
	{"APPROVAL_REQUESTED", approved[:3]},
	{"a decided approval", approved[:4]},
	{"an approval window nobody answered", expired[:4]},
	{"ACTION_STARTED", allowed[:3]},
	{"a closed action", allowed},
}

// appended is, by kind, an event the report takes whenever the lifecycle
// lets that kind follow, so a refusal can only be the step's own.
var appended = map[string]string{
	"ACTION_PROPOSED":    proposed("read_order"),
	"POLICY_DECIDED":     decided("ALLOW", "RULE_ALLOW"),
	"APPROVAL_REQUESTED": approval("PENDING"),
	"APPROVAL_DECIDED":   approval("APPROVED"),
	"ACTION_STARTED":     execution("x1"),
	"ACTION_COMPLETED":   ended("x1", "SUCCESS"),
	"ACTION_FAILED":      ended("x1", "FAILURE"),
	"ACTION_BLOCKED":     decided("DENY", "RULE_DENY"),
	"APPROVAL_EXPIRED":   approval("EXPIRED"),
	"FINDING_RAISED":     "",
	"POLICY_RELOADED":    "",
}

// chainEdge is one step of testdata/plane.json's chain: a state and a kind.
type chainEdge struct{ from, kind string }

// planeChain reads testdata/plane.json's chain: the steps taken, each with
// the state it moves to, and the kind number no build declares. It fails on
// a state or kind the file names that this reader does not know, so every
// step listed is one the checks below consult.
func planeChain(t *testing.T) (map[chainEdge]string, int32) {
	t.Helper()
	chain := readPlane(t).Chain
	var states []string
	for _, p := range stagePrefixes {
		states = append(states, p.state)
	}
	if !slices.Equal(chain.States, states) {
		t.Fatalf("testdata/plane.json names states\n%q\nthis reader's stages are\n%q", chain.States, states)
	}
	taken := map[chainEdge]string{}
	for _, e := range chain.Edges {
		_, declared := controlv1.EventKind_value[e.Kind]
		switch {
		case !declared || e.Kind == controlv1.EventKind_EVENT_KIND_UNSPECIFIED.String():
			t.Fatalf("testdata/plane.json names kind %q, which the contract does not declare", e.Kind)
		case !slices.Contains(states, e.From) || !slices.Contains(states, e.To):
			t.Fatalf("testdata/plane.json steps from %q to %q, a state this reader does not name", e.From, e.To)
		case taken[chainEdge{e.From, e.Kind}] != "":
			t.Fatalf("testdata/plane.json lists %s after %s twice", e.Kind, e.From)
		}
		taken[chainEdge{e.From, e.Kind}] = e.To
	}
	return taken, chain.UnplaceableKind
}

// TestLifecycleGrammarIsThePlanes holds the reader's steps to the plane's
// chain, edge for edge: every stage and every kind the contract declares,
// whether the step is taken and the stage it moves to, and the kind number no
// build declares, which the reader must not place.
func TestLifecycleGrammarIsThePlanes(t *testing.T) {
	taken, unplaceable := planeChain(t)
	stageOf := map[string]stage{}
	for i, p := range stagePrefixes {
		stageOf[p.state] = stage(i)
	}
	kinds := controlv1.EventKind(0).Descriptor().Values()
	for _, p := range stagePrefixes {
		for k := 1; k < kinds.Len(); k++ {
			kind := controlv1.EventKind(kinds.Get(k).Number())
			to, allowed := taken[chainEdge{p.state, kind.String()}]
			agrees(t, p.state, kind, allowed, to, stageOf)
		}
	}
	if kinds.ByNumber(protoreflect.EnumNumber(unplaceable)) != nil {
		t.Errorf("testdata/plane.json names kind %d as one no build declares; the contract declares it", unplaceable)
	}
	if _, placed := steps[controlv1.EventKind(unplaceable)]; placed {
		t.Errorf("the reader places kind %d, which no build declares", unplaceable)
	}
}

// agrees holds the reader's step for kind after the stage from to the
// plane's: whether it is taken, and the stage it moves to.
func agrees(t *testing.T, from string, kind controlv1.EventKind, allowed bool, to string, stageOf map[string]stage) {
	t.Helper()
	mine, placed := steps[kind]
	if !placed {
		t.Errorf("%s: the reader cannot place a kind the contract declares", kind)
		return
	}
	if taken := follows(stageOf[from], mine.from); taken != allowed {
		t.Errorf("%s after %s: the reader says %t, the plane %t", kindName(kind), from, taken, allowed)
	}
	next := mine.to
	if next == unchanged {
		next = stageOf[from]
	}
	if allowed && next != stageOf[to] {
		t.Errorf("%s after %s: the reader moves to stage %d, the plane to %s", kindName(kind), from, next, to)
	}
}

// TestLifecycleGrammar runs every stage and every kind through the report:
// each step the table allows is taken, and each other one is refused as the
// step it is.
func TestLifecycleGrammar(t *testing.T) {
	taken, undeclared := planeChain(t)
	kinds := controlv1.EventKind(0).Descriptor().Values()
	for _, p := range stagePrefixes {
		prev := "the start of the request"
		if len(p.steps) > 0 {
			prev = p.steps[len(p.steps)-1].kind
		}
		for k := 1; k < kinds.Len(); k++ {
			kind := strings.TrimPrefix(string(kinds.ByNumber(controlv1.EventKind(k).Number()).Name()), "EVENT_KIND_")
			_, allowed := taken[chainEdge{p.state, "EVENT_KIND_" + kind}]
			t.Run(p.state+"/"+kind, func(t *testing.T) {
				note := oneRow(t, then(p.steps, step{kind, appended[kind]}))[11]
				switch {
				case !allowed && note != kind+" cannot follow "+prev:
					t.Errorf("%s after %s: note %q, want it refused", kind, p.state, note)
				case allowed && note != "-" && note != "no event ends the action" && note != "no event proposes an action":
					t.Errorf("%s after %s: note %q, want the step taken", kind, p.state, note)
				}
			})
		}
		t.Run(p.state+"/undeclared", func(t *testing.T) { cannotPlace(t, p.steps, int(undeclared)) })
	}
}

// cannotPlace holds a kind no build declares, after prefix, to an unknown row.
func cannotPlace(t *testing.T, prefix []step, kind int) {
	events := chain("r1", then(prefix, step{"ACTION_PROPOSED", ""})...)
	last := len(events) - 1
	events[last] = strings.Replace(events[last], `"EVENT_KIND_ACTION_PROPOSED"`, strconv.Itoa(kind), 1)
	got := report(t, newExport("1.0").event(events...).whole())
	rows, _ := table(t, got.stdout)
	want := fmt.Sprintf("event r1-%d has kind %d, which this reader cannot place", last+1, kind)
	if len(rows) != 1 || !strings.HasSuffix(rows[0], "\tunknown\t"+want) {
		t.Errorf("rows %q, want one unknown: %s", rows, want)
	}
}

// oneRow runs one request through the report and returns its row's cells.
func oneRow(t *testing.T, s []step) []string {
	t.Helper()
	got := report(t, newExport("1.0").event(chain("r1", s...)...).whole())
	rows, _ := table(t, got.stdout)
	if len(rows) != 1 {
		t.Fatalf("%d rows, want 1:\n%s", len(rows), got.stdout)
	}
	return strings.Split(rows[0], "\t")
}

// then is a followed by b, a left as it was.
func then(a []step, b ...step) []step { return append(append([]step(nil), a...), b...) }

func unknownOne(name, in, row string) reportCase {
	return reportCase{name: name, in: in, rows: []string{row},
		totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 1; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
		code:   1, stderr: "not every request"}
}

func whole(req string, s ...step) string { return newExport("1.0").event(chain(req, s...)...).whole() }

// TestLifecycleShapes holds what a chain of events cannot become: a cycle
// beside the chain, a start that names no execution, and an unanswered
// window asked again and answered.
func TestLifecycleShapes(t *testing.T) {
	r1 := chain("r1", allowed...)
	cycle := concat(r1, []string{
		evt("r1", "r1-5", "r1-6", "FINDING_RAISED", ""),
		evt("r1", "r1-6", "r1-5", "FINDING_RAISED", ""),
	})
	again := then(expired[:4], step{"APPROVAL_REQUESTED", approval("PENDING")}, step{"APPROVAL_DECIDED", approval("APPROVED")},
		step{"ACTION_STARTED", execution("x2")}, step{"ACTION_COMPLETED", ended("x2", "SUCCESS")})
	cases := []reportCase{
		unknownOne("two events that follow each other beside the chain", newExport("1.0").event(cycle...).whole(),
			"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\t2 of the request's events are not on the chain from r1-1"),
		unknownOne("a start that names no execution", whole("r1", allowed[0], allowed[1], step{"ACTION_STARTED", ""},
			step{"ACTION_COMPLETED", `,"result":{"status":"RESULT_STATUS_SUCCESS"}`}),
			"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\tevent r1-3 is ACTION_STARTED and names no execution"),
		{name: "an expired window asked again, answered and run", in: whole("r5", again...),
			rows:   []string{"t\tp\tr5\trun-r5\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\t-\tyes\tapproved\tcompleted\t-"},
			totals: "totals: requests 1, completed 1, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 0; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc) })
	}
}

// TestPayloads holds that an event takes its step only with what the step
// needs: the action proposed, a verdict the contract declares, an answer.
func TestPayloads(t *testing.T) {
	withDecision := func(d string) string {
		return whole("r1", allowed[0], step{"POLICY_DECIDED", `,"decision":` + d}, allowed[2], allowed[3])
	}
	answered := func(a string) string {
		return whole("r3", approved[0], approved[1], approved[2], step{"APPROVAL_DECIDED", a}, approved[4], approved[5])
	}
	cases := []reportCase{
		unknownOne("an empty decision", withDecision(`{}`),
			"t\tp\tr1\trun-r1\tread_order\tUNSPECIFIED\t-\t-\tno\t-\tunknown\tevent r1-2 is POLICY_DECIDED and decides no verdict"),
		unknownOne("an unspecified verdict", withDecision(`{"verdict":"VERDICT_UNSPECIFIED","reasonCodes":["RULE_ALLOW"]}`),
			"t\tp\tr1\trun-r1\tread_order\tUNSPECIFIED\tRULE_ALLOW\t-\tno\t-\tunknown\tevent r1-2 is POLICY_DECIDED and decides no verdict"),
		unknownOne("a verdict the contract does not declare", withDecision(`{"verdict":99,"reasonCodes":["RULE_ALLOW"]}`),
			"t\tp\tr1\trun-r1\tread_order\t99\tRULE_ALLOW\t-\tno\t-\tunknown\tevent r1-2 decides verdict 99, which this reader does not declare"),
		unknownOne("a proposal with no payload", whole("r1", step{"ACTION_PROPOSED", ""}, allowed[1], allowed[2], allowed[3]),
			"t\tp\tr1\trun-r1\t-\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\tevent r1-1 is ACTION_PROPOSED and names no action"),
		unknownOne("a proposal with no action", whole("r1", step{"ACTION_PROPOSED", `,"proposed":{}`}, allowed[1], allowed[2], allowed[3]),
			"t\tp\tr1\trun-r1\t-\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\tevent r1-1 is ACTION_PROPOSED and names no action"),
		unknownOne("an answer with no state", answered(`,"approval":{}`),
			"t\tp\tr3\trun-r3\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\t-\tyes\tunknown\tunknown\tevent r3-4 decides the approval as APPROVAL_STATE_UNSPECIFIED"),
		unknownOne("an answer with no approval", answered(""),
			"t\tp\tr3\trun-r3\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\t-\tyes\tunknown\tunknown\tevent r3-4 decides the approval as APPROVAL_STATE_UNSPECIFIED"),
		unknownOne("an answer the contract does not declare", answered(`,"approval":{"state":99}`),
			"t\tp\tr3\trun-r3\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\t-\tyes\tunknown\tunknown\tevent r3-4 decides the approval as 99"),
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc) })
	}
}

// TestResults holds the end to what the result says: completed only on a
// success, aborted when nothing was sent, failed on a failure, uncertain on a
// failure whose effect nobody could tell, a timeout or an unknown outcome,
// and unknown whenever the result is at odds with its event or missing.
func TestResults(t *testing.T) {
	closed := func(kind, extra string) string {
		return whole("r1", allowed[0], allowed[1], allowed[2], step{kind, extra})
	}
	one := func(end string) string {
		counts := map[string]int{}
		counts[end] = 1
		return fmt.Sprintf("totals: requests 1, completed %d, failed %d, uncertain %d, aborted %d, blocked 0, open 0, unknown %d; "+
			"gaps 0, duplicates 0, conflicting 0, refused 0"+endReached, counts["completed"], counts["failed"], counts["uncertain"], counts["aborted"], counts["unknown"])
	}
	row := "t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\t"
	uncertain := func(status string) reportCase {
		return reportCase{name: "ACTION_FAILED " + status, in: closed("ACTION_FAILED", ended("x1", status)),
			rows:   []string{row + "uncertain\tevent r1-4 is ACTION_FAILED with result RESULT_STATUS_" + status + ": the effect may have happened"},
			totals: one("uncertain"), code: 1, stderr: "1 request(s) ended uncertain"}
	}
	mayHave := func(kind, status string) reportCase {
		return unknownOne(kind+" "+status, closed(kind, ended("x1", status)),
			row+"unknown\tevent r1-4 is "+kind+" with result RESULT_STATUS_"+status+": the effect may have happened")
	}
	cases := []reportCase{
		{name: "a success", in: closed("ACTION_COMPLETED", ended("x1", "SUCCESS")), rows: []string{row + "completed\t-"}, totals: one("completed")},
		{name: "nothing sent", in: closed("ACTION_FAILED", ended("x1", "BLOCKED")), rows: []string{row + "aborted\t-"}, totals: one("aborted")},
		{name: "a failure", in: closed("ACTION_FAILED", ended("x1", "FAILURE")), rows: []string{row + "failed\t-"}, totals: one("failed")},
		uncertain("TIMEOUT"),
		uncertain("UNKNOWN"),
		mayHave("ACTION_COMPLETED", "FAILURE"),
		mayHave("ACTION_COMPLETED", "BLOCKED"),
		mayHave("ACTION_COMPLETED", "UNKNOWN"),
		mayHave("ACTION_FAILED", "SUCCESS"),
		mayHave("ACTION_FAILED", "UNSPECIFIED"),
		mayHave("ACTION_FAILED", "CANCELLED"),
		unknownOne("a result the contract does not declare", closed("ACTION_FAILED", execution("x1")+`,"result":{"status":99}`),
			row+"unknown\tevent r1-4 is ACTION_FAILED with result 99: the effect may have happened"),
		unknownOne("a completion with no result", closed("ACTION_COMPLETED", execution("x1")),
			row+"unknown\tevent r1-4 is ACTION_COMPLETED and carries no result: the effect may have happened"),
		unknownOne("a failure with no result", closed("ACTION_FAILED", execution("x1")),
			row+"unknown\tevent r1-4 is ACTION_FAILED and carries no result: the effect may have happened"),
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc) })
	}
}

func inMode(events []string, mode string) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = strings.ReplaceAll(e, `"ENFORCEMENT_MODE_ENFORCE"`, mode)
	}
	return out
}

// TestEnforcement holds a run to its decision in every mode that enforces
// one, and shows a run in a mode that enforces nothing as it ran.
func TestEnforcement(t *testing.T) {
	ran := func(verdict string) []step {
		return []step{{"ACTION_PROPOSED", proposed("refund")}, {"POLICY_DECIDED", decided(verdict, "RULE_X")},
			{"ACTION_STARTED", execution("x1")}, {"ACTION_COMPLETED", ended("x1", "SUCCESS")}}
	}
	approvedRan := func(verdict string) []step {
		return []step{{"ACTION_PROPOSED", proposed("refund")}, {"POLICY_DECIDED", decided(verdict, "RULE_X")},
			{"APPROVAL_REQUESTED", approval("PENDING")}, {"APPROVAL_DECIDED", approval("APPROVED")},
			{"ACTION_STARTED", execution("x1")}, {"ACTION_COMPLETED", ended("x1", "SUCCESS")}}
	}
	rejectedRan := then(rejected[:4], step{"ACTION_STARTED", execution("x1")}, step{"ACTION_COMPLETED", ended("x1", "SUCCESS")})
	allowRejectedRan := then([]step{allowed[0], allowed[1], {"APPROVAL_REQUESTED", approval("PENDING")},
		{"APPROVAL_DECIDED", approval("REJECTED")}}, allowed[2], allowed[3])
	inModeWhole := func(mode string, s []step) string {
		return newExport("1.0").event(inMode(chain("r2", s...), `"`+mode+`"`)...).whole()
	}
	against := func(name, mode, verdict string) reportCase {
		short := strings.TrimPrefix(mode, "ENFORCEMENT_MODE_")
		return unknownOne(name, inModeWhole(mode, ran(verdict)),
			"t\tp\tr2\trun-r2\trefund\t"+verdict+"\tRULE_X\t-\tno\t-\tunknown\tevent r2-3 starts the action under "+short+
				" after verdict "+verdict+" and no approval: it ran against its decision")
	}
	observed := func(mode, verdict string) reportCase {
		short := strings.TrimPrefix(mode, "ENFORCEMENT_MODE_")
		return reportCase{name: verdict + " run under " + short, in: inModeWhole(mode, ran(verdict)),
			rows: []string{"t\tp\tr2\trun-r2\trefund\t" + verdict + "\tRULE_X\t-\tno\t-\tcompleted\tran under " + short +
				", which enforces nothing, after verdict " + verdict + " and no approval"},
			totals: "totals: requests 1, completed 1, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 0; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached}
	}
	unlifted := func(name, mode, verdict string) reportCase {
		short := strings.TrimPrefix(mode, "ENFORCEMENT_MODE_")
		return unknownOne(name, inModeWhole(mode, approvedRan(verdict)),
			"t\tp\tr2\trun-r2\trefund\t"+verdict+"\tRULE_X\t-\tyes\tapproved\tunknown\tevent r2-5 starts the action under "+short+
				" after verdict "+verdict+", which no approval lifts: it ran against its decision")
	}
	lifted := func(name, mode, verdict string) reportCase {
		return reportCase{name: name, in: inModeWhole(mode, approvedRan(verdict)),
			rows:   []string{"t\tp\tr2\trun-r2\trefund\t" + verdict + "\tRULE_X\t-\tyes\tapproved\tcompleted\t-"},
			totals: "totals: requests 1, completed 1, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 0; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached}
	}
	drop := func(events []string, i int) []string {
		out := append([]string(nil), events...)
		out[i] = strings.Replace(out[i], `,"enforcementMode":"ENFORCEMENT_MODE_ENFORCE"`, "", 1)
		return out
	}
	swap := func(events []string, i int, mode string) []string {
		out := append([]string(nil), events...)
		out[i] = strings.Replace(out[i], `"ENFORCEMENT_MODE_ENFORCE"`, mode, 1)
		return out
	}
	r1 := chain("r1", allowed...)
	allowRow := "t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\t"
	cases := []reportCase{
		against("a denied action run under ENFORCE", "ENFORCEMENT_MODE_ENFORCE", "DENY"),
		against("an undetermined action run under ENFORCE", "ENFORCEMENT_MODE_ENFORCE", "INDETERMINATE"),
		against("an action run without the approval it needed", "ENFORCEMENT_MODE_ENFORCE", "REQUIRE_APPROVAL"),
		against("a denied action run under APPROVE", "ENFORCEMENT_MODE_APPROVE", "DENY"),
		against("a denied action run under LOCKDOWN", "ENFORCEMENT_MODE_LOCKDOWN", "DENY"),
		against("a denied action run under SHADOW", "ENFORCEMENT_MODE_SHADOW", "DENY"),
		unknownOne("an action run after its approval was rejected", inModeWhole("ENFORCEMENT_MODE_ENFORCE", rejectedRan),
			"t\tp\tr2\trun-r2\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\t-\tyes\trejected\tunknown\t"+
				"event r2-5 starts the action under ENFORCE after its approval was rejected: it ran against its decision"),
		unknownOne("an allowed action run after its approval was rejected", inModeWhole("ENFORCEMENT_MODE_APPROVE", allowRejectedRan),
			"t\tp\tr2\trun-r2\tread_order\tALLOW\tRULE_ALLOW\t-\tyes\trejected\tunknown\t"+
				"event r2-5 starts the action under APPROVE after its approval was rejected: it ran against its decision"),
		unlifted("a denied action approved and run under ENFORCE", "ENFORCEMENT_MODE_ENFORCE", "DENY"),
		unlifted("an undetermined action approved and run under ENFORCE", "ENFORCEMENT_MODE_ENFORCE", "INDETERMINATE"),
		unlifted("a denied action approved and run under APPROVE", "ENFORCEMENT_MODE_APPROVE", "DENY"),
		lifted("an action approved as its verdict asked and run", "ENFORCEMENT_MODE_ENFORCE", "REQUIRE_APPROVAL"),
		lifted("an allowed action APPROVE held, approved and run", "ENFORCEMENT_MODE_APPROVE", "ALLOW"),
		{name: "a denied action approved and run under OBSERVE", in: inModeWhole("ENFORCEMENT_MODE_OBSERVE", approvedRan("DENY")),
			rows: []string{"t\tp\tr2\trun-r2\trefund\tDENY\tRULE_X\t-\tyes\tapproved\tcompleted\t" +
				"ran under OBSERVE, which enforces nothing, after verdict DENY, which no approval lifts"},
			totals: "totals: requests 1, completed 1, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 0; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached},
		observed("ENFORCEMENT_MODE_OBSERVE", "DENY"),
		observed("ENFORCEMENT_MODE_WARN", "INDETERMINATE"),
		unknownOne("an event that names no mode", newExport("1.0").event(drop(r1, 2)...).whole(),
			allowRow+"event r1-3 names no enforcement mode"),
		unknownOne("a mode the contract does not declare", newExport("1.0").event(swap(r1, 2, "99")...).whole(),
			allowRow+"event r1-3 names enforcement mode 99, which this reader does not declare"),
		unknownOne("a mode that changes within the request", newExport("1.0").event(swap(r1, 2, `"ENFORCEMENT_MODE_OBSERVE"`)...).whole(),
			allowRow+"event r1-3 names enforcement mode OBSERVE, and the request's first event ENFORCE"),
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc) })
	}
}
