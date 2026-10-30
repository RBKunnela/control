package scenario_test

import (
	"strings"
	"testing"

	"github.com/guardana/control/internal/scenario"
)

type refusalCase struct {
	name string
	raw  string
	err  scenario.Error
	path string
}

func runRefusals(t *testing.T, cases []refusalCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { refused(t, c.raw, c.err, c.path) })
	}
}

func withPlane(plane string) string {
	return top(`"about":"a","plane":` + plane + `,"steps":[` + plain() + `]`)
}

// TestTopLevelRefusals: about, plane, run and steps, each at the input where
// its rule bites; the accepted inputs beside them are the other side.
func TestTopLevelRefusals(t *testing.T) {
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	runRefusals(t, []refusalCase{
		{"about missing", top(`"plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":[` + plain() + `]`), scenario.ErrMissing, "about"},
		{"about empty", top(`"about":"","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":[` + plain() + `]`), scenario.ErrBound, "about"},
		{"about 201", top(`"about":"` + strings.Repeat("a", 201) + `","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":[` + plain() + `]`), scenario.ErrBound, "about"},
		{"about line feed", top(`"about":"a\nb","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":[` + plain() + `]`), scenario.ErrValue, "about"},
		{"about tab", top(`"about":"a\tb","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":[` + plain() + `]`), scenario.ErrValue, "about"},
		{"about escape", top(`"about":"a\u001b[31m","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":[` + plain() + `]`), scenario.ErrValue, "about"},
		{"about number", top(`"about":1,"plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":[` + plain() + `]`), scenario.ErrWrongType, "about"},
		{"plane missing", top(`"about":"a","steps":[` + plain() + `]`), scenario.ErrMissing, "plane"},
		{"mode missing", withPlane(`{"bundle":{"id":"demo"}}`), scenario.ErrMissing, "plane.mode"},
		{"mode unknown", withPlane(`{"mode":"AUDIT","bundle":{"id":"demo"}}`), scenario.ErrValue, "plane.mode"},
		{"mode lower case", withPlane(`{"mode":"enforce","bundle":{"id":"demo"}}`), scenario.ErrValue, "plane.mode"},
		{"mode prefixed", withPlane(`{"mode":"ENFORCEMENT_MODE_ENFORCE","bundle":{"id":"demo"}}`), scenario.ErrValue, "plane.mode"},
		{"bundle missing", withPlane(`{"mode":"ENFORCE"}`), scenario.ErrMissing, "plane.bundle"},
		{"bundle id missing", withPlane(`{"mode":"ENFORCE","bundle":{"digest":"` + digest + `"}}`), scenario.ErrMissing, "plane.bundle.id"},
		{"bundle id empty", withPlane(`{"mode":"ENFORCE","bundle":{"id":""}}`), scenario.ErrBound, "plane.bundle.id"},
		{"bundle id 1025", withPlane(`{"mode":"ENFORCE","bundle":{"id":"` + strings.Repeat("b", 1025) + `"}}`), scenario.ErrBound, "plane.bundle.id"},
		{"bundle id space at end", withPlane(`{"mode":"ENFORCE","bundle":{"id":"demo "}}`), scenario.ErrValue, "plane.bundle.id"},
		{"digest upper case", withPlane(`{"mode":"ENFORCE","bundle":{"id":"demo","digest":"` + strings.ToUpper(digest) + `"}}`), scenario.ErrValue, "plane.bundle.digest"},
		{"digest upper hex", withPlane(`{"mode":"ENFORCE","bundle":{"id":"demo","digest":"sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"}}`), scenario.ErrValue, "plane.bundle.digest"},
		{"digest short", withPlane(`{"mode":"ENFORCE","bundle":{"id":"demo","digest":"` + digest[:len(digest)-1] + `"}}`), scenario.ErrValue, "plane.bundle.digest"},
		{"digest long", withPlane(`{"mode":"ENFORCE","bundle":{"id":"demo","digest":"` + digest + `0"}}`), scenario.ErrValue, "plane.bundle.digest"},
		{"digest other hash", withPlane(`{"mode":"ENFORCE","bundle":{"id":"demo","digest":"sha512:` + digest[7:] + `"}}`), scenario.ErrValue, "plane.bundle.digest"},
		{"digest empty", withPlane(`{"mode":"ENFORCE","bundle":{"id":"demo","digest":""}}`), scenario.ErrValue, "plane.bundle.digest"},
		{"run unknown", top(`"about":"a","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"run":"later","steps":[` + plain() + `]`), scenario.ErrValue, "run"},
		{"steps missing", top(`"about":"a","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}}`), scenario.ErrMissing, "steps"},
		{"steps empty", doc(), scenario.ErrBound, "steps"},
		{"steps 257", doc(slicesOf(plain(), 257)...), scenario.ErrBound, "steps"},
		{"steps object", top(`"about":"a","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":{}`), scenario.ErrWrongType, "steps"},
	})
	accept(t, top(`"about":"`+strings.Repeat("a", 200)+`","plane":{"mode":"ENFORCE","bundle":{"id":"`+strings.Repeat("b", 1024)+`","digest":"`+digest+`"}},"steps":[`+plain()+`]`))
	accept(t, top(`"about":"spaces and é","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":[`+plain()+`]`))
	if s := accept(t, doc(slicesOf(plain(), 256)...)); len(s.Steps) != 256 {
		t.Errorf("read %d steps, want 256", len(s.Steps))
	}
}

func slicesOf(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// TestStepShape: a step is an object with exactly one known member.
func TestStepShape(t *testing.T) {
	runRefusals(t, []refusalCase{
		{"empty", doc(plain(), `{}`), scenario.ErrStep, "steps[1]"},
		{"two", doc(plain(), `{"pause":{"global":true},"unpause":{"step":0}}`), scenario.ErrStep, "steps[1]"},
		{"array", doc(plain(), `[]`), scenario.ErrWrongType, "steps[1]"},
		{"string", doc(plain(), `"call"`), scenario.ErrWrongType, "steps[1]"},
	})
}

// TestCallRefusals: tool, args, answer, decided and trail, one rule each.
func TestCallRefusals(t *testing.T) {
	c := func(tool string) string {
		return `{"call":{"tool":` + tool + `,"args":{},"answer":` + resultAnswer + `,"decided":"none","trail":` + newTrail + `}}`
	}
	missing := func(drop string) string {
		members := map[string]string{"tool": `"t"`, "args": `{}`, "answer": resultAnswer, "decided": `"none"`, "trail": newTrail}
		var parts []string
		for _, k := range []string{"tool", "args", "answer", "decided", "trail"} {
			if k != drop {
				parts = append(parts, `"`+k+`":`+members[k])
			}
		}
		return `{"call":{` + strings.Join(parts, ",") + `}}`
	}
	runRefusals(t, []refusalCase{
		{"tool missing", doc(missing("tool")), scenario.ErrMissing, "steps[0].call.tool"},
		{"args missing", doc(missing("args")), scenario.ErrMissing, "steps[0].call.args"},
		{"answer missing", doc(missing("answer")), scenario.ErrMissing, "steps[0].call.answer"},
		{"decided missing", doc(missing("decided")), scenario.ErrMissing, "steps[0].call.decided"},
		{"trail missing", doc(missing("trail")), scenario.ErrMissing, "steps[0].call.trail"},
		{"tool empty", doc(c(`""`)), scenario.ErrBound, "steps[0].call.tool"},
		{"tool 1025", doc(c(`"` + strings.Repeat("t", 1025) + `"`)), scenario.ErrBound, "steps[0].call.tool"},
		{"tool number", doc(c(`1`)), scenario.ErrWrongType, "steps[0].call.tool"},
		{"args array", doc(call(`[]`, resultAnswer, noDecision, newTrail)), scenario.ErrWrongType, "steps[0].call.args"},
		{"args string", doc(call(`"{}"`, resultAnswer, noDecision, newTrail)), scenario.ErrWrongType, "steps[0].call.args"},
		{"call not object", doc(`{"call":[]}`), scenario.ErrWrongType, "steps[0].call"},
	})
	accept(t, doc(c(`"`+strings.Repeat("t", 1024)+`"`)))
}

// TestAnswerRefusals: the kind is one of four, every code is registered, a
// result and an error carry none and a pending answer exactly its own.
func TestAnswerRefusals(t *testing.T) {
	a := func(answer string) string { return doc(call(`{}`, answer, noDecision, newTrail)) }
	runRefusals(t, []refusalCase{
		{"kind unknown", a(`{"kind":"ok","codes":[]}`), scenario.ErrValue, "steps[0].call.answer.kind"},
		{"kind missing", a(`{"codes":[]}`), scenario.ErrMissing, "steps[0].call.answer.kind"},
		{"codes missing", a(`{"kind":"result"}`), scenario.ErrMissing, "steps[0].call.answer.codes"},
		{"codes string", a(`{"kind":"result","codes":"RULE_DENY"}`), scenario.ErrWrongType, "steps[0].call.answer.codes"},
		{"code unregistered", a(`{"kind":"blocked","codes":["RULE_DENY","NOT_A_CODE"]}`), scenario.ErrValue, "steps[0].call.answer.codes[1]"},
		{"code lower case", a(`{"kind":"blocked","codes":["rule_deny"]}`), scenario.ErrValue, "steps[0].call.answer.codes[0]"},
		{"code number", a(`{"kind":"blocked","codes":[1]}`), scenario.ErrWrongType, "steps[0].call.answer.codes[0]"},
		{"result with a code", a(`{"kind":"result","codes":["RULE_ALLOW"]}`), scenario.ErrValue, "steps[0].call.answer.codes"},
		{"error with a code", a(`{"kind":"error","codes":["RULE_ALLOW"]}`), scenario.ErrValue, "steps[0].call.answer.codes"},
		{"pending with none", a(`{"kind":"pending","codes":[]}`), scenario.ErrValue, "steps[0].call.answer.codes"},
		{"pending twice", a(`{"kind":"pending","codes":["APPROVAL_PENDING","APPROVAL_PENDING"]}`), scenario.ErrValue, "steps[0].call.answer.codes"},
		{"pending other", a(`{"kind":"pending","codes":["APPROVAL_REQUIRED"]}`), scenario.ErrValue, "steps[0].call.answer.codes"},
		{"codes 65", a(`{"kind":"blocked","codes":[` + repeatJoin(`"RULE_DENY"`, 65) + `]}`), scenario.ErrBound, "steps[0].call.answer.codes"},
	})
	if s := accept(t, a(`{"kind":"blocked","codes":[`+repeatJoin(`"RULE_DENY"`, 64)+`]}`)); len(s.Steps[0].Call.Answer.Codes) != 64 {
		t.Errorf("read %d codes, want all 64 as written", len(s.Steps[0].Call.Answer.Codes))
	}
	accept(t, a(`{"kind":"blocked","codes":[]}`))
	if s := accept(t, a(`{"kind":"error","codes":[]}`)); s.Steps[0].Call.Answer.Kind != scenario.AnswerError {
		t.Errorf("an error answer reads as %q", s.Steps[0].Call.Answer.Kind)
	}
}

func repeatJoin(s string, n int) string { return strings.Join(slicesOf(s, n), ",") }

// TestDecidedRefusals: "none" or a decision whose verdict is named, whose
// codes are registered and whose obligations are in the catalogue.
func TestDecidedRefusals(t *testing.T) {
	d := func(decided string) string { return doc(call(`{}`, resultAnswer, decided, newTrail)) }
	ob := func(o string) string { return `{"verdict":"ALLOW","codes":[],"obligations":[` + o + `]}` }
	runRefusals(t, []refusalCase{
		{"other string", d(`"nothing"`), scenario.ErrValue, "steps[0].call.decided"},
		{"array", d(`[]`), scenario.ErrWrongType, "steps[0].call.decided"},
		{"verdict unspecified", d(`{"verdict":"UNSPECIFIED","codes":[],"obligations":[]}`), scenario.ErrValue, "steps[0].call.decided.verdict"},
		{"verdict prefixed", d(`{"verdict":"VERDICT_ALLOW","codes":[],"obligations":[]}`), scenario.ErrValue, "steps[0].call.decided.verdict"},
		{"verdict lower case", d(`{"verdict":"allow","codes":[],"obligations":[]}`), scenario.ErrValue, "steps[0].call.decided.verdict"},
		{"verdict missing", d(`{"codes":[],"obligations":[]}`), scenario.ErrMissing, "steps[0].call.decided.verdict"},
		{"codes missing", d(`{"verdict":"ALLOW","obligations":[]}`), scenario.ErrMissing, "steps[0].call.decided.codes"},
		{"obligations missing", d(`{"verdict":"ALLOW","codes":[]}`), scenario.ErrMissing, "steps[0].call.decided.obligations"},
		{"code unregistered", d(`{"verdict":"DENY","codes":["RULE_DENY","DENIED"],"obligations":[]}`), scenario.ErrValue, "steps[0].call.decided.codes[1]"},
		{"codes 65", d(`{"verdict":"DENY","codes":[` + repeatJoin(`"RULE_DENY"`, 65) + `],"obligations":[]}`), scenario.ErrBound, "steps[0].call.decided.codes"},
		{"type outside the catalogue", d(ob(`{"type":"redact","params":{},"advisory":false}`)), scenario.ErrValue, "steps[0].call.decided.obligations[0].type"},
		{"type missing", d(ob(`{"params":{},"advisory":false}`)), scenario.ErrMissing, "steps[0].call.decided.obligations[0].type"},
		{"params missing", d(ob(`{"type":"read_only","advisory":false}`)), scenario.ErrMissing, "steps[0].call.decided.obligations[0].params"},
		{"advisory missing", d(ob(`{"type":"read_only","params":{}}`)), scenario.ErrMissing, "steps[0].call.decided.obligations[0].advisory"},
		{"params array", d(ob(`{"type":"read_only","params":[],"advisory":false}`)), scenario.ErrWrongType, "steps[0].call.decided.obligations[0].params"},
		{"advisory string", d(ob(`{"type":"read_only","params":{},"advisory":"false"}`)), scenario.ErrWrongType, "steps[0].call.decided.obligations[0].advisory"},
		{"obligation string", d(ob(`"read_only"`)), scenario.ErrWrongType, "steps[0].call.decided.obligations[0]"},
		{"obligations 65", d(ob(repeatJoin(`{"type":"read_only","params":{},"advisory":false}`, 65))), scenario.ErrBound, "steps[0].call.decided.obligations"},
	})
	s := accept(t, d(ob(repeatJoin(`{"type":"read_only","params":{},"advisory":false}`, 64))))
	if n := len(s.Steps[0].Call.Decided.Obligations); n != 64 {
		t.Errorf("read %d obligations, want 64", n)
	}
	accept(t, d(`{"verdict":"DENY","codes":[`+repeatJoin(`"RULE_DENY"`, 64)+`],"obligations":[]}`))
	accept(t, d(`{"verdict":"INDETERMINATE","codes":["POLICY_UNAVAILABLE"],"obligations":[]}`))
}

// TestTrailRefusals: a request that is new or names an earlier pending call,
// and kinds that are named events.
func TestTrailRefusals(t *testing.T) {
	tr := func(trail string) string { return doc(pending(), call(`{}`, resultAnswer, noDecision, trail)) }
	runRefusals(t, []refusalCase{
		{"not an object", doc(call(`{}`, resultAnswer, noDecision, `"new"`)), scenario.ErrWrongType, "steps[0].call.trail"},
		{"request missing", tr(`{"kinds":[]}`), scenario.ErrMissing, "steps[1].call.trail.request"},
		{"kinds missing", tr(`{"request":"new"}`), scenario.ErrMissing, "steps[1].call.trail.kinds"},
		{"request unknown", tr(`{"request":"old","kinds":[]}`), scenario.ErrValue, "steps[1].call.trail.request"},
		{"request leading zero", tr(`{"request":"step[00]","kinds":[]}`), scenario.ErrValue, "steps[1].call.trail.request"},
		{"request spaced", tr(`{"request":"step[ 0]","kinds":[]}`), scenario.ErrValue, "steps[1].call.trail.request"},
		{"request negative", tr(`{"request":"step[-1]","kinds":[]}`), scenario.ErrValue, "steps[1].call.trail.request"},
		{"request unclosed", tr(`{"request":"step[0","kinds":[]}`), scenario.ErrValue, "steps[1].call.trail.request"},
		{"request itself", tr(`{"request":"step[1]","kinds":[]}`), scenario.ErrStep, "steps[1].call.trail.request"},
		{"request later", tr(`{"request":"step[2]","kinds":[]}`), scenario.ErrStep, "steps[1].call.trail.request"},
		{"request huge", tr(`{"request":"step[99999999999999999999]","kinds":[]}`), scenario.ErrStep, "steps[1].call.trail.request"},
		{"request not pending", doc(plain(), call(`{}`, resultAnswer, noDecision, `{"request":"step[0]","kinds":[]}`)), scenario.ErrStep, "steps[1].call.trail.request"},
		{"request a pause", doc(pending(), `{"pause":{"global":true}}`, call(`{}`, resultAnswer, noDecision, `{"request":"step[1]","kinds":[]}`)), scenario.ErrStep, "steps[2].call.trail.request"},
		{"kind unspecified", tr(`{"request":"new","kinds":["UNSPECIFIED"]}`), scenario.ErrValue, "steps[1].call.trail.kinds[0]"},
		{"kind prefixed", tr(`{"request":"new","kinds":["ACTION_PROPOSED","EVENT_KIND_POLICY_DECIDED"]}`), scenario.ErrValue, "steps[1].call.trail.kinds[1]"},
		{"kind unnamed", tr(`{"request":"new","kinds":["ACTION"]}`), scenario.ErrValue, "steps[1].call.trail.kinds[0]"},
		{"kinds 65", tr(`{"request":"new","kinds":[` + repeatJoin(`"ACTION_PROPOSED"`, 65) + `]}`), scenario.ErrBound, "steps[1].call.trail.kinds"},
	})
	s := accept(t, tr(`{"request":"step[0]","kinds":[`+repeatJoin(`"FINDING_RAISED"`, 64)+`]}`))
	if got := s.Steps[1].Call.Trail; got.Request != 0 || len(got.Kinds) != 64 {
		t.Errorf("Trail = %+v, want request 0 and 64 kinds", got)
	}
}

// TestNoCallExpectsAnEvent: a scenario whose trails may all be empty would
// examine nothing, and is refused; one expected event is enough.
func TestNoCallExpectsAnEvent(t *testing.T) {
	refused(t, doc(call(`{}`, resultAnswer, noDecision, emptyTrail), `{"pause":{"global":true}}`), scenario.ErrNoEvidence, "steps")
	accept(t, doc(call(`{}`, resultAnswer, noDecision, emptyTrail), plain()))
}

// TestApprovalRefusals: an approve or a reject answers an earlier pending
// call, names an approver the approvals store would take, the reserved authn:
// prefix refused as the store refuses it, and gives a reason it would take or
// none.
func TestApprovalRefusals(t *testing.T) {
	ap := func(body string) string { return doc(pending(), `{"approve":`+body+`}`) }
	runRefusals(t, []refusalCase{
		{"step missing", ap(`{"approver":"a"}`), scenario.ErrMissing, "steps[1].approve.step"},
		{"approver missing", ap(`{"step":0}`), scenario.ErrMissing, "steps[1].approve.approver"},
		{"itself", ap(`{"step":1,"approver":"a"}`), scenario.ErrStep, "steps[1].approve.step"},
		{"later", doc(pending(), `{"approve":{"step":2,"approver":"a"}}`, pending()), scenario.ErrStep, "steps[1].approve.step"},
		{"not pending", doc(plain(), `{"approve":{"step":0,"approver":"a"}}`), scenario.ErrStep, "steps[1].approve.step"},
		{"not a call", doc(pending(), `{"pause":{"global":true}}`, `{"reject":{"step":1,"approver":"a"}}`), scenario.ErrStep, "steps[2].reject.step"},
		{"step negative", ap(`{"step":-1,"approver":"a"}`), scenario.ErrValue, "steps[1].approve.step"},
		{"step fraction", ap(`{"step":0.0,"approver":"a"}`), scenario.ErrValue, "steps[1].approve.step"},
		{"step exponent", ap(`{"step":0e0,"approver":"a"}`), scenario.ErrValue, "steps[1].approve.step"},
		{"step string", ap(`{"step":"0","approver":"a"}`), scenario.ErrWrongType, "steps[1].approve.step"},
		{"step huge", ap(`{"step":99999999999999999999,"approver":"a"}`), scenario.ErrStep, "steps[1].approve.step"},
		{"approver empty", ap(`{"step":0,"approver":""}`), scenario.ErrBound, "steps[1].approve.approver"},
		{"approver 129", ap(`{"step":0,"approver":"` + strings.Repeat("a", 129) + `"}`), scenario.ErrBound, "steps[1].approve.approver"},
		{"approver space at end", ap(`{"step":0,"approver":"alice "}`), scenario.ErrValue, "steps[1].approve.approver"},
		{"approver control", ap(`{"step":0,"approver":"al\tice"}`), scenario.ErrValue, "steps[1].approve.approver"},
		{"approver reserved prefix", ap(`{"step":0,"approver":"authn:x"}`), scenario.ErrValue, "steps[1].approve.approver"},
		{"approver reserved prefix in capitals", ap(`{"step":0,"approver":"AUTHN:okta:alice"}`), scenario.ErrValue, "steps[1].approve.approver"},
		{"reject approver reserved prefix", doc(pending(), `{"reject":{"step":0,"approver":"authn\u0903x"}}`), scenario.ErrValue, "steps[1].reject.approver"},
		{"reason empty", ap(`{"step":0,"approver":"a","reason":""}`), scenario.ErrBound, "steps[1].approve.reason"},
		{"reason 1025", ap(`{"step":0,"approver":"a","reason":"` + strings.Repeat("r", 1025) + `"}`), scenario.ErrBound, "steps[1].approve.reason"},
		{"reason line feed", ap(`{"step":0,"approver":"a","reason":"one\ntwo"}`), scenario.ErrValue, "steps[1].approve.reason"},
		{"reason tab", ap(`{"step":0,"approver":"a","reason":"one\ttwo"}`), scenario.ErrValue, "steps[1].approve.reason"},
		{"reject approver empty", doc(pending(), `{"reject":{"step":0,"approver":""}}`), scenario.ErrBound, "steps[1].reject.approver"},
	})
	s := accept(t, ap(`{"step":0,"approver":"`+strings.Repeat("a", 128)+`","reason":"`+strings.Repeat("r", 1024)+`"}`))
	if got := s.Steps[1].Approve; got == nil || got.Step != 0 || len(got.Approver) != 128 || len(got.Reason) != 1024 {
		t.Errorf("Approve = %+v", got)
	}
}

// TestAPendingCallIsAnsweredOnce: a second approve or reject of one pending
// call is refused, whichever answered first; two pending calls take one
// answer each.
func TestAPendingCallIsAnsweredOnce(t *testing.T) {
	const approve0, reject0 = `{"approve":{"step":0,"approver":"a"}}`, `{"reject":{"step":0,"approver":"a"}}`
	runRefusals(t, []refusalCase{
		{"approved twice", doc(pending(), approve0, approve0), scenario.ErrStep, "steps[2].approve.step"},
		{"approved then rejected", doc(pending(), approve0, reject0), scenario.ErrStep, "steps[2].reject.step"},
		{"rejected then approved", doc(pending(), reject0, approve0), scenario.ErrStep, "steps[2].approve.step"},
		{"answered twice with a call between", doc(pending(), reject0, plain(), reject0), scenario.ErrStep, "steps[3].reject.step"},
	})
	s := accept(t, doc(pending(), pending(), approve0, `{"reject":{"step":1,"approver":"a"}}`))
	if s.Steps[2].Approve.Step != 0 || s.Steps[3].Reject.Step != 1 {
		t.Errorf("answered steps = %d, %d", s.Steps[2].Approve.Step, s.Steps[3].Reject.Step)
	}
}

// TestPauseRefusals: exactly one scope as the pause command takes it, and a
// reason the pause file would keep with the runner's 38-byte marker added:
// 474 bytes of the file's 512.
func TestPauseRefusals(t *testing.T) {
	p := func(body string) string { return doc(plain(), `{"pause":`+body+`}`) }
	runRefusals(t, []refusalCase{
		{"nothing", p(`{}`), scenario.ErrValue, "steps[1].pause"},
		{"global false", p(`{"global":false}`), scenario.ErrValue, "steps[1].pause.global"},
		{"global string", p(`{"global":"true"}`), scenario.ErrWrongType, "steps[1].pause.global"},
		{"global and provider", p(`{"global":true,"provider":"mail"}`), scenario.ErrValue, "steps[1].pause"},
		{"global and action", p(`{"global":true,"action":"tool"}`), scenario.ErrValue, "steps[1].pause"},
		{"name without action", p(`{"provider":"mail","name":"send"}`), scenario.ErrValue, "steps[1].pause"},
		{"action without provider", p(`{"action":"prompt"}`), scenario.ErrValue, "steps[1].pause"},
		{"tool without name", p(`{"provider":"mail","action":"tool"}`), scenario.ErrValue, "steps[1].pause"},
		{"prompt with name", p(`{"provider":"mail","action":"prompt","name":"p"}`), scenario.ErrValue, "steps[1].pause"},
		{"resource with name", p(`{"provider":"mail","action":"resource","name":"r"}`), scenario.ErrValue, "steps[1].pause"},
		{"action unknown", p(`{"provider":"mail","action":"call"}`), scenario.ErrValue, "steps[1].pause"},
		{"provider empty", p(`{"provider":""}`), scenario.ErrValue, "steps[1].pause"},
		{"provider 257", p(`{"provider":"` + strings.Repeat("p", 257) + `"}`), scenario.ErrValue, "steps[1].pause"},
		{"reason 513", p(`{"global":true,"reason":"` + strings.Repeat("r", 513) + `"}`), scenario.ErrValue, "steps[1].pause.reason"},
		{"reason 475", p(`{"global":true,"reason":"` + strings.Repeat("r", 475) + `"}`), scenario.ErrBound, "steps[1].pause.reason"},
		{"reason control", p(`{"global":true,"reason":"a\u0007"}`), scenario.ErrValue, "steps[1].pause.reason"},
		{"reason empty", p(`{"global":true,"reason":""}`), scenario.ErrBound, "steps[1].pause.reason"},
	})
	s := accept(t, p(`{"provider":"`+strings.Repeat("p", 256)+`","action":"resource","reason":"`+strings.Repeat("r", 474)+`"}`))
	if got := s.Steps[1].Pause; got == nil || len(got.Scope.Provider) != 256 || got.Scope.Action != "resource" || len(got.Reason) != 474 {
		t.Errorf("Pause = %+v", got)
	}
}

// TestUnpauseRefusals: an unpause lifts an earlier pause step, once.
func TestUnpauseRefusals(t *testing.T) {
	runRefusals(t, []refusalCase{
		{"a call", doc(plain(), `{"unpause":{"step":0}}`), scenario.ErrStep, "steps[1].unpause.step"},
		{"itself", doc(plain(), `{"unpause":{"step":1}}`), scenario.ErrStep, "steps[1].unpause.step"},
		{"later", doc(plain(), `{"unpause":{"step":2}}`, `{"pause":{"global":true}}`), scenario.ErrStep, "steps[1].unpause.step"},
		{"twice", doc(plain(), `{"pause":{"global":true}}`, `{"unpause":{"step":1}}`, `{"unpause":{"step":1}}`), scenario.ErrStep, "steps[3].unpause.step"},
		{"missing", doc(plain(), `{"unpause":{}}`), scenario.ErrMissing, "steps[1].unpause.step"},
	})
	s := accept(t, doc(plain(), `{"pause":{"global":true}}`, `{"pause":{"global":true}}`, `{"unpause":{"step":2}}`, `{"unpause":{"step":1}}`))
	if s.Steps[3].Unpause.Step != 2 || s.Steps[4].Unpause.Step != 1 {
		t.Errorf("unpause steps = %d, %d", s.Steps[3].Unpause.Step, s.Steps[4].Unpause.Step)
	}
}
