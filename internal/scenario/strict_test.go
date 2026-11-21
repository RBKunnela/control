package scenario_test

import (
	"strings"
	"testing"

	"github.com/guardana/control/internal/scenario"
)

// TestKindIsCheckedFirst: whatever else is wrong with a document and wherever
// kind stands, a kind this build does not read is the refusal, named kind.
func TestKindIsCheckedFirst(t *testing.T) {
	for _, raw := range []string{
		`{"zzz":1,"kind":"agent-scenario/v2","yyy":2}`,
		`{"about":null,"kind":"agent-scenario/v2"}`,
		`{"about":"a","about":"b","kind":"agent-scenario/v2"}`,
		`{"about":"\ud800","kind":"agent-scenario/v2"}`,
		"{\"about\":\"\xff\",\"kind\":\"agent-scenario/v2\"}",
		`{"kind":"agent-scenario/v2"} trailing`,
		`{"steps":[{"call":{"args":{"p":null}}}],"kind":"agent-scenario/v1alpha2"}`,
	} {
		refused(t, raw, scenario.ErrKind, "kind")
	}
}

// TestKindIsCheckedBeforeTheDepth: containers past the bound, before or
// after kind and however many, do not hide a kind this build does not read;
// the text past the bound is still held to JSON syntax.
func TestKindIsCheckedBeforeTheDepth(t *testing.T) {
	nest := func(n int, inner string) string { return strings.Repeat("[", n) + inner + strings.Repeat("]", n) }
	for _, raw := range []string{
		`{"kind":"agent-scenario/v2","deep":` + nest(64, "") + `}`,
		`{"deep":` + nest(64, "") + `,"kind":"agent-scenario/v2"}`,
		`{"deep":` + nest(64, `{"a":[1,"x",true,false,{}],"b":{"c":[]}}`) + `,"kind":"agent-scenario/v2"}`,
		`{"deep":{"x":` + nest(100000, "") + `},"kind":"agent-scenario/v2"}`,
	} {
		refused(t, raw, scenario.ErrKind, "kind")
	}
	refused(t, `{"kind":"agent-scenario/v2","deep":`+nest(64, "1,,2")+`}`, scenario.ErrSyntax, "deep"+strings.Repeat("[0]", 63))
	refused(t, `{"kind":"agent-scenario/v2","deep":`+nest(64, `{"a" 1}`)+`}`, scenario.ErrSyntax, "deep"+strings.Repeat("[0]", 63))
	refused(t, `{"kind":"agent-scenario/v2","deep":`+strings.Repeat("[", 66)+"]", scenario.ErrSyntax, "deep"+strings.Repeat("[0]", 63))
}

// TestKindRefusals: a document with no kind, two, or one that is not a
// string names kind; one that is not an object has no kind to name.
func TestKindRefusals(t *testing.T) {
	refused(t, `{"zzz":1}`, scenario.ErrMissing, "kind")
	refused(t, `{"kind":"agent-scenario/v1alpha1","kind":"agent-scenario/v1alpha1"}`, scenario.ErrDuplicate, "kind")
	refused(t, `{"kind":1}`, scenario.ErrWrongType, "kind")
	refused(t, `{"kind":null}`, scenario.ErrNull, "kind")
	refused(t, `[]`, scenario.ErrWrongType, "")
	refused(t, `"agent-scenario/v1alpha1"`, scenario.ErrWrongType, "")
}

// TestKnownKindThenOtherRefusals: with the kind right, the other refusals
// come through, each naming its member.
func TestKnownKindThenOtherRefusals(t *testing.T) {
	refused(t, `{"zzz":1,"kind":"agent-scenario/v1alpha1"}`, scenario.ErrUnknownMember, "zzz")
	refused(t, `{"about":null,"kind":"agent-scenario/v1alpha1"}`, scenario.ErrNull, "about")
}

// TestNullIsRefusedEverywhere: inside arguments and parameters, which are
// otherwise kept as written, a null is refused as a null.
func TestNullIsRefusedEverywhere(t *testing.T) {
	obligation := func(params string) string {
		return `{"verdict":"ALLOW_WITH_OBLIGATIONS","codes":[],"obligations":[{"type":"emit_alert","params":` + params + `,"advisory":true}]}`
	}
	for _, c := range []struct{ raw, path string }{
		{doc(call(`{"p":null}`, resultAnswer, noDecision, newTrail)), "steps[0].call.args.p"},
		{doc(call(`{"p":[1,null]}`, resultAnswer, noDecision, newTrail)), "steps[0].call.args.p[1]"},
		{doc(call(`{"p":{"q":null}}`, resultAnswer, noDecision, newTrail)), "steps[0].call.args.p.q"},
		{doc(call(`{}`, resultAnswer, obligation(`{"x":null}`), newTrail)), "steps[0].call.decided.obligations[0].params.x"},
		{doc(call(`{}`, `{"kind":"result","codes":null}`, noDecision, newTrail)), "steps[0].call.answer.codes"},
		{doc(call(`null`, resultAnswer, noDecision, newTrail)), "steps[0].call.args"},
		{top(`"about":"a","plane":{"mode":"ENFORCE","bundle":{"id":"demo","digest":null}},"steps":[` + plain() + `]`), "plane.bundle.digest"},
	} {
		refused(t, c.raw, scenario.ErrNull, c.path)
	}
	accept(t, doc(call(`{"p":{"q":[1,"null",false]}}`, resultAnswer, obligation(`{"x":"null"}`), newTrail)))
}

// TestLoneSurrogatesAreRefused: a surrogate escape with no partner is a code
// unit no UTF-8 text holds; a pair is one character and is kept.
func TestLoneSurrogatesAreRefused(t *testing.T) {
	for _, c := range []struct{ args, path string }{
		{`{"p":"\ud800"}`, "steps[0].call.args.p"},
		{`{"p":"\udc00x"}`, "steps[0].call.args.p"},
		{`{"p":"\ud800\u0041"}`, "steps[0].call.args.p"},
		{`{"p":"\uDBFF"}`, "steps[0].call.args.p"},
		{`{"p":"\ude00\ud83d"}`, "steps[0].call.args.p"},
		{`{"p":["ok","\ud800\ud800"]}`, "steps[0].call.args.p[1]"},
		{`{"\ud800":1}`, `steps[0].call.args["\ufffd"]`},
	} {
		refused(t, doc(call(c.args, resultAnswer, noDecision, newTrail)), scenario.ErrSurrogate, c.path)
	}
	s := accept(t, doc(call(`{"p":"\ud83d\ude00\uD83D\uDE00"}`, resultAnswer, noDecision, newTrail)))
	if got := string(s.Steps[0].Call.Args); got != `{"p":"\ud83d\ude00\uD83D\uDE00"}` {
		t.Errorf("Args = %q, want the pair as written", got)
	}
}

// TestBytesThatAreNotUTF8: inside a string they are refused as such, and the
// quote shows the byte; outside one they are not JSON at all.
func TestBytesThatAreNotUTF8(t *testing.T) {
	r := refused(t, doc(call("{\"p\":\"a\xffb\"}", resultAnswer, noDecision, newTrail)), scenario.ErrNotUTF8, "steps[0].call.args.p")
	if r.Quote != `\"a\xffb\"` {
		t.Errorf("Quote = %q, want the token with the byte escaped", r.Quote)
	}
	refused(t, doc(call("{\"p\":\"\xed\xa0\x80\"}", resultAnswer, noDecision, newTrail)), scenario.ErrNotUTF8, "steps[0].call.args.p")
	refused(t, top("\"about\":\"a\xc3\""), scenario.ErrNotUTF8, "about")
	refused(t, top("\"about\":\"a\",\xff"), scenario.ErrSyntax, "")
	refused(t, "\xef\xbb\xbf"+doc(plain()), scenario.ErrSyntax, "")
	accept(t, doc(call("{\"p\":\"\xc3\xa9\xf0\x9f\x98\x80\"}", resultAnswer, noDecision, newTrail)))
}

// TestRepeatedMembersAreRefused at every depth, compared as decoded text.
func TestRepeatedMembersAreRefused(t *testing.T) {
	for _, c := range []struct{ raw, path string }{
		{top(`"about":"a","about":"a"`), "about"},
		{doc(call(`{"a":1,"a":1}`, resultAnswer, noDecision, newTrail)), "steps[0].call.args.a"},
		{doc(call(`{"a":1,"\u0061":1}`, resultAnswer, noDecision, newTrail)), "steps[0].call.args.a"},
		{doc(call(`{"x":{"a":[{"b":1,"b":2}]}}`, resultAnswer, noDecision, newTrail)), "steps[0].call.args.x.a[0].b"},
		{doc(`{"call":{"tool":"t","tool":"t","args":{},"answer":` + resultAnswer + `,"decided":"none","trail":` + newTrail + `}}`), "steps[0].call.tool"},
	} {
		refused(t, c.raw, scenario.ErrDuplicate, c.path)
	}
	accept(t, doc(call(`{"a":1,"A":1,"x":{"a":1}}`, resultAnswer, noDecision, newTrail)))
}

// TestUnknownMembersAreRefused at every level the format fixes.
func TestUnknownMembersAreRefused(t *testing.T) {
	for _, c := range []struct{ raw, path string }{
		{top(`"about":"a","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":[` + plain() + `],"extra":1`), "extra"},
		{top(`"about":"a","plane":{"mode":"ENFORCE","pdp":"x","bundle":{"id":"demo"}},"steps":[` + plain() + `]`), "plane.pdp"},
		{top(`"about":"a","plane":{"mode":"ENFORCE","bundle":{"id":"demo","version":"1"}},"steps":[` + plain() + `]`), "plane.bundle.version"},
		{doc(`{"call":{"tool":"t","server":"s","args":{},"answer":` + resultAnswer + `,"decided":"none","trail":` + newTrail + `}}`), "steps[0].call.server"},
		{doc(call(`{}`, `{"kind":"result","codes":[],"text":"x"}`, noDecision, newTrail)), "steps[0].call.answer.text"},
		{doc(call(`{}`, resultAnswer, `{"verdict":"ALLOW","codes":[],"obligations":[],"rule":"r"}`, newTrail)), "steps[0].call.decided.rule"},
		{doc(call(`{}`, resultAnswer, `{"verdict":"ALLOW","codes":[],"obligations":[{"type":"emit_alert","params":{},"advisory":true,"x":1}]}`, newTrail)), "steps[0].call.decided.obligations[0].x"},
		{doc(call(`{}`, resultAnswer, noDecision, `{"request":"new","kinds":["ACTION_PROPOSED"],"closed":true}`)), "steps[0].call.trail.closed"},
		{doc(pending(), `{"approve":{"step":0,"approver":"a","when":"now"}}`), "steps[1].approve.when"},
		{doc(plain(), `{"pause":{"global":true,"principal":"p"}}`), "steps[1].pause.principal"},
		{doc(plain(), `{"pause":{"global":true}}`, `{"unpause":{"step":1,"all":true}}`), "steps[2].unpause.all"},
		{doc(`{"wait":{}}`), "steps[0].wait"},
	} {
		refused(t, c.raw, scenario.ErrUnknownMember, c.path)
	}
}

// TestNothingFollowsTheDocument: white space may, anything else may not.
func TestNothingFollowsTheDocument(t *testing.T) {
	accept(t, doc(plain())+" \n\t\r")
	refused(t, doc(plain())+" x", scenario.ErrTrailing, "")
	refused(t, doc(plain())+doc(plain()), scenario.ErrTrailing, "")
	refused(t, doc(plain())+"{", scenario.ErrTrailing, "")
}

// TestNotJSON: text a JSON reader cannot read is refused as such, never
// read as far as it goes.
func TestNotJSON(t *testing.T) {
	for _, raw := range []string{
		``, ` `, `{`, `{"kind":"agent-scenario/v1alpha1"`, `{"kind":"agent-scenario/v1alpha1",}`,
		`{"kind":'agent-scenario/v1alpha1'}`, `{"kind":"agent-scenario/v1alpha1" "about":"a"}`,
		`{"kind":"agent-scenario/v1alpha1","n":01}`, `{"kind":"agent-scenario/v1alpha1","n":1.}`,
		`{"kind":"agent-scenario/v1alpha1","n":.5}`, `{"kind":"agent-scenario/v1alpha1","n":1e}`,
		`{"kind":"agent-scenario/v1alpha1","n":+1}`, `{"kind":"agent-scenario/v1alpha1","n":tru}`,
		`{"kind":"agent-scenario/v1alpha1","s":"\x"}`, `{"kind":"agent-scenario/v1alpha1","s":"\u12"}`,
		"{\"kind\":\"agent-scenario/v1alpha1\",\"s\":\"a\nb\"}",
		`{"kind":"agent-scenario/v1alpha1","a":[1 2]}`,
	} {
		_, err := scenario.Read("a.json", []byte(raw))
		if !isClass(err, scenario.ErrSyntax) {
			t.Errorf("Read(%q) = %v, want ErrSyntax", raw, err)
		}
	}
}

// TestSizeBound: a document of exactly MaxBytes is read, one byte more is
// refused before it is parsed.
func TestSizeBound(t *testing.T) {
	raw := doc(plain())
	accept(t, raw+strings.Repeat(" ", 1<<20-len(raw)))
	refused(t, raw+strings.Repeat(" ", 1<<20-len(raw)+1), scenario.ErrTooLarge, "")
	if scenario.MaxBytes != 1<<20 {
		t.Errorf("MaxBytes = %d, want 1 MiB", scenario.MaxBytes)
	}
}

// TestDepthBound: the arguments sit five containers deep, so 59 nested
// arrays inside them reach the bound of 64 and 60 pass it.
func TestDepthBound(t *testing.T) {
	nest := func(n int) string { return `{"p":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}` }
	accept(t, doc(call(nest(59), resultAnswer, noDecision, newTrail)))
	r := refused(t, doc(call(nest(60), resultAnswer, noDecision, newTrail)), scenario.ErrTooDeep,
		"steps[0].call.args.p"+strings.Repeat("[0]", 59))
	if !strings.Contains(r.Detail, "65 containers, the bound is 64") {
		t.Errorf("Detail = %q", r.Detail)
	}
}

// TestFileNameIsTheID: lower-case letters, digits and hyphens, starting with
// a letter or digit, at most 64 before ".json".
func TestFileNameIsTheID(t *testing.T) {
	raw := doc(plain())
	for _, name := range []string{"a.json", "0.json", "allowed-read-2.json", strings.Repeat("a", 64) + ".json"} {
		s, err := scenario.Read(name, []byte(raw))
		if err != nil || s.ID != name {
			t.Errorf("Read(%q) = %+v, %v", name, s, err)
		}
	}
	for _, name := range []string{
		"Foo.json", "a.JSON", "-a.json", "a", "a.json.json", ".json", "a_b.json", "a b.json",
		"dir/a.json", "a.yaml", strings.Repeat("a", 65) + ".json", "a\x1b[31m.json", "é.json", "",
	} {
		refusedNamed(t, name, raw, scenario.ErrName, "")
	}
}

// TestQuoteIsBounded: a refusal quotes at most 64 escaped bytes of what it
// is about, and says when it cut.
func TestQuoteIsBounded(t *testing.T) {
	r := refused(t, `{"kind":"`+strings.Repeat(`\u0001`, 100)+`"}`, scenario.ErrKind, "kind")
	if r.Quote != strings.Repeat(`\x01`, 16) || !r.Cut {
		t.Errorf("Quote = %q (%d bytes), Cut = %v", r.Quote, len(r.Quote), r.Cut)
	}
	r = refused(t, top(`"about":"`+strings.Repeat("é", 101)+`","plane":{"mode":"ENFORCE","bundle":{"id":"demo"}},"steps":[`+plain()+`]`), scenario.ErrBound, "about")
	if r.Quote != "" {
		t.Errorf("a bound refusal quoted %q", r.Quote)
	}
	r = refused(t, `{"kind":"`+strings.Repeat("x", 63)+`é"}`, scenario.ErrKind, "kind")
	if r.Quote != strings.Repeat("x", 63) || !r.Cut {
		t.Errorf("Quote = %q, Cut = %v; want the 63 bytes before an escape that does not fit", r.Quote, r.Cut)
	}
}
