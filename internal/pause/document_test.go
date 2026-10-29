package pause_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/pause"
)

// entryJSON is one entry as an operator's file spells it.
func entryJSON(id, scope, reason string) string {
	return fmt.Sprintf(`{"id":%q,"scope":%s,"created_at":"2026-09-24T10:00:00Z","reason":%q}`, id, scope, reason)
}

func docJSON(entries ...string) string {
	return `{"schema_version":"1","entries":[` + strings.Join(entries, ",") + `]}`
}

const (
	globalScope   = `{"kind":"global"}`
	providerScope = `{"kind":"provider","provider":"orders"}`
	toolScope     = `{"kind":"action","action":"tool","provider":"orders","name":"refund"}`
	resourceScope = `{"kind":"action","action":"resource","provider":"files"}`
)

func TestParseReadsEveryScope(t *testing.T) {
	doc, err := pause.Parse([]byte(docJSON(
		entryJSON("a", globalScope, "incident 7"),
		entryJSON("b", providerScope, ""),
		entryJSON("c", toolScope, "refunds misbehave"),
		entryJSON("d", resourceScope, "files"),
		entryJSON("e", `{"kind":"action","action":"prompt","provider":"orders"}`, ""),
	)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []pause.Entry{
		{ID: "a", Scope: pause.Scope{Kind: "global"}, Reason: "incident 7"},
		{ID: "b", Scope: pause.Scope{Kind: "provider", Provider: "orders"}},
		{ID: "c", Scope: pause.Scope{Kind: "action", Action: "tool", Provider: "orders", Name: "refund"}, Reason: "refunds misbehave"},
		{ID: "d", Scope: pause.Scope{Kind: "action", Action: "resource", Provider: "files"}, Reason: "files"},
		{ID: "e", Scope: pause.Scope{Kind: "action", Action: "prompt", Provider: "orders"}},
	}
	if len(doc.Entries) != len(want) {
		t.Fatalf("Parse read %d entries, want %d", len(doc.Entries), len(want))
	}
	created := time.Date(2026, time.September, 24, 10, 0, 0, 0, time.UTC)
	for i, got := range doc.Entries {
		if got.ID != want[i].ID || got.Scope != want[i].Scope || got.Reason != want[i].Reason || !got.CreatedAt.Equal(created) {
			t.Errorf("entry %d = %+v, want %+v created at %v", i, got, want[i], created)
		}
	}
	empty, err := pause.Parse([]byte(docJSON()))
	if err != nil || len(empty.Entries) != 0 {
		t.Errorf("an empty list: %+v, %v", empty, err)
	}
}

// TestParseRefusesTheWholeDocument: each input breaks exactly one rule of a
// document that is otherwise read, so each refusal is the one its case names.
func TestParseRefusesTheWholeDocument(t *testing.T) {
	ok := entryJSON("a", toolScope, "r")
	cases := []struct {
		name string
		doc  string
		want error
	}{
		{"not JSON", `{"schema_version":"1","entries":[`, pause.ErrMalformed},
		{"not an object", `[]`, pause.ErrMalformed},
		{"text after the document", docJSON(ok) + `{}`, pause.ErrMalformed},
		{"not UTF-8", docJSON(`{"id":"a","scope":{"kind":"global"},"created_at":"2026-09-24T10:00:00Z","reason":"` + "\xff" + `"}`), pause.ErrMalformed},
		{"no schema version", `{"entries":[]}`, pause.ErrMalformed},
		{"a version that is a number", `{"schema_version":1,"entries":[]}`, pause.ErrMalformed},
		{"an unknown version", `{"schema_version":"2","entries":[]}`, pause.ErrVersion},
		{"an unknown top member", `{"schema_version":"1","entries":[],"extra":1}`, pause.ErrMalformed},
		{"a member in another case", `{"schema_version":"1","Entries":[]}`, pause.ErrMalformed},
		{"a repeated top member", `{"schema_version":"1","entries":[],"entries":[]}`, pause.ErrMalformed},
		{"no entries", `{"schema_version":"1"}`, pause.ErrMalformed},
		{"entries null", `{"schema_version":"1","entries":null}`, pause.ErrMalformed},
		{"an unknown entry member", docJSON(`{"id":"a","scope":{"kind":"global"},"created_at":"2026-09-24T10:00:00Z","reason":"","note":""}`), pause.ErrMalformed},
		{"a repeated entry member", docJSON(`{"id":"a","id":"b","scope":{"kind":"global"},"created_at":"2026-09-24T10:00:00Z","reason":""}`), pause.ErrMalformed},
		{"no reason", docJSON(`{"id":"a","scope":{"kind":"global"},"created_at":"2026-09-24T10:00:00Z"}`), pause.ErrMalformed},
		{"a reason null", docJSON(`{"id":"a","scope":{"kind":"global"},"created_at":"2026-09-24T10:00:00Z","reason":null}`), pause.ErrMalformed},
		{"no created_at", docJSON(`{"id":"a","scope":{"kind":"global"},"reason":""}`), pause.ErrMalformed},
		{"a created_at that is no time", docJSON(`{"id":"a","scope":{"kind":"global"},"created_at":"yesterday","reason":""}`), pause.ErrMalformed},
		{"no id", docJSON(`{"scope":{"kind":"global"},"created_at":"2026-09-24T10:00:00Z","reason":""}`), pause.ErrMalformed},
		{"an empty id", docJSON(entryJSON("", globalScope, "")), pause.ErrMalformed},
		{"an id with a control character", docJSON(entryJSON("a\u0007", globalScope, "")), pause.ErrMalformed},
		{"a duplicate id", docJSON(ok, entryJSON("a", globalScope, "")), pause.ErrMalformed},
		{"a control character in a reason", docJSON(entryJSON("a", globalScope, "line\nbreak")), pause.ErrMalformed},
		{"a format character in a reason", docJSON(entryJSON("a", globalScope, "right\u202eto left")), pause.ErrMalformed},
		{"an unknown scope", docJSON(entryJSON("a", `{"kind":"agent","agent":"x"}`, "")), pause.ErrMalformed},
		{"a principal scope", docJSON(entryJSON("a", `{"kind":"principal"}`, "")), pause.ErrMalformed},
		{"an unknown scope member", docJSON(entryJSON("a", `{"kind":"global","tenant":"t"}`, "")), pause.ErrMalformed},
		{"a global scope with an empty member", docJSON(entryJSON("a", `{"kind":"global","provider":""}`, "")), pause.ErrMalformed},
		{"a global scope with a provider", docJSON(entryJSON("a", `{"kind":"global","provider":"orders"}`, "")), pause.ErrMalformed},
		{"a provider scope without its provider", docJSON(entryJSON("a", `{"kind":"provider"}`, "")), pause.ErrMalformed},
		{"a provider scope with an empty provider", docJSON(entryJSON("a", `{"kind":"provider","provider":""}`, "")), pause.ErrMalformed},
		{"a provider scope with a name", docJSON(entryJSON("a", `{"kind":"provider","provider":"orders","name":"refund"}`, "")), pause.ErrMalformed},
		{"an action scope without its kind of call", docJSON(entryJSON("a", `{"kind":"action","provider":"orders","name":"refund"}`, "")), pause.ErrMalformed},
		{"an action scope of an unknown kind of call", docJSON(entryJSON("a", `{"kind":"action","action":"sampling","provider":"orders","name":"x"}`, "")), pause.ErrMalformed},
		{"an action scope without its provider", docJSON(entryJSON("a", `{"kind":"action","action":"tool","name":"refund"}`, "")), pause.ErrMalformed},
		{"a tool scope without its name", docJSON(entryJSON("a", `{"kind":"action","action":"tool","provider":"orders"}`, "")), pause.ErrMalformed},
		{"a prompt scope with a name", docJSON(entryJSON("a", `{"kind":"action","action":"prompt","provider":"orders","name":"summary"}`, "")), pause.ErrMalformed},
		{"a resource scope with a name", docJSON(entryJSON("a", `{"kind":"action","action":"resource","provider":"files","name":"file:///etc/passwd"}`, "")), pause.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := pause.Parse([]byte(c.doc)); !errors.Is(err, c.want) {
				t.Errorf("Parse = %v, want %v", err, c.want)
			}
		})
	}
}

// TestParseHoldsEveryBound: at each bound the document is read, one past it
// the whole document is refused. The bounds are literals here, apart from the
// constants they pin.
func TestParseHoldsEveryBound(t *testing.T) {
	for _, c := range []struct {
		name   string
		build  func(n int) string
		at     int
		refuse error
	}{
		{"id bytes", func(n int) string { return docJSON(entryJSON(strings.Repeat("i", n), globalScope, "")) }, 64, pause.ErrMalformed},
		{"provider bytes", func(n int) string {
			return docJSON(entryJSON("a", `{"kind":"provider","provider":"`+strings.Repeat("p", n)+`"}`, ""))
		}, 256, pause.ErrMalformed},
		{"name bytes", func(n int) string {
			return docJSON(entryJSON("a", `{"kind":"action","action":"tool","provider":"orders","name":"`+strings.Repeat("n", n)+`"}`, ""))
		}, 256, pause.ErrMalformed},
		{"reason bytes", func(n int) string { return docJSON(entryJSON("a", globalScope, strings.Repeat("r", n))) }, 512, pause.ErrMalformed},
		{"entries", func(n int) string {
			entries := make([]string, n)
			for i := range entries {
				entries[i] = entryJSON(fmt.Sprintf("e%d", i), globalScope, "")
			}
			return docJSON(entries...)
		}, 64, pause.ErrMalformed},
		{"file bytes", func(n int) string {
			doc := docJSON(entryJSON("a", globalScope, ""))
			return doc + strings.Repeat(" ", n-len(doc))
		}, 163840, pause.ErrTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := pause.Parse([]byte(c.build(c.at))); err != nil {
				t.Errorf("at the bound %d: %v", c.at, err)
			}
			if _, err := pause.Parse([]byte(c.build(c.at + 1))); !errors.Is(err, c.refuse) {
				t.Errorf("one past the bound %d: %v, want %v", c.at, err, c.refuse)
			}
		})
	}
}

// TestAnErrorNeverEchoesAReason: a refusal may be printed or logged, and a
// reason is the operator's text.
func TestAnErrorNeverEchoesAReason(t *testing.T) {
	const secret = "the-operator-wrote-this"
	for _, doc := range []string{
		docJSON(entryJSON("a", globalScope, secret+"\u0001")),
		docJSON(entryJSON("a", globalScope, secret+strings.Repeat("x", 600))),
		docJSON(entryJSON("a", `{"kind":"nope"}`, secret)),
	} {
		_, err := pause.Parse([]byte(doc))
		if err == nil {
			t.Fatalf("Parse accepted %s", doc)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the refusal %q repeats the reason", err)
		}
	}
}

// TestScopeMatches: a scope matches when every field it names equals the
// call's, and a field the call does not carry matches, as does a kind the
// plane does not name, however close its spelling.
func TestScopeMatches(t *testing.T) {
	tool := pause.Scope{Kind: "action", Action: "tool", Provider: "orders", Name: "refund"}
	resource := pause.Scope{Kind: "action", Action: "resource", Provider: "files"}
	provider := pause.Scope{Kind: "provider", Provider: "orders"}
	prompt := pause.Scope{Kind: "action", Action: "prompt", Provider: "orders"}
	cases := []struct {
		scope                pause.Scope
		kind, provider, name string
		want                 bool
	}{
		{pause.Scope{Kind: "global"}, "tool", "any", "thing", true},
		{provider, "tool", "orders", "refund", true},
		{provider, "prompt", "orders", "x", true},
		{provider, "tool", "payments", "refund", false},
		{provider, "tool", "", "refund", true},
		{provider, "", "", "", true},
		{tool, "tool", "orders", "refund", true},
		{tool, "tool", "orders", "Refund", false},
		{tool, "tool", "orders", "refunds", false},
		{tool, "prompt", "orders", "refund", false},
		{tool, "tool", "payments", "refund", false},
		{tool, "tool", "", "refund", true},
		{tool, "", "orders", "refund", true},
		{tool, "tool", "orders", "", true},
		{resource, "resource", "files", "file:///a/../b", true},
		{resource, "resource", "other", "file:///a", false},
		{resource, "tool", "files", "read", false},
		{prompt, "prompt", "orders", "summary", true},
		{prompt, "prompt", "payments", "summary", false},
		{prompt, "tool", "orders", "summary", false},
		{pause.Scope{Kind: "tenant"}, "tool", "orders", "refund", true},
		{tool, "Tool", "orders", "refund", true},
		{tool, "tool ", "orders", "refund", true},
		{tool, "function", "orders", "refund", true},
		{tool, "function", "payments", "refund", false},
		{resource, "Resource", "files", "file:///a", true},
		{prompt, "prompts", "orders", "summary", true},
	}
	for _, c := range cases {
		if got := c.scope.Matches(c.kind, c.provider, c.name); got != c.want {
			t.Errorf("%+v.Matches(%q, %q, %q) = %v, want %v", c.scope, c.kind, c.provider, c.name, got, c.want)
		}
	}
}

// TestMarshalReadsBack: what the writer renders is what the reader reads,
// and a document the reader would refuse is never rendered.
func TestMarshalReadsBack(t *testing.T) {
	doc := pause.Document{Entries: []pause.Entry{
		{ID: "a", Scope: pause.Scope{Kind: "global"}, CreatedAt: time.Date(2026, 9, 24, 10, 0, 0, 5, time.FixedZone("x", 3600)), Reason: "<incident> & \"quotes\""},
		{ID: "b", Scope: pause.Scope{Kind: "action", Action: "tool", Provider: "orders", Name: "refund"}, CreatedAt: time.Date(2026, 9, 24, 11, 0, 0, 0, time.UTC)},
	}}
	out, err := pause.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := pause.Parse(out)
	if err != nil {
		t.Fatalf("Parse of the rendering: %v\n%s", err, out)
	}
	for i := range doc.Entries {
		got, want := back.Entries[i], doc.Entries[i]
		if got.ID != want.ID || got.Scope != want.Scope || got.Reason != want.Reason || !got.CreatedAt.Equal(want.CreatedAt) {
			t.Errorf("entry %d read back as %+v, want %+v", i, got, want)
		}
	}
	empty, err := pause.Marshal(pause.Document{})
	if err != nil || !strings.Contains(string(empty), `"entries": []`) {
		t.Errorf("an empty document renders as %s, %v; want an empty list", empty, err)
	}
	for _, bad := range []pause.Document{
		{Entries: []pause.Entry{{ID: "a", Scope: pause.Scope{Kind: "global"}}}},
		{Entries: []pause.Entry{{ID: "a", Scope: pause.Scope{Kind: "agent"}, CreatedAt: time.Unix(1, 0)}}},
		{Entries: []pause.Entry{
			{ID: "a", Scope: pause.Scope{Kind: "global"}, CreatedAt: time.Unix(1, 0)},
			{ID: "a", Scope: pause.Scope{Kind: "global"}, CreatedAt: time.Unix(1, 0)},
		}},
	} {
		if _, err := pause.Marshal(bad); !errors.Is(err, pause.ErrMalformed) {
			t.Errorf("Marshal(%+v) = %v, want ErrMalformed", bad, err)
		}
	}
}

// largest is entry i with every field at its bound, spelled with fill where
// an identifier takes it and with quotes where it does not.
func largest(i int, fill string) pause.Entry {
	ident := fill
	if len(fill) != 1 {
		ident = `"`
	}
	upTo := func(s string, n int) string { return strings.Repeat(s, n/len(s)) }
	return pause.Entry{
		ID: fmt.Sprintf("%02d", i) + upTo(ident, 62),
		Scope: pause.Scope{
			Kind: pause.ScopeAction, Action: pause.ActionTool,
			Provider: upTo(ident, 256), Name: upTo(ident, 256),
		},
		CreatedAt: time.Date(2026, time.September, 24, 10, 0, 0, 123456789, time.UTC),
		Reason:    upTo(fill, 512),
	}
}

// TestTheEntryBoundBitesBeforeTheByteBound: 64 entries with every field at its
// bound render within the 163840-byte bound whatever their text is, so the
// document is written and read back; a 65th is refused for the count, not for
// the size.
func TestTheEntryBoundBitesBeforeTheByteBound(t *testing.T) {
	for _, fill := range []string{`"`, `\`, "<", "&", "\u2028", "e"} {
		t.Run(fmt.Sprintf("%q", fill), func(t *testing.T) {
			var doc pause.Document
			for i := range 64 {
				doc.Entries = append(doc.Entries, largest(i, fill))
			}
			out, err := pause.Marshal(doc)
			if err != nil {
				t.Fatalf("Marshal of 64 entries at their bounds: %v", err)
			}
			if len(out) > 163840 {
				t.Errorf("the rendering is %d bytes, past the byte bound", len(out))
			}
			if back, err := pause.Parse(out); err != nil || len(back.Entries) != 64 {
				t.Errorf("the rendering reads back as %d entries, %v", len(back.Entries), err)
			}
			doc.Entries = append(doc.Entries, largest(64, fill))
			_, err = pause.Marshal(doc)
			if !errors.Is(err, pause.ErrMalformed) || errors.Is(err, pause.ErrTooLarge) || !strings.Contains(err.Error(), "65 entries") {
				t.Errorf("Marshal of 65 entries = %v; want the entry bound", err)
			}
		})
	}
}

// TestARefusedVersionIsQuotedShort: a version read from the file reaches a
// refusal, a log line and an answer, so what is quoted of it is bounded.
func TestARefusedVersionIsQuotedShort(t *testing.T) {
	long := strings.Repeat("v", 60<<10)
	_, err := pause.Parse([]byte(`{"schema_version":"` + long + `","entries":[]}`))
	if !errors.Is(err, pause.ErrVersion) {
		t.Fatalf("Parse = %v, want ErrVersion", err)
	}
	if len(err.Error()) > 512 {
		t.Errorf("the refusal quotes %d bytes", len(err.Error()))
	}
}

// TestMarshalEscapesOnlyWhatJSONNeeds: a reason with angle brackets and an
// ampersand is written as it is, so its bytes count once against the bound.
func TestMarshalEscapesOnlyWhatJSONNeeds(t *testing.T) {
	doc := pause.Document{Entries: []pause.Entry{
		{ID: "a", Scope: pause.Scope{Kind: "global"}, CreatedAt: time.Unix(1, 0), Reason: "<incident> & \"quotes\""},
	}}
	out, err := pause.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(out), `"reason": "<incident> & \"quotes\""`) {
		t.Errorf("the rendering escapes more than JSON needs:\n%s", out)
	}
}
