package authzen

import (
	"testing"
	"time"

	"github.com/guardana/control/internal/core"
)

// informational is the context member the answer cases list as harmless on
// an allow.
var informational = []string{"reason_user"}

// answerCases are bodies of a 200 that is otherwise conformant, and the state
// each one is. They seed FuzzAnswer too.
var answerCases = []struct {
	name string
	body string
	want core.External
}{
	{"allow", `{"decision":true}`, core.ExternalAllowed()},
	{"allow with an empty context", `{"decision":true,"context":{}}`, core.ExternalAllowed()},
	{"allow with white space", " \n{ \"decision\" : true }\n ", core.ExternalAllowed()},
	{"allow, name escaped", `{"d\u0065cision":true}`, core.ExternalAllowed()},
	{"deny", `{"decision":false}`, core.ExternalDenied()},
	{"a duplicate decision, deny first", `{"decision":false,"decision":true}`, core.ExternalAnswerRefused()},
	{"a duplicate decision, both true", `{"decision":true,"decision":true}`, core.ExternalAnswerRefused()},
	{"a duplicate decision, escaped", `{"decision":false,"d\u0065cision":true}`, core.ExternalAnswerRefused()},
	{"decision a string", `{"decision":"true"}`, core.ExternalAnswerRefused()},
	{"decision a number", `{"decision":1}`, core.ExternalAnswerRefused()},
	{"decision null", `{"decision":null}`, core.ExternalAnswerRefused()},
	{"decision capitalised", `{"Decision":true}`, core.ExternalAnswerRefused()},
	{"decision capitalised beside a deny", `{"decision":false,"Decision":true}`, core.ExternalDenied()},
	{"no decision", `{}`, core.ExternalAnswerRefused()},
	{"only a context", `{"context":{}}`, core.ExternalAnswerRefused()},
	{"a trailing document", `{"decision":true}{"decision":true}`, core.ExternalAnswerRefused()},
	{"a trailing document after a deny", `{"decision":false}{"decision":false}`, core.ExternalAnswerRefused()},
	{"trailing bytes", `{"decision":false} x`, core.ExternalAnswerRefused()},
	{"truncated", `{"decision":true`, core.ExternalAnswerRefused()},
	{"empty", ``, core.ExternalAnswerRefused()},
	{"an array", `[{"decision":true}]`, core.ExternalAnswerRefused()},
	{"a bare true", `true`, core.ExternalAnswerRefused()},
	{"an unknown member on true", `{"decision":true,"reason":"ok"}`, core.ExternalAnswerRefused()},
	{"an unknown member beside a context on true", `{"decision":true,"context":{},"reason":"ok"}`, core.ExternalAnswerRefused()},
	{"an unknown member on false", `{"decision":false,"reason":"no"}`, core.ExternalDenied()},
	{"an unknown member on false that does not parse", `{"decision":false,"reason":tru}`, core.ExternalAnswerRefused()},
	{"an unlisted context member on true", `{"decision":true,"context":{"advice":"step up"}}`, core.ExternalAnswerRefused()},
	{"a listed context member on true", `{"decision":true,"context":{"reason_user":{"en":"fine"}}}`, core.ExternalAllowed()},
	{"a listed context member twice", `{"decision":true,"context":{"reason_user":1,"reason_user":2}}`, core.ExternalAnswerRefused()},
	{"a listed member at the top level", `{"decision":true,"reason_user":"fine"}`, core.ExternalAnswerRefused()},
	{"non-empty obligations", `{"decision":true,"context":{"obligations":[{"id":"notify"}]}}`, core.ExternalDeniedObligations()},
	{"non-empty obligations beside an unlisted member", `{"decision":true,"context":{"obligations":[1],"advice":"x"}}`, core.ExternalDeniedObligations()},
	{"empty obligations", `{"decision":true,"context":{"obligations":[]}}`, core.ExternalAllowed()},
	{"empty obligations with white space", `{"decision":true,"context":{"obligations":[ ]}}`, core.ExternalAllowed()},
	{"obligations twice", `{"decision":true,"context":{"obligations":[],"obligations":[{"id":"x"}]}}`, core.ExternalAnswerRefused()},
	{"obligations null", `{"decision":true,"context":{"obligations":null}}`, core.ExternalAnswerRefused()},
	{"obligations an object", `{"decision":true,"context":{"obligations":{}}}`, core.ExternalAnswerRefused()},
	{"obligations on a deny", `{"decision":false,"context":{"obligations":[{"id":"notify"}]}}`, core.ExternalDenied()},
	{"context null on true", `{"decision":true,"context":null}`, core.ExternalAnswerRefused()},
	{"context an array on true", `{"decision":true,"context":[]}`, core.ExternalAnswerRefused()},
	{"context twice on true", `{"decision":true,"context":{},"context":{}}`, core.ExternalAnswerRefused()},
	{"context null on false", `{"decision":false,"context":null}`, core.ExternalDenied()},
	{"obligations at the top level", `{"decision":true,"obligations":[{"id":"x"}]}`, core.ExternalAnswerRefused()},
	{"a byte that is not UTF-8 in a listed member on true", "{\"decision\":true,\"context\":{\"reason_user\":\"fine\xff\"}}", core.ExternalAnswerRefused()},
	{"a byte that is not UTF-8 in a listed member's name on true", "{\"decision\":true,\"context\":{\"reason_user\xff\":1}}", core.ExternalAnswerRefused()},
	{"a byte that is not UTF-8 in an unknown member on false", "{\"decision\":false,\"reason\":\"no\xff\"}", core.ExternalAnswerRefused()},
	{"a lone surrogate's bytes on true", "{\"decision\":true,\"context\":{\"reason_user\":\"\xed\xa0\x80\"}}", core.ExternalAnswerRefused()},
}

// TestAnswers runs every answer case through the decision point, so each one
// is read the way Ask reads it.
func TestAnswers(t *testing.T) {
	for _, tc := range answerCases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPDP(t, answer(tc.body))
			opts := options(p)
			opts.Informational = informational
			got := client(t, opts).Ask(within(t, 10*time.Second), envelope())
			if got != tc.want {
				t.Errorf("Ask with %q = %v, want %v", tc.body, got, tc.want)
			}
			if p.hits() != 1 {
				t.Errorf("the decision point was asked %d times, want 1", p.hits())
			}
		})
	}
}

// TestInformationalIsPerClient: with nothing listed, which is the default, a
// context member on an allow is refused.
func TestInformationalIsPerClient(t *testing.T) {
	p := newPDP(t, answer(`{"decision":true,"context":{"reason_user":{"en":"fine"}}}`))
	if got := client(t, options(p)).Ask(within(t, 10*time.Second), envelope()); got != core.ExternalAnswerRefused() {
		t.Errorf("an unlisted member with nothing listed = %v, want answer refused", got)
	}
}
