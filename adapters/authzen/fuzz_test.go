package authzen

import (
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/guardana/control/internal/core"
)

// FuzzAnswer reads arbitrary bodies and checks each state against a second,
// independent reading: an allow is exactly {decision: true, context?} with
// only listed members and no obligation, and nothing but a well-formed
// document in UTF-8 is ever read as a decision. The second reading decodes as
// leniently as the first, so the encoding is checked on its own.
func FuzzAnswer(f *testing.F) {
	for _, tc := range answerCases {
		f.Add([]byte(tc.body))
	}
	listed := map[string]bool{"reason_user": true}
	f.Fuzz(func(t *testing.T, body []byte) {
		got := readAnswer(body, listed)
		switch got {
		case core.ExternalAnswerRefused():
			return
		case core.ExternalAllowed(), core.ExternalDenied(), core.ExternalDeniedObligations():
		default:
			t.Fatalf("readAnswer(%q) = %v, a state no answer can be", body, got)
		}
		if !utf8.Valid(body) {
			t.Fatalf("readAnswer(%q) = %v, but the body is not UTF-8", body, got)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(body, &top); err != nil {
			t.Fatalf("readAnswer(%q) = %v, but the body is not one JSON object: %v", body, got, err)
		}
		decision := string(top["decision"])
		if got == core.ExternalDenied() {
			if decision != "false" {
				t.Fatalf("readAnswer(%q) = denied, but decision is %q", body, decision)
			}
			return
		}
		if decision != "true" {
			t.Fatalf("readAnswer(%q) = %v, but decision is %q", body, got, decision)
		}
		obligations := checkAllow(t, body, top, listed)
		if (got == core.ExternalDeniedObligations()) != (obligations > 0) {
			t.Fatalf("readAnswer(%q) = %v with %d obligations", body, got, obligations)
		}
	})
}

// checkAllow checks the shape of an answer that said true and returns how many
// obligations it carries.
func checkAllow(t *testing.T, body []byte, top map[string]json.RawMessage, listed map[string]bool) int {
	t.Helper()
	context := object(t, body, top)
	var obligations []json.RawMessage
	if o, ok := context["obligations"]; ok {
		if err := json.Unmarshal(o, &obligations); err != nil || obligations == nil {
			t.Fatalf("readAnswer(%q) read obligations that are not an array", body)
		}
	}
	if len(obligations) > 0 {
		return len(obligations)
	}
	for name := range top {
		if name != "decision" && name != "context" {
			t.Fatalf("readAnswer(%q) allowed with a top-level member %q", body, name)
		}
	}
	for name := range context {
		if name != "obligations" && !listed[name] {
			t.Fatalf("readAnswer(%q) allowed with an unlisted context member %q", body, name)
		}
	}
	return 0
}

// object is the answer's context, which has to be an object when present.
func object(t *testing.T, body []byte, top map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	raw, ok := top["context"]
	if !ok {
		return nil
	}
	var context map[string]json.RawMessage
	if err := json.Unmarshal(raw, &context); err != nil || context == nil {
		t.Fatalf("readAnswer(%q) read a context that is not an object", body)
	}
	return context
}
