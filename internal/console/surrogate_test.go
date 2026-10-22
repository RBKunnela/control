package console

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
)

// reasonOf reads one record's reason straight from the store.
func (s *site) reasonOf(t *testing.T, approvalID string) string {
	t.Helper()
	l, err := s.store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range l.Entries {
		if e.Record.ApprovalID == approvalID {
			return e.Record.Approval.GetReason()
		}
	}
	t.Fatalf("the store holds no record %s", approvalID)
	return ""
}

// TestALoneSurrogateEscapeIsRefused: the bytes of a \uD800 escape are ASCII,
// so they pass the UTF-8 check, and the decoder would store U+FFFD in their
// place, a value nobody sent. Each escape that is not half of a valid pair is
// refused with 400 in an answer's reason and in a pause's, and nothing is
// written.
func TestALoneSurrogateEscapeIsRefused(t *testing.T) {
	dir, plane := newPlane(t)
	hold(t, plane, "SURR")
	file := newPauseFile(t)
	before, err := os.ReadFile(file) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t, dir, file)
	digest := s.digestOf(t, "SURR")
	for name, reason := range map[string]string{
		"a high half alone":             `ok\ud800`,
		"a low half alone":              `ok\udc00`,
		"a high half, then a letter":    `\ud83dx`,
		"a high half, then an escape":   `\ud83d\u0041`,
		"two high halves":               `\ud83d\ud83d`,
		"a high half, then U+E000":      `\ud83d\ue000`,
		"the halves in reverse order":   `\ude00\ud83d`,
		"the last high half, uppercase": `\uDBFF`,
		"a low half, then a low half":   `\udc00\udc00`,
		"the last low half, twice":      `\udfff\uDFFF`,
		"a high half, then no escape":   `\ud800Xudc00`,
		"a high half, then a dash":      `\udbff-udfff`,
	} {
		for _, w := range []struct{ path, body string }{
			{"/api/reject", `{"id":"SURR","reason":"` + reason + `","action_digest":"` + digest + `"}`},
			{"/api/approve", `{"id":"SURR","reason":"` + reason + `","action_digest":"` + digest + `"}`},
			{"/api/pause", `{"scope":{"kind":"global","provider":"","action":"","name":""},"reason":"` + reason + `"}`},
		} {
			if a := s.do(t, s.write(w.path, w.body)); a.status != http.StatusBadRequest {
				t.Errorf("%s at %s: answered %d %q, want 400", name, w.path, a.status, a.body)
			}
		}
	}
	if a := s.do(t, s.write("/api/reject", `{"id":"SURR","re\ud800":"","action_digest":"`+digest+`"}`)); a.status != http.StatusBadRequest {
		t.Errorf("a lone half in a member name: answered %d %q, want 400", a.status, a.body)
	}
	if got := s.stateOf(t, "SURR"); got != pending {
		t.Errorf("the record is %s after refused answers", got)
	}
	if after, err := os.ReadFile(file); err != nil || string(after) != string(before) { //nolint:gosec // G304: the test's own temporary directory
		t.Errorf("a refused pause changed the file: %q, %v", after, err)
	}
}

// TestAValidPairAndAnEscapedBackslashAreKept: a pair of halves is one
// character, and an escaped backslash before "ud800" is six characters of
// text, not an escape. Both are filed as sent.
func TestAValidPairAndAnEscapedBackslashAreKept(t *testing.T) {
	dir, plane := newPlane(t)
	hold(t, plane, "PAIR")
	hold(t, plane, "TEXT")
	s := serve(t, dir, "")
	for id, c := range map[string]struct{ sent, stored string }{
		"PAIR": {`ok \ud83d\ude00`, "ok \U0001F600"},
		"TEXT": {`ok \\ud800`, `ok \ud800`},
	} {
		body := `{"id":"` + id + `","reason":"` + c.sent + `","action_digest":"` + s.digestOf(t, id) + `"}`
		if a := s.do(t, s.write("/api/reject", body)); a.status != http.StatusOK {
			t.Fatalf("%s: answered %d %q", id, a.status, a.body)
		}
		if got := s.reasonOf(t, id); got != c.stored || strings.ContainsRune(got, '\uFFFD') {
			t.Errorf("%s: the stored reason is %q, want %q", id, got, c.stored)
		}
	}
}
