package pause_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/guardana/control/internal/pause"
)

// FuzzParse: no input panics the reader; a document it accepts holds only
// entries that pass their own checks, renders without loss, and reads back as
// itself. A rendering may only be refused for its size, since escaping and
// indentation can carry a document at the bound past it.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		docJSON(),
		docJSON(entryJSON("a", globalScope, "r"), entryJSON("b", providerScope, "")),
		docJSON(entryJSON("c", toolScope, "<&>"), entryJSON("d", resourceScope, "é")),
		`{"schema_version":"2","entries":[],"entries":[]}`,
		`{"schema_version":"1","entries":[]}`,
		docJSON(entryJSON("r", runScope, ""), entryJSON("g", agentScope, ""), entryJSON("u", principalScope, "")),
		docJSON(entryJSON("a", `{"kind":"run","id":"run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provider":"orders"}`, "")),
		docJSON(entryJSON("a", `{"kind":"action","action":"resource","provider":"f","name":"x"}`, "")),
		docJSON(entryJSON("a", `{"kind":"action","action":"prompt","provider":"f","name":"x"}`, "")),
		docJSON(entryJSON("a", `{"kind":"action","action":"prompt","provider":"f"}`, "<\u2028>")),
		`{"schema_version":"2","entries":null}`,
		strings.Repeat(" ", 16) + docJSON() + " x",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		doc, err := pause.Parse(raw)
		if err != nil {
			if !errors.Is(err, pause.ErrMalformed) && !errors.Is(err, pause.ErrVersion) && !errors.Is(err, pause.ErrTooLarge) {
				t.Fatalf("a refusal outside the three sentinels: %v", err)
			}
			return
		}
		if err := doc.Check(); err != nil {
			t.Fatalf("an accepted document fails its own check: %v", err)
		}
		roundTrip(t, doc)
	})
}

// roundTrip holds an accepted document to its rendering.
func roundTrip(t *testing.T, doc pause.Document) {
	t.Helper()
	out, err := pause.Marshal(doc)
	if errors.Is(err, pause.ErrTooLarge) {
		return
	}
	if err != nil {
		t.Fatalf("an accepted document does not render: %v", err)
	}
	back, err := pause.Parse(out)
	if err != nil || len(back.Entries) != len(doc.Entries) {
		t.Fatalf("the rendering reads back as %+v, %v", back, err)
	}
	for i := range doc.Entries {
		a, b := doc.Entries[i], back.Entries[i]
		if a.ID != b.ID || a.Scope != b.Scope || a.Reason != b.Reason || !a.CreatedAt.Equal(b.CreatedAt) {
			t.Fatalf("entry %d read back as %+v, want %+v", i, b, a)
		}
	}
}
