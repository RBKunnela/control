package attempts

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadManifest: no input panics the reader, and a value it parses reads
// back to the same canonical form from that form.
func FuzzReadManifest(f *testing.F) {
	f.Add([]byte(validManifest))
	if raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "vulnerable-mcp-agent", "attempts", "manifest.json")); err == nil {
		f.Add(raw)
	}
	f.Add([]byte(`{"kind": "attempt-manifest/v1alpha1", "about": "😀"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ReadManifest(raw)
		v, noted, fatal := parse(raw, MaxDepth)
		if fatal != nil || noted != nil {
			return
		}
		again, err := ParseValue([]byte(v.Canonical()))
		if err != nil || again.Canonical() != v.Canonical() {
			t.Fatalf("%q canonical %s reads back as %v, %v", raw, v.Canonical(), again, err)
		}
	})
}

// FuzzParseJournal: no input panics the journal's reader.
func FuzzParseJournal(f *testing.F) {
	f.Add([]byte("{\"call\":\"read_order\",\"args\":{\"id\":\"ord-1\"}}\n"))
	f.Add([]byte("{\"call\":\"a\"}\n{\"call\""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		j, err := ParseJournal(raw)
		if err == nil && j == nil {
			t.Fatal("no journal and no error")
		}
	})
}
