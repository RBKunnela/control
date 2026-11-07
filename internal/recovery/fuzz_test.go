package recovery_test

import (
	"testing"

	"github.com/guardana/control/internal/recovery"
)

// FuzzParseManifest: no input panics, and a manifest read renders to one
// that reads back to the same rendering.
func FuzzParseManifest(f *testing.F) {
	f.Add([]byte(manifestWith("0.1", goodEntry)))
	f.Add([]byte(manifestWith("0.1", "")))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := recovery.ParseManifest(raw)
		if err != nil {
			return
		}
		out, err := recovery.MarshalManifest(m)
		if err != nil {
			t.Fatalf("a manifest read does not render: %v", err)
		}
		back, err := recovery.ParseManifest(out)
		if err != nil {
			t.Fatalf("a rendering does not read back: %v", err)
		}
		again, err := recovery.MarshalManifest(back)
		if err != nil || string(again) != string(out) {
			t.Fatalf("the rendering moved: %v", err)
		}
	})
}
