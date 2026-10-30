package ingest

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/guardana/control/internal/observe"
)

// TestAKindWithNoEntryIsRefused: a descriptor observe reads whose kind the
// registry lacks is refused, never read through another kind's checks.
func TestAKindWithNoEntryIsRefused(t *testing.T) {
	raw, err := os.ReadFile("otelgenai/testdata/descriptor.json")
	if err != nil {
		t.Fatal(err)
	}
	saved := kinds
	t.Cleanup(func() { kinds = saved })
	kinds = nil
	for _, k := range saved {
		if k.Name != observe.KindOTelGenAI {
			kinds = append(kinds, k)
		}
	}
	_, err = ReadDescriptor(raw)
	if !errors.Is(err, observe.ErrDescriptor) || !strings.Contains(err.Error(), `kind: "otel-genai-traces" has no importer in this build`) {
		t.Fatalf("ReadDescriptor = %v, want the kind refused", err)
	}
	if _, ok := Lookup(observe.KindOTelGenAI); ok {
		t.Fatal("Lookup found a kind the registry lacks")
	}
}
