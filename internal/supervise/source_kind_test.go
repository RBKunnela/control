package supervise_test

import (
	"errors"
	"testing"

	"github.com/guardana/control/internal/supervise"
)

// TestASourceOfAKindThatNamesNoRunIsRefused: an egress access log's
// connections name no run, so supervising against one would lend the run its
// liveness and the doubt of its every refusal while nothing of it could be
// taken. A source of no kind, or of a kind this build does not know, lands on
// the refused side; a source of the runtime's spans is read.
func TestASourceOfAKindThatNamesNoRunIsRefused(t *testing.T) {
	p := procWith(t)
	run := supervise.Run{ID: runID, Tenant: tenant}
	other := conforming()
	for i := range other {
		other[i].run = "run-ffffffffffffffffffffffffffffffff"
	}
	for name, x := range map[string]supervise.Export{"the run": export(conforming()...), "no event of the run": export(other...)} {
		for kind, want := range map[string]string{
			"egress-access-log": `supervise: input refused: source "s1" is of kind "egress-access-log", whose observations name no run; supervise reads none`,
			"":                  `supervise: input refused: source "s1" is of kind "", whose observations name no run; supervise reads none`,
			"otel-genai-logs":   `supervise: input refused: source "s1" is of kind "otel-genai-logs", whose observations name no run; supervise reads none`,
		} {
			src := source()
			src.Kind = kind
			_, err := supervise.Evaluate(supervise.Input{Procedure: p, Run: run, Exports: []supervise.Export{x}, Sources: []supervise.Source{source2(), src}})
			if !errors.Is(err, supervise.ErrInput) || err.Error() != want {
				t.Errorf("%s, kind %q: Evaluate = %v, want %q", name, kind, err, want)
			}
		}
		if _, err := supervise.Evaluate(supervise.Input{Procedure: p, Run: run, Exports: []supervise.Export{x}, Sources: []supervise.Source{source2(), source()}}); err != nil {
			t.Errorf("%s, sources of the runtime's spans: Evaluate = %v", name, err)
		}
	}
}
