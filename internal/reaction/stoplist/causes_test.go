package stoplist

import (
	"slices"
	"testing"

	"github.com/guardana/control/internal/reaction"
)

// TestCausesNameEachCauseOnce: a counter keyed by cause would add two
// causes spelled alike into one, so every cause a snapshot can report is
// listed, once, the file's and the judge's.
func TestCausesNameEachCauseOnce(t *testing.T) {
	all := Causes()
	seen := map[reaction.Cause]bool{}
	for _, c := range all {
		if seen[c] {
			t.Errorf("cause %q listed twice", c)
		}
		seen[c] = true
	}
	for _, want := range []reaction.Cause{
		"missing", "unreadable", "a link", "writable by others", "owned by another account", "too large", "shrunk", "never read",
		"owned by the plane's account", "below its floor", "forked at its floor", "a broken chain", "floor unusable",
		"operator ports unavailable",
	} {
		if !slices.Contains(all, want) {
			t.Errorf("Causes lacks %q", want)
		}
	}
	if len(all) != 10+len(reaction.Causes()) {
		t.Errorf("Causes holds %d, want the 10 of the file and the judge's %d", len(all), len(reaction.Causes()))
	}
}
