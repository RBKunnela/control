package reaction

import (
	"errors"
	"testing"
)

// TestAListSwappedForAnotherVersionNamesOnlyTheWaysOutItHas: a list put in
// place of the accepted one is told to put that one back either way; only a
// 2.0 list in place of a 3.0 one is also told to carry, since a carry takes
// no other version.
func TestAListSwappedForAnotherVersionNamesOnlyTheWaysOutItHas(t *testing.T) {
	for _, c := range []struct {
		got, want, says string
		is              error
	}{
		{"2.0", "3.0", "reaction: a 2.0 stop list in place of the accepted 3.0 one is not served: put the accepted list back, " +
			"or carry this one into 3.0 with stops init --carry", ErrListUpgrade},
		{"3.0", "1.0", "reaction: a 3.0 stop list in place of the accepted 1.0 one is not served: put the accepted list back", ErrListVersion},
		{"1.0", "3.0", "reaction: a 1.0 stop list in place of the accepted 3.0 one is not served: put the accepted list back", ErrListVersion},
	} {
		err := versionSwap{got: c.got, want: c.want}
		if err.Error() != c.says || !errors.Is(err, ErrListHeader) || !errors.Is(err, c.is) {
			t.Errorf("%s in place of %s: %q, want %q, a changed header and %v", c.got, c.want, err.Error(), c.says, c.is)
		}
	}
}
