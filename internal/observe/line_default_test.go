package observe_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/guardana/control/internal/observe"
)

// TestAMemberAtItsDefaultIsRefused: the writer never spells a member at its
// default, so a member given at it is no line the writer wrote, and a member
// of a later minor given empty would read as a record of the minor it
// declares. The same lines without the member read.
func TestAMemberAtItsDefaultIsRefused(t *testing.T) {
	lines := fixtureLines(t)
	obs := strings.TrimSuffix(string(lines[0]), "\n")
	rep := strings.TrimSuffix(string(lines[1]), "\n")
	for _, l := range []string{obs, rep} {
		if _, err := observe.UnmarshalLine([]byte(l)); err != nil {
			t.Fatalf("the fixture: %v", err)
		}
	}
	for name, c := range map[string]struct{ line, old, with string }{
		"refused lines by reason, empty": {rep, `"otherResource":"1"`, `"otherResource":"1","refusedBy":{}`},
		"the same in its proto name":     {rep, `"otherResource":"1"`, `"otherResource":"1","refused_by":{}`},
		"callers dropped, zero":          {rep, `"otherResource":"1"`, `"otherResource":"1","callersDropped":"0"`},
		"runs in doubt, none":            {rep, `"inputBytes":"4096"`, `"inputBytes":"4096","doubtedRunIds":[]`},
		"every run doubted, false":       {rep, `"inputBytes":"4096"`, `"inputBytes":"4096","everyRunDoubted":false`},
		"a source's kind, empty":         {obs, `"sourceId":`, `"kind":"","sourceId":`},
		"a count of zero":                {rep, `"otherResource":"1"`, `"otherResource":"1","duplicate":"0"`},
		"an empty string":                {obs, `"status":"STATUS_OK"`, `"status":"STATUS_OK","errorType":""`},
	} {
		if !strings.Contains(c.line, c.old) {
			t.Fatalf("%s: the fixture lacks %q", name, c.old)
		}
		bad := strings.Replace(c.line, c.old, c.with, 1)
		if r, err := observe.UnmarshalLine([]byte(bad)); !errors.Is(err, observe.ErrLine) || r != nil {
			t.Errorf("%s: UnmarshalLine = %v, %v; want ErrLine", name, r, err)
		}
	}
}
