//go:build unix

package notify

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestAStateWithoutItsMarkerIsRefusedUnlessInit: a directory never
// initialised is refused and left empty; init starts it; init again over it
// is refused; a marker this package did not write is damage.
func TestAStateWithoutItsMarkerIsRefusedUnlessInit(t *testing.T) {
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert))
	_, err := Run(t.Context(), r.options(false))
	wantIs(t, "a run on an empty directory", err, ErrNotInitialised)
	if entries, err := os.ReadDir(r.state); err != nil || len(entries) != 0 {
		t.Errorf("the refused run left %d entries, %v", len(entries), err)
	}
	if r.received(t) != "" {
		t.Error("the refused run delivered")
	}
	wantSummary(t, r.run(t, r.options(true)), 1, 0, 0, 0)
	_, err = Run(t.Context(), r.options(true))
	wantIs(t, "init over an initialised state", err, ErrInitialised)
	if got := r.delivered(t); got != keyA {
		t.Errorf("a refused init changed the delivered list to %q", got)
	}
	marker := filepath.Join(r.state, "notify-state")
	for _, body := range []string{"notify-state 2\n", "notify-state 1\n\n", ""} {
		mustDo(t, os.WriteFile(marker, []byte(body), 0o600))
		_, err = Run(t.Context(), r.options(false))
		wantIs(t, "a marker "+strconv.Quote(body), err, ErrState)
	}
}

// TestAnotherLogIsRefused: a state bound to one log's first line refuses a
// log that starts otherwise, delivering nothing; a state started on an empty
// log binds to the first line it later finds.
func TestAnotherLogIsRefused(t *testing.T) {
	r := newRig(t)
	wantSummary(t, r.run(t, r.options(true)), 0, 0, 0, 0)
	r.write(t, finding(idA, confirmed, alert))
	wantSummary(t, r.run(t, r.options(false)), 1, 0, 0, 0)

	other := newRig(t)
	other.write(t, finding(idB, confirmed, alert))
	o := r.options(false)
	o.FindingsDir = other.findings
	_, err := Run(t.Context(), o)
	wantIs(t, "another log", err, ErrOtherLog)
	if got := r.received(t); got != r.logLine(t, idA, confirmed) {
		t.Errorf("the refused run delivered: %q", got)
	}

	r.write(t, finding(idC, confirmed, alert))
	wantSummary(t, r.run(t, r.options(false)), 1, 1, 0, 0)

	digest := filepath.Join(r.state, "log-first-line.sha256")
	recorded, err := os.ReadFile(digest) //nolint:gosec // G304: the test's own file
	mustDo(t, err)
	for _, body := range []string{"zz\n", strings.ToUpper(string(recorded)), strings.TrimSuffix(string(recorded), "\n")} {
		mustDo(t, os.WriteFile(digest, []byte(body), 0o600))
		_, err = Run(t.Context(), r.options(false))
		wantIs(t, "a digest "+strconv.Quote(body), err, ErrState)
	}
}

// TestATornDeliveredTailIsCut: bytes after the last newline that a mark could
// have left are cut, and the keys before them still count; a whole line this
// package does not write, or a tail it could not have left, is damage.
func TestATornDeliveredTailIsCut(t *testing.T) {
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert))
	r.run(t, r.options(true))
	path := filepath.Join(r.state, "delivered.jsonl")
	appendTail(t, path, `"`+idB[:20])
	wantSummary(t, r.run(t, r.options(false)), 0, 1, 0, 0)
	if got := r.delivered(t); got != keyA {
		t.Errorf("delivered list after the cut = %q, want %q", got, keyA)
	}
	appendTail(t, path, `"`+strings.Repeat("a", 67))
	wantSummary(t, r.run(t, r.options(false)), 0, 1, 0, 0)
	if got := r.delivered(t); got != keyA {
		t.Errorf("delivered list after cutting the longest torn mark = %q, want %q", got, keyA)
	}
	for name, tail := range map[string]string{
		"an unquoted line":         idB + ":FINDING_VERDICT_CONFIRMED\n",
		"an unknown verdict":       `"` + idB + `:FINDING_VERDICT_MAYBE"` + "\n",
		"an unspecified one":       `"` + idB + `:FINDING_VERDICT_UNSPECIFIED"` + "\n",
		"a short id":               `"fnd-0123:FINDING_VERDICT_CONFIRMED"` + "\n",
		"upper-case hex":           `"` + strings.ToUpper(idB) + `:FINDING_VERDICT_CONFIRMED"` + "\n",
		"a carriage return":        `"` + idB + `:FINDING_VERDICT_CONFIRMED"` + "\r\n",
		"an empty line":            "\n",
		"a tail with a space":      `"fnd- `,
		"a tail that is no key":    "garbage",
		"a tail past any line":     `"` + idB + `:FINDING_VERDICT_INDETERMINATE"` + `"`,
		"a tail as long as a line": `"` + strings.Repeat("a", 68),
	} {
		mustDo(t, os.WriteFile(path, []byte(keyA+tail), 0o600))
		if _, err := Run(t.Context(), r.options(false)); !errors.Is(err, ErrState) {
			t.Errorf("%s: Run = %v, want ErrState", name, err)
		}
		if got := r.delivered(t); got != keyA+tail {
			t.Errorf("%s: a refused run changed the list to %q", name, got)
		}
	}
}

func appendTail(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: the test's own file
	mustDo(t, err)
	_, err = f.WriteString(s)
	mustDo(t, errors.Join(err, f.Close()))
}

// TestAStateOthersCanReachIsRefused: a directory or a state file the group
// or others may reach, or a link in a file's place, is refused before
// anything is delivered.
func TestAStateOthersCanReachIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(t *testing.T, state string)
		want   error
	}{
		"a group-writable directory":  {func(t *testing.T, s string) { chmod(t, s, 0o770) }, ErrStateMode},
		"a world-enterable directory": {func(t *testing.T, s string) { chmod(t, s, 0o701) }, ErrStateMode},
		"a group-readable list": {func(t *testing.T, s string) {
			chmod(t, filepath.Join(s, "delivered.jsonl"), 0o640)
		}, ErrStateMode},
		"a link for the list": {func(t *testing.T, s string) {
			list := filepath.Join(s, "delivered.jsonl")
			mustDo(t, os.Rename(list, list+".real"))
			mustDo(t, os.Symlink("delivered.jsonl.real", list))
		}, ErrState},
		"a link for the directory": {func(t *testing.T, s string) {
			mustDo(t, os.Rename(s, s+".real"))
			mustDo(t, os.Symlink(s+".real", s))
		}, ErrState},
		"a missing list": {func(t *testing.T, s string) {
			mustDo(t, os.Remove(filepath.Join(s, "delivered.jsonl")))
		}, ErrState},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.run(t, r.options(true))
			r.write(t, finding(idA, confirmed, alert))
			tc.change(t, r.state)
			_, err := Run(t.Context(), r.options(false))
			wantIs(t, name, err, tc.want)
			if r.received(t) != "" {
				t.Error("the refused run delivered")
			}
		})
	}
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	mustDo(t, os.Chmod(path, mode))
}

// TestTheDeliveredListIsBounded: a list of exactly MaxDeliveredBytes is read;
// one byte more is refused; and a list with no room left for one more mark
// refuses before the program runs, so nothing is delivered unmarked.
func TestTheDeliveredListIsBounded(t *testing.T) {
	if MaxDeliveredBytes != 64<<20 {
		t.Fatalf("MaxDeliveredBytes = %d; the bound this test writes is 64 MiB", MaxDeliveredBytes)
	}
	const bound = 64 << 20
	short := keyA
	long := `"` + idC + `:FINDING_VERDICT_INDETERMINATE"` + "\n"
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert))
	r.run(t, r.options(true))
	path := filepath.Join(r.state, "delivered.jsonl")

	mustDo(t, os.WriteFile(path, []byte(listOf(t, bound, short, long)), 0o600))
	wantSummary(t, r.run(t, r.options(false)), 0, 1, 0, 0)

	mustDo(t, os.WriteFile(path, []byte(listOf(t, bound+1, short, long)), 0o600))
	_, err := Run(t.Context(), r.options(false))
	wantIs(t, "a list one byte past the bound", err, ErrTooLarge)

	mustDo(t, os.WriteFile(path, []byte(listOf(t, bound, short, long)), 0o600))
	r.write(t, finding(idB, confirmed, alert))
	before := r.received(t)
	_, err = Run(t.Context(), r.options(false))
	wantIs(t, "a list with no room for a mark", err, ErrTooLarge)
	if got := r.received(t); got != before {
		t.Errorf("a run with no room delivered %q", strings.TrimPrefix(got, before))
	}
}

// listOf is short and long repeated to exactly size bytes.
func listOf(t *testing.T, size int, short, long string) string {
	t.Helper()
	for n := 0; n*len(long) <= size; n++ {
		if rest := size - n*len(long); rest%len(short) == 0 {
			return strings.Repeat(long, n) + strings.Repeat(short, rest/len(short))
		}
	}
	t.Fatalf("no list of %d bytes from lines of %d and %d", size, len(short), len(long))
	return ""
}
