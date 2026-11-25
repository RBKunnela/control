package files_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/guardana/control/internal/files"
)

// TestWritersOfOneJudgedFileLeaveOneBodyAtTheName: writers that all judged
// one file replace it at once. In every round exactly one answers nil and
// the name holds its body; every other is refused as not the file judged,
// none of their bodies is at the name, and no temporary file is left.
func TestWritersOfOneJudgedFileLeaveOneBodyAtTheName(t *testing.T) {
	const rounds = 200
	for _, n := range []int{3, 6} {
		broken := 0
		for r := range rounds {
			dir := t.TempDir()
			out := filepath.Join(dir, "out")
			writeFile(t, out, []byte("judged"), 0o600)
			judged := lstat(t, out)
			errs := make([]error, n)
			var start, wg sync.WaitGroup
			start.Add(1)
			for i := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					start.Wait()
					errs[i] = files.ReplaceJudged(t.Context(), dir, "out", []byte(fmt.Sprintf("body-%d", i)), 0o644, judged)
				}()
			}
			start.Done()
			wg.Wait()
			if why := oneBodyAtTheName(t, dir, readBody(t, out), errs); why != "" {
				broken++
				if broken <= 3 {
					t.Errorf("%d writers, round %d: %s", n, r, why)
				}
			}
		}
		if broken > 0 {
			t.Errorf("%d writers: %d of %d rounds broke the contract", n, broken, rounds)
		}
	}
}

// oneBodyAtTheName says what a round of writers of body-<i> left wrong, or
// "" when exactly one answered nil, its body is at the name, every other was
// refused as not the file judged, and no temporary file is left.
func oneBodyAtTheName(t *testing.T, dir, got string, errs []error) string {
	t.Helper()
	won := -1
	for i, err := range errs {
		switch {
		case err == nil && won >= 0:
			return fmt.Sprintf("body-%d and body-%d both answered nil", won, i)
		case err == nil:
			won = i
		case !errors.Is(err, files.ErrNotJudged):
			return fmt.Sprintf("body-%d: %v, want ErrNotJudged", i, err)
		case got == fmt.Sprintf("body-%d", i):
			return fmt.Sprintf("body-%d was refused (%v) but the name holds it", i, err)
		}
	}
	if won < 0 {
		return fmt.Sprintf("no writer answered nil; the name holds %q", got)
	}
	if want := fmt.Sprintf("body-%d", won); got != want {
		return fmt.Sprintf("%s answered nil, but the name holds %q", want, got)
	}
	for _, name := range entries(t, dir) {
		if files.IsTemp(name) {
			return fmt.Sprintf("a temporary file is left: %s", name)
		}
	}
	return ""
}

// TestAReplaceAnswersNilOnlyWhileTheNameHoldsItsNewFile: a file renamed over
// the name once the new file took it, by a writer that takes no lock, makes
// the replace fail with ErrNotKept, which is not a refusal that wrote
// nothing; the judged file that came out is removed all the same.
func TestAReplaceAnswersNilOnlyWhileTheNameHoldsItsNewFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	files.BetweenExchanges(t, func(_ *os.Root, _ string) {
		renamedIn(t, dir, "out", "the other writer's")
	})
	err := files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, judged)
	if !errors.Is(err, files.ErrNotKept) || errors.Is(err, files.ErrNothingWritten) {
		t.Errorf("a replace whose new file lost the name = %v, want ErrNotKept, not ErrNothingWritten", err)
	}
	if got := readBody(t, out); got != "the other writer's" {
		t.Errorf("the name holds %q, want the other writer's file", got)
	}
	if got := entries(t, dir); len(got) != 1 {
		t.Errorf("the directory holds %v, want the one name", got)
	}
}

// TestReplaceJudgedRefusesAnEntryJudgedThatIsNotARegularFile: a link judged
// as a link is refused, since no lock holds a link itself; the link and the
// file it names are left as they are.
func TestReplaceJudgedRefusesAnEntryJudgedThatIsNotARegularFile(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	writeFile(t, outside, []byte("not yours"), 0o600)
	out := filepath.Join(dir, "out")
	if err := os.Symlink(outside, out); err != nil {
		t.Fatal(err)
	}
	for _, judged := range []struct {
		what string
		path string
	}{{"the file it names", outside}, {"a link", out}} {
		err := files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, lstat(t, judged.path))
		if !errors.Is(err, files.ErrNotJudged) && !errors.Is(err, files.ErrNotRegular) {
			t.Errorf("a link judged as %s = %v, want a refusal", judged.what, err)
		}
	}
	if lstat(t, out).Mode()&os.ModeSymlink == 0 {
		t.Error("the link at the name was replaced")
	}
	if got := readBody(t, outside); got != "not yours" {
		t.Errorf("the link's target now holds %q", got)
	}
	if got := entries(t, dir); len(got) != 1 {
		t.Errorf("the directory holds %v, want the one name", got)
	}
}
