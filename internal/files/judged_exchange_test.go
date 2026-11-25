package files_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/files"
)

// renamedIn puts body at name in dir by a rename, as another writer would.
func renamedIn(t *testing.T, dir, name, body string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, ".writer"), []byte(body), 0o600)
	if err := os.Rename(filepath.Join(dir, ".writer"), filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

// TestAFileRenamedInDuringTheReplaceIsPutBack: a file that takes the name
// after the replace judged it again, and before the exchange, comes out of
// the exchange and is put back; the replace is refused.
func TestAFileRenamedInDuringTheReplaceIsPutBack(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	files.BetweenExchanges(t, func(_ *os.Root, tmp string) {
		// The exchange already ran: what came out is at tmp. Make it the
		// other writer's file, as if that file had taken the name first.
		renamedIn(t, dir, tmp, "the other writer's")
	})
	err := files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, judged)
	if !errors.Is(err, files.ErrNotJudged) || errors.Is(err, files.ErrNothingWritten) || !strings.Contains(err.Error(), "until what stood there was put back") {
		t.Errorf("a replace whose exchange took out another file = %v, want ErrNotJudged saying it was put back, not ErrNothingWritten", err)
	}
	if got := readBody(t, out); got != "the other writer's" {
		t.Errorf("the name holds %q, want the other writer's file back", got)
	}
	if got := entries(t, dir); len(got) != 1 {
		t.Errorf("the directory holds %v, want the one name", got)
	}
}

// TestWhatChangedAgainWhileItWasPutBackStaysUnderTheTemporaryName: when the
// name changes again before the exchange back, the file that came out is put
// back and the newcomer is left under the temporary name the error names,
// never removed.
func TestWhatChangedAgainWhileItWasPutBackStaysUnderTheTemporaryName(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	var tmpName string
	files.BetweenExchanges(t, func(_ *os.Root, tmp string) {
		tmpName = tmp
		renamedIn(t, dir, tmp, "the other writer's")
		renamedIn(t, dir, "out", "a third writer's")
	})
	err := files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, judged)
	if !errors.Is(err, files.ErrNotJudged) || errors.Is(err, files.ErrNothingWritten) || !strings.Contains(err.Error(), "changed again") || !strings.Contains(err.Error(), tmpName) {
		t.Errorf("a name changed again before the exchange back = %v, want ErrNotJudged naming %s, not ErrNothingWritten", err, tmpName)
	}
	if got := readBody(t, out); got != "the other writer's" {
		t.Errorf("the name holds %q, want the other writer's file", got)
	}
	if got := readBody(t, filepath.Join(dir, tmpName)); got != "a third writer's" {
		t.Errorf("%s holds %q, want the third writer's file", tmpName, got)
	}
}

// TestAnExchangeBackThatFailsIsNotPutBack: when what came out cannot be
// exchanged back, the error says the new file holds the name and where what
// stood there went, and it is not ErrNotJudged, which callers read as the
// name holding what stood there.
func TestAnExchangeBackThatFailsIsNotPutBack(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	aside := filepath.Join(dir, "aside")
	files.BetweenExchanges(t, func(_ *os.Root, tmp string) {
		renamedIn(t, dir, tmp, "the other writer's")
		if err := os.Rename(filepath.Join(dir, tmp), aside); err != nil {
			t.Fatal(err)
		}
	})
	err := files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, judged)
	if !errors.Is(err, files.ErrNotPutBack) || errors.Is(err, files.ErrNotJudged) {
		t.Errorf("a replace whose exchange back failed = %v, want ErrNotPutBack alone", err)
	}
	if got := readBody(t, out); got != "new" {
		t.Errorf("the name holds %q; the error says the new file does", got)
	}
}
