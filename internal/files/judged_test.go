package files_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/guardana/control/internal/files"
)

func lstat(t *testing.T, path string) fs.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func readBody(t *testing.T, path string) string {
	t.Helper()
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

// TestReplaceJudgedReplacesOnlyTheFileJudged: the file judged is replaced
// whole with the mode asked; a file renamed over the name after the
// judgement is left with its bytes and refused; and the directory is left
// holding the one name either way.
func TestReplaceJudgedReplacesOnlyTheFileJudged(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	if err := files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, judged); err != nil {
		t.Fatalf("the control, the judged file still there: %v", err)
	}
	if got := readBody(t, out); got != "new" || mode(t, out) != 0o644 {
		t.Errorf("the judged file was replaced with %q, mode %04o; want new, 0644", got, mode(t, out))
	}

	judged = lstat(t, out)
	writeFile(t, filepath.Join(dir, "unrelated"), []byte("never judged"), 0o600)
	if err := os.Rename(filepath.Join(dir, "unrelated"), out); err != nil {
		t.Fatal(err)
	}
	err := files.ReplaceJudged(t.Context(), dir, "out", []byte("newer"), 0o644, judged)
	if !errors.Is(err, files.ErrNotJudged) {
		t.Errorf("a replace over a file renamed in after the judgement = %v, want ErrNotJudged", err)
	}
	if got := readBody(t, out); got != "never judged" {
		t.Errorf("the file renamed in now holds %q", got)
	}
	if got := entries(t, dir); len(got) != 1 {
		t.Errorf("the directory holds %v after the refusal, want the one name", got)
	}
}

// TestReplaceJudgedRefusesAFileGoneOrComeSinceTheJudgement: a file judged
// that is gone is not written again, and a name judged absent that a file
// took since is refused and left as it was; the control, a name still
// absent, is created.
func TestReplaceJudgedRefusesAFileGoneOrComeSinceTheJudgement(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	if err := os.Remove(out); err != nil {
		t.Fatal(err)
	}
	if err := files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, judged); !errors.Is(err, files.ErrNotJudged) {
		t.Errorf("a replace of a file gone since the judgement = %v, want ErrNotJudged", err)
	}
	if got := entries(t, dir); len(got) != 0 {
		t.Errorf("the directory holds %v, want nothing", got)
	}
	if err := files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, nil); err != nil {
		t.Fatalf("the control, a name judged absent and still absent: %v", err)
	}
	if got := readBody(t, out); got != "new" {
		t.Errorf("the name judged absent holds %q, want new", got)
	}
	if err := files.ReplaceJudged(t.Context(), dir, "out", []byte("newer"), 0o644, nil); !errors.Is(err, files.ErrNotJudged) {
		t.Errorf("a name judged absent that a file took since = %v, want ErrNotJudged", err)
	}
	if got := readBody(t, out); got != "new" {
		t.Errorf("the file that took the name now holds %q", got)
	}
}

// TestReplaceJudgedRefusesANameThatIsNotOneEntry: a name that reaches out of
// the directory, or names no entry of it, is refused and nothing outside is
// written; the control, one plain name, is replaced.
func TestReplaceJudgedRefusesANameThatIsNotOneEntry(t *testing.T) {
	top := t.TempDir()
	sub := filepath.Join(top, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(top, "victim")
	writeFile(t, victim, []byte("outside"), 0o600)
	writeFile(t, filepath.Join(sub, "out"), []byte("judged"), 0o600)
	root, err := os.OpenRoot(sub)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, name := range []string{"../victim", "./out", "x/../out", "", ".", ".."} {
		if err := files.ReplaceJudgedIn(t.Context(), root, name, []byte("new"), 0o644, lstat(t, victim)); !errors.Is(err, files.ErrNotOneName) {
			t.Errorf("ReplaceJudgedIn(%q) = %v, want ErrNotOneName", name, err)
		}
	}
	if got := readBody(t, victim); got != "outside" {
		t.Errorf("the file outside the directory now holds %q", got)
	}
	if err := files.ReplaceJudgedIn(t.Context(), root, "out", []byte("new"), 0o644, lstat(t, filepath.Join(sub, "out"))); err != nil {
		t.Fatalf("the control, one plain name: %v", err)
	}
}

// TestReplaceJudgedKeepsADirectoryAtTheName: a directory that took the
// judged file's name, whatever inode number it got, is kept whole and the
// replace refused with nothing written.
func TestReplaceJudgedKeepsADirectoryAtTheName(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	if err := os.Remove(out); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(out, "inside"), []byte("kept"), 0o600)
	if err := files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, judged); !errors.Is(err, files.ErrNotJudged) || !errors.Is(err, files.ErrNothingWritten) {
		t.Errorf("a replace over a directory at the name = %v, want ErrNotJudged with nothing written", err)
	}
	if info := lstat(t, out); !info.IsDir() {
		t.Errorf("the name holds %v after the refusal, want the directory", info.Mode())
	}
	if got := readBody(t, filepath.Join(out, "inside")); got != "kept" {
		t.Errorf("the directory's file holds %q", got)
	}
	if got := entries(t, dir); len(got) != 1 {
		t.Errorf("the directory holds %v, want the one name", got)
	}
}

// TestReplaceJudgedRefusesTheJudgedFileWrittenSince: the judged file itself,
// written in place since, is another file as it was judged and is kept.
func TestReplaceJudgedRefusesTheJudgedFileWrittenSince(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	if err := os.WriteFile(out, []byte("written since the judgement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, judged); !errors.Is(err, files.ErrNotJudged) {
		t.Errorf("a replace of the judged file written since = %v, want ErrNotJudged", err)
	}
	if got := readBody(t, out); got != "written since the judgement" {
		t.Errorf("the file written since now holds %q", got)
	}
}

// TestReplaceJudgedRefusesAFileThatReusedTheJudgedInode: a new file at the
// name whose inode number is the judged file's, freed since, is another file.
// It needs a file system that hands a freed number out again.
func TestReplaceJudgedRefusesAFileThatReusedTheJudgedInode(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	reused := ""
	for i := 0; i < 3000 && reused == ""; i++ {
		if err := os.Remove(out); err != nil {
			t.Fatal(err)
		}
		writeFile(t, out, []byte("a later file, never judged"), 0o600)
		if os.SameFile(lstat(t, out), judged) {
			reused = out
		}
	}
	if reused == "" {
		t.Skip("no inode number was reused here")
	}
	if err := files.ReplaceJudged(t.Context(), dir, "out", []byte("old"), 0o644, judged); !errors.Is(err, files.ErrNotJudged) {
		t.Errorf("a file of a reused inode number at the name = %v, want ErrNotJudged", err)
	}
	if got := readBody(t, out); got != "a later file, never judged" {
		t.Errorf("the later file now holds %q", got)
	}
}

// TestARefusedReplaceOfAnEarlierChangeIsNeverRead: a file that took the name
// before the replace began is refused before the new file is written, so a
// reader polling the name never reads the refused body.
func TestARefusedReplaceOfAnEarlierChangeIsNeverRead(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	writeFile(t, filepath.Join(dir, "other"), []byte("other"), 0o600)
	if err := os.Rename(filepath.Join(dir, "other"), out); err != nil {
		t.Fatal(err)
	}
	var seen atomic.Int64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if b, err := os.ReadFile(out); err == nil && string(b) == "refused" { //nolint:gosec // G304: the test's own file
				seen.Add(1)
			}
		}
	}()
	for range 500 {
		if err := files.ReplaceJudged(t.Context(), dir, "out", []byte("refused"), 0o644, judged); !errors.Is(err, files.ErrNotJudged) || !errors.Is(err, files.ErrNothingWritten) {
			t.Errorf("a replace over a file renamed in before it began = %v, want ErrNotJudged with nothing written", err)
			break
		}
	}
	close(stop)
	<-done
	if n := seen.Load(); n > 0 {
		t.Errorf("a reader read the refused body %d times", n)
	}
}
