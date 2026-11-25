//go:build unix

package pause

import (
	"os"
	"path/filepath"
	"testing"
)

// TestACopyReadThroughARetargetedLinkIsAnotherFile: the pause file's path
// runs through a link to directory A, and a file signed there is taken; a
// copy of it in directory B, read once the link names B, is refused before
// any judge sees it.
func TestACopyReadThroughARetargetedLinkIsAnotherFile(t *testing.T) {
	top := t.TempDir()
	for _, d := range []string{"A", "B"} {
		if err := os.MkdirAll(filepath.Join(top, d, "pause"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	current := filepath.Join(top, "current")
	if err := os.Symlink(filepath.Join(top, "A"), current); err != nil {
		t.Fatal(err)
	}
	p := &signedPlane{path: filepath.Join(current, "pause", "pause.json")}
	p.write(t, "alice", p.header(t, "alice", 1), paused)
	judged := 0
	counts := judgeFunc(func(f Signed) (SignedBy, error) { judged++; return takes(f) })
	if s := p.read(t, counts); s.State() != Paused || judged != 1 {
		t.Fatalf("the control, the file read where it was signed = %s, %q: %s, judged %d time(s); want paused", s.State(), s.Cause(), s.Detail(), judged)
	}
	raw, err := os.ReadFile(p.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(top, "B", "pause", "pause.json"), raw, 0o640); err != nil { //nolint:gosec // G306: the mode a signed write leaves
		t.Fatal(err)
	}
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(top, "B"), current); err != nil {
		t.Fatal(err)
	}
	wantUnknown(t, "a copy read through the retargeted link", p.read(t, counts), CauseOtherFile)
	if judged != 1 {
		t.Errorf("the copy was handed to the judge, which raises the floor: judged %d time(s), want 1", judged)
	}
}

// TestACopyReadBeforeTheLinkIsPutBackIsAnotherFile: a copy in directory B,
// read through the link while it names B, with the link put back on A
// before the read is held to its path: the body names the file the path
// leads to again, so only the directory the copy was read from tells it
// apart. It is refused before any judge sees it.
func TestACopyReadBeforeTheLinkIsPutBackIsAnotherFile(t *testing.T) {
	top, current, retarget := twoDirsBehindALink(t)
	p := &signedPlane{path: filepath.Join(current, "pause", "pause.json")}
	p.write(t, "alice", p.header(t, "alice", 1), paused)
	raw, err := os.ReadFile(p.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(top, "B", "pause", "pause.json"), raw, 0o640); err != nil { //nolint:gosec // G306: the mode a signed write leaves
		t.Fatal(err)
	}
	if err := os.WriteFile(p.path, []byte("not a pause file"), 0o640); err != nil { //nolint:gosec // G306: the mode a signed write leaves
		t.Fatal(err)
	}
	retarget("B")
	put := false
	dirSteps = func(at string) {
		if at == stepFileNamed && !put {
			put = true
			retarget("A")
		}
	}
	t.Cleanup(func() { dirSteps = nil })
	judged := 0
	counts := judgeFunc(func(f Signed) (SignedBy, error) { judged++; return takes(f) })
	s := p.read(t, counts)
	if !put {
		t.Fatal("the read never reached the step where the file is named")
	}
	wantUnknown(t, "a copy in B read before the link was put back on A", s, CauseOtherFile)
	if judged != 0 {
		t.Errorf("the copy was handed to the judge %d time(s), want none", judged)
	}
}

// twoDirsBehindALink makes directories A and B, each with a pause
// directory, and a link "current" naming A; retarget points it at another.
func twoDirsBehindALink(t *testing.T) (top, current string, retarget func(string)) {
	t.Helper()
	top = t.TempDir()
	for _, d := range []string{"A", "B"} {
		if err := os.MkdirAll(filepath.Join(top, d, "pause"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	current = filepath.Join(top, "current")
	if err := os.Symlink(filepath.Join(top, "A"), current); err != nil {
		t.Fatal(err)
	}
	retarget = func(to string) {
		if err := os.Remove(current); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(top, to), current); err != nil {
			t.Fatal(err)
		}
	}
	return top, current, retarget
}
