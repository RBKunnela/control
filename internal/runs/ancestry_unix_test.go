//go:build unix

package runs_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// TestADescendantOfARefusedChildIsRefused: the put-back attack one level
// down. The child refused under the put-back parent still signs as a parent,
// and its own child is refused too, naming the ancestor whose close was
// carried.
func TestADescendantOfARefusedChildIsRefused(t *testing.T) {
	dir, a := newSigned(t)
	parent, parentToken := openSignedRoot(t, a, "alice")
	parentOpen := readBytes(t, recordPath(dir, parent.ID))
	closeSigned(t, a, parent.ID, opened.Add(time.Minute))
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(2 * time.Minute)
	if _, err := p.Resolve(t.Context(), parentToken, alice, at); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve of the closed parent = %v, want closed", err)
	}
	writeFile(t, recordPath(dir, parent.ID), parentOpen)
	child, childToken := openSignedChild(t, a, parent.ID, at)
	_, err := p.Resolve(t.Context(), childToken, alice, at.Add(time.Minute))
	requireParentClosed(t, err)
	_, grandToken := openSignedChild(t, a, child.ID, at)
	_, err = p.Resolve(t.Context(), grandToken, alice, at.Add(time.Minute))
	requireParentClosed(t, err)
	if !strings.Contains(err.Error(), parent.ID) {
		t.Errorf("Resolve = %v, want it to name %s, whose close was carried", err, parent.ID)
	}
}

// TestAGrandchildOfACarriedChildCloseIsRefused: a child's close carried and
// its open record put back, a grandchild signed under it is refused, so the
// check is not of the root alone.
func TestAGrandchildOfACarriedChildCloseIsRefused(t *testing.T) {
	dir, a := newSigned(t)
	root, _ := openSignedRoot(t, a, "alice")
	child, childToken := openSignedChild(t, a, root.ID, opened)
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(time.Minute)
	if _, err := p.Resolve(t.Context(), childToken, alice, at); err != nil {
		t.Fatal(err)
	}
	childOpen := readBytes(t, recordPath(dir, child.ID))
	closeSigned(t, a, child.ID, at)
	if _, err := p.Resolve(t.Context(), childToken, alice, at); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve of the closed child = %v, want closed", err)
	}
	writeFile(t, recordPath(dir, child.ID), childOpen)
	_, grandToken := openSignedChild(t, a, child.ID, opened)
	_, err := p.Resolve(t.Context(), grandToken, alice, at.Add(time.Minute))
	requireParentClosed(t, err)
}

// TestAGrandchildOfAnOpenChildOfAClosedRootRuns: below a child the plane
// admitted before its root's close, a grandchild keeps running, though it
// was first called after the close.
func TestAGrandchildOfAnOpenChildOfAClosedRootRuns(t *testing.T) {
	dir, a := newSigned(t)
	root, rootToken := openSignedRoot(t, a, "alice")
	child, childToken := openSignedChild(t, a, root.ID, opened)
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(time.Minute)
	if _, err := p.Resolve(t.Context(), childToken, alice, at); err != nil {
		t.Fatal(err)
	}
	_, grandToken := openSignedChild(t, a, child.ID, opened)
	closeSigned(t, a, root.ID, at)
	if _, err := p.Resolve(t.Context(), rootToken, alice, at); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve of the closed root = %v, want closed", err)
	}
	if _, err := p.Resolve(t.Context(), grandToken, alice, at.Add(time.Minute)); err != nil {
		t.Fatalf("a grandchild of an open child: %v", err)
	}
}

// TestARefusedFirstCallLeavesNoSeen: a child's first call refused as expired
// or for another identity makes no first admission.
func TestARefusedFirstCallLeavesNoSeen(t *testing.T) {
	other := alice
	other.AgentID = "someone-else"
	for name, c := range map[string]struct {
		who  runs.Identity
		at   time.Time
		want runs.Cause
	}{
		"expired":          {alice, opened.Add(time.Hour), runs.CauseExpired},
		"another identity": {other, opened.Add(time.Minute), runs.CauseIdentity},
	} {
		t.Run(name, func(t *testing.T) {
			dir, a := newSigned(t)
			root, _ := openSignedRoot(t, a, "alice")
			child, childToken := openSignedChild(t, a, root.ID, opened)
			p := signedPlane(t, dir, alicesJudge)
			if _, err := p.Resolve(t.Context(), childToken, c.who, c.at); causeOf(t, err) != c.want {
				t.Fatalf("Resolve = %v, want %s", err, c.want)
			}
			requireSeen(t, dir, child.ID, false)
		})
	}
}

// spoilers make a marker that is no regular file of the plane's alone.
var spoilers = map[string]func(t *testing.T, path string){
	"a directory": func(t *testing.T, path string) {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	},
	"a link": func(t *testing.T, path string) {
		if err := os.Symlink(filepath.Join(filepath.Dir(path), "elsewhere"), path); err != nil {
			t.Fatal(err)
		}
	},
	"group-writable": func(t *testing.T, path string) {
		writeFile(t, path, nil)
		if err := os.Chmod(path, 0o620); err != nil { //nolint:gosec // G302: the mode under test
			t.Fatal(err)
		}
	},
}

// TestAnAncestorsCloseThePlaneCannotTrustRefuses: an ancestor's .closed that
// is no regular file of the plane's alone refuses an unseen descendant as
// unreadable, whether it is the parent's or the grandparent's.
func TestAnAncestorsCloseThePlaneCannotTrustRefuses(t *testing.T) {
	for name, spoil := range spoilers {
		for _, depth := range []string{"parent", "grandparent"} {
			t.Run(name+"/"+depth, func(t *testing.T) {
				dir, a := newSigned(t)
				root, _ := openSignedRoot(t, a, "alice")
				child, token := openSignedChild(t, a, root.ID, opened)
				if depth == "grandparent" {
					_, token = openSignedChild(t, a, child.ID, opened)
				}
				p := signedPlane(t, dir, alicesJudge)
				spoil(t, filepath.Join(dir, "state", root.ID+".closed"))
				run, err := p.Resolve(t.Context(), token, alice, opened.Add(time.Minute))
				if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, runs.ErrForeignFile) || run != (runs.Run{}) {
					t.Fatalf("Resolve = %+v, %v, want unreadable, ErrForeignFile and nothing admitted", run, err)
				}
			})
		}
	}
}

// TestAnAncestorRecordThePlaneCannotTakeRefuses: an unseen grandchild whose
// parent's record does not count is refused as unreadable.
func TestAnAncestorRecordThePlaneCannotTakeRefuses(t *testing.T) {
	dir, a := newSigned(t)
	root, _ := openSignedRoot(t, a, "alice")
	child, _ := openSignedChild(t, a, root.ID, opened)
	_, grandToken := openSignedChild(t, a, child.ID, opened)
	flat, fa, _ := setup(t)
	unsigned, _ := openRoot(t, fa)
	writeFile(t, recordPath(dir, child.ID), readBytes(t, filepath.Join(flat, unsigned.ID+".run.json")))
	_, err := signedPlane(t, dir, alicesJudge).Resolve(t.Context(), grandToken, alice, opened.Add(time.Minute))
	if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, runs.ErrUnsigned) {
		t.Fatalf("Resolve = %v, want unreadable, ErrUnsigned", err)
	}
}

// TestTheAncestryReadIsBounded: a first admission reads at most MaxAncestry
// ancestors. A run with that many is admitted; one with one more is refused
// until the plane admitted one of its ancestors.
func TestTheAncestryReadIsBounded(t *testing.T) {
	dir, a := newSigned(t)
	root, _ := openSignedRoot(t, a, "alice")
	id, tokens := root.ID, []string{""}
	for range runs.MaxAncestry + 1 {
		rec, token := openSignedChild(t, a, id, opened)
		id, tokens = rec.ID, append(tokens, token)
	}
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(time.Minute)
	deepest, last := tokens[runs.MaxAncestry+1], tokens[runs.MaxAncestry]
	_, err := p.Resolve(t.Context(), deepest, alice, at)
	if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, runs.ErrTreeBound) {
		t.Fatalf("Resolve with %d ancestors = %v, want unreadable, ErrTreeBound", runs.MaxAncestry+1, err)
	}
	if _, err := p.Resolve(t.Context(), last, alice, at); err != nil {
		t.Fatalf("Resolve with %d ancestors: %v", runs.MaxAncestry, err)
	}
	if _, err := p.Resolve(t.Context(), deepest, alice, at); err != nil {
		t.Fatalf("Resolve once its parent was admitted: %v", err)
	}
}
