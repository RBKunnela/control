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

// TestAnAdminReadsOfASignedLayoutOnlyWhatItsJudgeTakes: the operator's
// Lookup, Tree and Children of a signed layout refuse every record while no
// judge was given, and with one refuse a record of the tree the judge does
// not take, naming the record.
func TestAnAdminReadsOfASignedLayoutOnlyWhatItsJudgeTakes(t *testing.T) {
	_, a := newSigned(t)
	root, _ := openSignedRoot(t, a, "alice")
	child, _, err := a.OpenSigned(t.Context(), runs.OpenRequest{Who: alice, Parent: root.ID, TTL: time.Minute, Now: opened},
		testSigner("mallory"), takeKey("alice", "mallory"))
	if err != nil {
		t.Fatal(err)
	}
	reads := map[string]func() error{
		"Lookup":   func() error { _, err := a.Lookup(t.Context(), root.ID); return err },
		"Tree":     func() error { _, err := a.Tree(t.Context(), root.ID, 10); return err },
		"Children": func() error { _, err := a.Children(t.Context(), root.ID, 10); return err },
	}
	for name, read := range reads {
		if err := read(); !errors.Is(err, runs.ErrUnjudged) {
			t.Errorf("%s with no judge = %v, want ErrUnjudged", name, err)
		}
	}
	a.JudgeWith(alicesJudge)
	if got, err := a.Lookup(t.Context(), root.ID); err != nil || got.ID != root.ID || got.SecretSHA256 != "" {
		t.Errorf("Lookup of alice's root = %+v, %v", got, err)
	}
	for _, name := range []string{"Tree", "Children"} {
		if err := reads[name](); !errors.Is(err, runs.ErrUnauthenticated) || !strings.Contains(err.Error(), child.ID) {
			t.Errorf("%s over mallory's child = %v, want it refused naming %s", name, err, child.ID)
		}
	}
	a.JudgeWith(takeKey("alice", "mallory"))
	if tree, err := a.Tree(t.Context(), root.ID, 10); err != nil || len(tree) != 2 {
		t.Errorf("Tree once the judge takes both = %d runs, %v", len(tree), err)
	}
}

// TestAnAdminRefusesARecordCopiedFromAnotherLayout: a record signed for
// another layout's records/ and copied in is refused by the operator's
// Lookup, whatever the judge takes.
func TestAnAdminRefusesARecordCopiedFromAnotherLayout(t *testing.T) {
	dir, a := newSigned(t)
	a.JudgeWith(alicesJudge)
	other, b := newSigned(t)
	copied, _ := openSignedRoot(t, b, "alice")
	writeFile(t, recordPath(dir, copied.ID), readBytes(t, recordPath(other, copied.ID)))
	if _, err := a.Lookup(t.Context(), copied.ID); !errors.Is(err, runs.ErrOtherDirectory) {
		t.Errorf("Lookup of a record copied from another layout = %v, want ErrOtherDirectory", err)
	}
}

// TestALayoutsModeIsNeverSetThroughALink: a directory of the layout that a
// link took the place of is refused, and the link's target keeps its mode;
// the directory itself is set.
func TestALayoutsModeIsNeverSetThroughALink(t *testing.T) {
	dir := newDir(t)
	if err := os.Mkdir(filepath.Join(dir, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(dir, "records")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	top, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = top.Close() }()
	if err := runs.ChmodMade(top, "records", 0o750); !errors.Is(err, runs.ErrLayout) {
		t.Errorf("ChmodMade over a link = %v, want ErrLayout", err)
	}
	if info, err := os.Stat(filepath.Join(dir, "target")); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the link's target = %v, %v; want it left 0700", info, err)
	}
	if err := runs.ChmodMade(top, "state", 0o750); err != nil {
		t.Fatalf("ChmodMade = %v", err)
	}
	if info, err := os.Stat(filepath.Join(dir, "state")); err != nil || info.Mode().Perm() != 0o750 {
		t.Errorf("state = %v, %v; want 0750", info, err)
	}
}
