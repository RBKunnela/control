package runs_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

var bob = runs.Identity{ProjectID: "project-a", TenantID: "tenant-b", PrincipalType: "user", PrincipalID: "bob", AgentID: "agent-2"}

// plant writes a record for id straight into dir, as a writer of the
// directory could, without the operator's lock or its checks of a parent.
func plant(t *testing.T, dir, id, tenant, root, parent string) {
	t.Helper()
	body := fmt.Sprintf(`{"schema_version":"2.0","run_id":%q,"project_id":"project-a","tenant_id":%q,"principal_type":"user",`+
		`"principal_id":"p","agent_id":"a","root":%q,"parent":%q,"opened_at":"2026-03-01T12:00:00Z",`+
		`"expires_at":"2026-03-01T13:00:00Z","closed_at":"","secret_sha256":%q}`,
		id, tenant, root, parent, strings.Repeat("0", 64))
	writeFile(t, filepath.Join(dir, id+".run.json"), []byte(body))
}

func plantedID(i int) string { return fmt.Sprintf("run-%032x", i+1) }

// ids is the run id of each record, in order.
func ids(recs []runs.Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.ID)
	}
	return out
}

// family is a root with two children, one of which has a child, and another
// root of the same tenant with a child of its own.
type family struct {
	root, child, grandchild, sibling, otherRoot, otherChild string
}

func openFamily(t *testing.T, a *runs.Admin) family {
	t.Helper()
	var f family
	rec, _ := openRoot(t, a)
	f.root = rec.ID
	rec, _ = openUnder(t, a, f.root, alice)
	f.child = rec.ID
	rec, _ = openUnder(t, a, f.child, alice)
	f.grandchild = rec.ID
	rec, _ = openUnder(t, a, f.root, alice)
	f.sibling = rec.ID
	rec, _ = openRoot(t, a)
	f.otherRoot = rec.ID
	rec, _ = openUnder(t, a, f.otherRoot, alice)
	f.otherChild = rec.ID
	return f
}

// TestTreeIsTheRootAndEveryRunUnderIt: the root first, then each run after
// its parent, the runs of another root left out, and no secret's hash.
func TestTreeIsTheRootAndEveryRunUnderIt(t *testing.T) {
	_, a, _ := setup(t)
	f := openFamily(t, a)
	tree, err := a.Tree(t.Context(), f.root, 4)
	if err != nil {
		t.Fatalf("Tree: %v", err)
	}
	got := ids(tree)
	want := []string{f.root, min(f.child, f.sibling), max(f.child, f.sibling), f.grandchild}
	if !slices.Equal(got, want) {
		t.Fatalf("Tree = %v, want %v: the root, its children by id, then the grandchild", got, want)
	}
	parents := map[string]string{f.root: "", f.child: f.root, f.sibling: f.root, f.grandchild: f.child}
	expires := time.Date(2026, time.March, 1, 13, 0, 0, 0, time.UTC)
	for _, r := range tree {
		if r.SecretSHA256 != "" || r.Root != f.root || r.Parent != parents[r.ID] || r.Who != alice ||
			!r.OpenedAt.Equal(opened) || !r.ExpiresAt.Equal(expires) {
			t.Errorf("member %+v", r)
		}
	}
}

// TestTreeIsBoundedByItsOwnSize: a tree of four is read at a bound of four
// and refused at three, and 1001 runs of another tenant beside it bound
// nothing.
func TestTreeIsBoundedByItsOwnSize(t *testing.T) {
	dir, a, _ := setup(t)
	f := openFamily(t, a)
	for i := range 1001 {
		id := plantedID(i)
		plant(t, dir, id, bob.TenantID, id, "")
	}
	if l, err := a.List(t.Context(), 1000); err != nil || l.Complete {
		t.Fatalf("List at 1000: complete %t, %v; want a listing the bound stopped", l.Complete, err)
	}
	if tree, err := a.Tree(t.Context(), f.root, 4); err != nil || len(tree) != 4 {
		t.Fatalf("Tree at its own size: %v, %v", ids(tree), err)
	}
	if tree, err := a.Tree(t.Context(), f.root, 3); !errors.Is(err, runs.ErrTreeBound) || tree != nil {
		t.Fatalf("Tree one past its bound: %v, %v; want ErrTreeBound", ids(tree), err)
	}
	for _, bound := range []int{0, -1} {
		if _, err := a.Tree(t.Context(), f.root, bound); !errors.Is(err, runs.ErrBound) {
			t.Fatalf("bound %d: %v", bound, err)
		}
	}
}

// TestTreeRefusesWhatItCannotVouchFor: a member of another tenant or
// project, a member whose parent is in no tree, two members each the other's
// parent, a member whose parent is another root's run, a record of another
// tree that does not decode, a child asked for as a root and a run no record
// names.
func TestTreeRefusesWhatItCannotVouchFor(t *testing.T) {
	for name, c := range map[string]struct {
		edit func(t *testing.T, dir string, f family)
		root func(f family) string
		want error
	}{
		"a member of another tenant": {func(t *testing.T, dir string, f family) {
			rewrite(t, dir, f.grandchild+".run.json", func(m map[string]json.RawMessage) { m["tenant_id"] = json.RawMessage(`"tenant-b"`) })
		}, nil, runs.ErrTreeTenant},
		"a member of another project": {func(t *testing.T, dir string, f family) {
			rewrite(t, dir, f.grandchild+".run.json", func(m map[string]json.RawMessage) { m["project_id"] = json.RawMessage(`"project-b"`) })
		}, nil, runs.ErrTreeProject},
		"a parent in no tree": {func(t *testing.T, dir string, f family) {
			plant(t, dir, plantedID(7), alice.TenantID, f.root, plantedID(8))
		}, nil, runs.ErrTreeBroken},
		"a loop of parents": {func(t *testing.T, dir string, f family) {
			plant(t, dir, plantedID(7), alice.TenantID, f.root, plantedID(8))
			plant(t, dir, plantedID(8), alice.TenantID, f.root, plantedID(7))
		}, nil, runs.ErrTreeBroken},
		"a parent under another root": {func(t *testing.T, dir string, f family) {
			plant(t, dir, plantedID(7), alice.TenantID, f.root, f.otherChild)
		}, nil, runs.ErrTreeBroken},
		"a record of another tree that does not decode": {func(t *testing.T, dir string, f family) {
			rewrite(t, dir, f.otherChild+".run.json", func(m map[string]json.RawMessage) { m["root"] = json.RawMessage(`17`) })
		}, nil, runs.ErrMalformed},
		"a child asked for as a root": {nil, func(f family) string { return f.child }, runs.ErrNotRoot},
		"no record":                   {nil, func(family) string { return plantedID(99) }, runs.ErrNoRun},
	} {
		t.Run(name, func(t *testing.T) {
			dir, a, _ := setup(t)
			f := openFamily(t, a)
			root := f.root
			if c.edit != nil {
				c.edit(t, dir, f)
			}
			if c.root != nil {
				root = c.root(f)
			}
			if tree, err := a.Tree(t.Context(), root, 100); !errors.Is(err, c.want) || tree != nil {
				t.Fatalf("Tree = %v, %v; want %q", ids(tree), err, c.want)
			}
		})
	}
}

// TestChildrenAreTheRunsOpenedUnderOneRun: a child's own children, not their
// children nor its siblings, after the run itself, bounded by their number.
func TestChildrenAreTheRunsOpenedUnderOneRun(t *testing.T) {
	_, a, _ := setup(t)
	f := openFamily(t, a)
	got, err := a.Children(t.Context(), f.root, 3)
	if err != nil {
		t.Fatalf("Children(root): %v", err)
	}
	want := []string{f.root, min(f.child, f.sibling), max(f.child, f.sibling)}
	if !slices.Equal(ids(got), want) {
		t.Fatalf("Children(root) = %v, want %v", ids(got), want)
	}
	if got, err := a.Children(t.Context(), f.child, 2); err != nil || !slices.Equal(ids(got), []string{f.child, f.grandchild}) ||
		got[0].Parent != f.root || got[0].SecretSHA256 != "" {
		t.Fatalf("Children(child) = %+v, %v", got, err)
	}
	if got, err := a.Children(t.Context(), f.grandchild, 1); err != nil || !slices.Equal(ids(got), []string{f.grandchild}) {
		t.Fatalf("Children(grandchild) = %v, %v", ids(got), err)
	}
	if got, err := a.Children(t.Context(), f.root, 2); !errors.Is(err, runs.ErrTreeBound) || got != nil {
		t.Fatalf("Children one past its bound = %v, %v; want ErrTreeBound", ids(got), err)
	}
}

// TestChildrenRefuseWhatTheyCannotVouchFor: a child of another tenant or
// project, one whose root is not its parent's, and a run no record names.
func TestChildrenRefuseWhatTheyCannotVouchFor(t *testing.T) {
	for name, c := range map[string]struct {
		edit func(t *testing.T, dir string, f family)
		id   func(f family) string
		want error
	}{
		"another tenant": {func(t *testing.T, dir string, f family) {
			rewrite(t, dir, f.grandchild+".run.json", func(m map[string]json.RawMessage) { m["tenant_id"] = json.RawMessage(`"tenant-b"`) })
		}, func(f family) string { return f.child }, runs.ErrTreeTenant},
		"another project": {func(t *testing.T, dir string, f family) {
			rewrite(t, dir, f.grandchild+".run.json", func(m map[string]json.RawMessage) { m["project_id"] = json.RawMessage(`"project-b"`) })
		}, func(f family) string { return f.child }, runs.ErrTreeProject},
		"another root": {func(t *testing.T, dir string, f family) {
			plant(t, dir, plantedID(7), alice.TenantID, f.otherRoot, f.child)
		}, func(f family) string { return f.child }, runs.ErrTreeBroken},
		"no record": {nil, func(family) string { return plantedID(99) }, runs.ErrNoRun},
	} {
		t.Run(name, func(t *testing.T) {
			dir, a, _ := setup(t)
			f := openFamily(t, a)
			if c.edit != nil {
				c.edit(t, dir, f)
			}
			if got, err := a.Children(t.Context(), c.id(f), 100); !errors.Is(err, c.want) || got != nil {
				t.Fatalf("Children = %v, %v; want %q", ids(got), err, c.want)
			}
		})
	}
}

// TestAdminLookupReadsOneRecord: the operator's lookup reads a child as it
// is, with no secret's hash, and refuses a run no record names.
func TestAdminLookupReadsOneRecord(t *testing.T) {
	_, a, _ := setup(t)
	f := openFamily(t, a)
	got, err := a.Lookup(t.Context(), f.grandchild)
	if err != nil || got.ID != f.grandchild || got.Parent != f.child || got.Root != f.root || got.SecretSHA256 != "" {
		t.Fatalf("Lookup = %+v, %v", got, err)
	}
	if _, err := a.Lookup(t.Context(), plantedID(99)); !errors.Is(err, runs.ErrNoRun) {
		t.Fatalf("Lookup of no record: %v", err)
	}
}

func TestTheZeroAdminReadsNoTree(t *testing.T) {
	var a runs.Admin
	id := plantedID(1)
	if _, err := a.Tree(t.Context(), id, 1); !errors.Is(err, runs.ErrClosed) {
		t.Errorf("Tree: %v", err)
	}
	if _, err := a.Children(t.Context(), id, 1); !errors.Is(err, runs.ErrClosed) {
		t.Errorf("Children: %v", err)
	}
	if _, err := a.Lookup(t.Context(), id); !errors.Is(err, runs.ErrClosed) {
		t.Errorf("Lookup: %v", err)
	}
}
