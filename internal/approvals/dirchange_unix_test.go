//go:build unix

package approvals_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
)

const approved = controlv1.ApprovalState_APPROVAL_STATE_APPROVED

// planeCalls is every call of the plane's handle that reads or writes the
// directory, each on the one held fixture.
func planeCalls(t *testing.T, p *approvals.Plane, _ approvals.Hold) map[string]error {
	t.Helper()
	ctx := t.Context()
	binding := bindingOf(t, "req-1")
	_, find := p.Find(ctx, binding, minted)
	second := held(t, "APPROVAL2", "req-2")
	_, prune := p.Prune(ctx, expires)
	return map[string]error{
		"Find":  find,
		"Hold":  p.Hold(ctx, second, minted),
		"Prune": prune,
	}
}

// stateIn reads one record's state from a fresh approver over dir.
func stateIn(t *testing.T, dir, approvalID string) controlv1.ApprovalState {
	t.Helper()
	l, err := openApprover(t, dir).List(t.Context())
	if err != nil {
		t.Fatalf("listing %s: %v", dir, err)
	}
	for _, e := range l.Entries {
		if e.Record.ApprovalID == approvalID {
			return e.Record.Approval.GetState()
		}
	}
	t.Fatalf("%s holds no record %s", dir, approvalID)
	return 0
}

// TestADirectoryLoosenedAfterOpenIsRefusedByBothHandles: a group-writable
// mode set after both handles opened refuses every call of either, and the
// record is left as it was. Put back, the same answer is filed: the mode was
// the whole difference.
func TestADirectoryLoosenedAfterOpenIsRefusedByBothHandles(t *testing.T) {
	p, dir, h := heldOne(t)
	a := openApprover(t, dir)
	if err := os.Chmod(dir, 0o720); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: a directory needs its execute bit; 0700 is owner-only
	_, answer := a.Answer(t.Context(), firstApproval, approved, "approver-1", "", minted)
	_, list := a.List(t.Context())
	calls := planeCalls(t, p, h)
	calls["Answer"], calls["List"] = answer, list
	for name, err := range calls {
		if !errors.Is(err, approvals.ErrDirectoryChanged) || !errors.Is(err, approvals.ErrPermissions) {
			t.Errorf("%s on a loosened directory = %v, want ErrDirectoryChanged and ErrPermissions", name, err)
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs its execute bit; 0700 is owner-only
		t.Fatal(err)
	}
	if got := stateIn(t, dir, firstApproval); got != controlv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Fatalf("a refused call left the record %s", got)
	}
	if _, err := a.Answer(t.Context(), firstApproval, approved, "approver-1", "", minted); err != nil {
		t.Fatalf("the same answer on the directory as opened: %v", err)
	}
	if _, err := p.Find(t.Context(), bindingOf(t, "req-1"), minted); err != nil {
		t.Errorf("Find on the directory as opened: %v", err)
	}
}

// TestADirectoryAGroupMayReadIsStillServed: read and search for the group
// and the world are not write, so they are not a change that refuses.
func TestADirectoryAGroupMayReadIsStillServed(t *testing.T) {
	p, dir, _ := heldOne(t)
	a := openApprover(t, dir)
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: a directory needs its execute bit; 0700 is owner-only
	if _, err := a.List(t.Context()); err != nil {
		t.Errorf("List on a 0755 directory: %v", err)
	}
	if _, err := p.Find(t.Context(), bindingOf(t, "req-1"), minted); err != nil {
		t.Errorf("Find on a 0755 directory: %v", err)
	}
}

// TestADirectorySwappedUnderItsNameIsRefused: the directory both handles
// opened is renamed away, and another store stands at its name, once as a
// link and once as a directory. Neither handle reads or answers in the other
// store, and its record stays pending.
func TestADirectorySwappedUnderItsNameIsRefused(t *testing.T) {
	for name, swap := range map[string]func(t *testing.T, at, other string){
		"a link": func(t *testing.T, at, other string) {
			if err := os.Symlink(other, at); err != nil {
				t.Fatal(err)
			}
		},
		"a directory": func(t *testing.T, at, other string) {
			if err := os.Rename(other, at); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, dir, h := heldOne(t)
			a := openApprover(t, dir)
			other := filepath.Join(t.TempDir(), "other")
			if err := os.Mkdir(other, 0o700); err != nil {
				t.Fatal(err)
			}
			q, err := approvals.OpenPlane(other)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = q.Close() })
			if err := q.Hold(t.Context(), held(t, "ELSEWHERE", "req-9"), minted); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(dir, dir+".moved"); err != nil {
				t.Fatal(err)
			}
			swap(t, dir, other)
			_, answer := a.Answer(t.Context(), "ELSEWHERE", approved, "approver-1", "", minted)
			_, list := a.List(t.Context())
			calls := planeCalls(t, p, h)
			calls["Answer"], calls["List"] = answer, list
			for call, err := range calls {
				if !errors.Is(err, approvals.ErrDirectoryChanged) {
					t.Errorf("%s through a swapped name = %v, want ErrDirectoryChanged", call, err)
				}
				if errors.Is(err, approvals.ErrNoApproval) {
					t.Errorf("%s through a swapped name reads as no approval, which holds the call anew: %v", call, err)
				}
			}
			if got := stateIn(t, dir, "ELSEWHERE"); got != controlv1.ApprovalState_APPROVAL_STATE_PENDING {
				t.Errorf("the other store's record is %s", got)
			}
		})
	}
}
