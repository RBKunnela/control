package approvals_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
)

// The names a record of firstApproval takes, spelled as the package
// documentation spells them, and the two names a 1.0 directory gave a record
// the plane resolved, which no record takes any more.
const (
	heldName       = firstApproval + ".0-held.rec"
	answeredName   = firstApproval + ".1-answered.rec"
	notResumedName = firstApproval + ".2-not-resumed.rec"
	consumedName   = firstApproval + ".3-consumed.rec"
)

// afterLink returns an option whose step runs plant the first time a name is
// linked after arm: between a transition's link and the re-read behind it,
// which is where a plane that crashed between its own link and unlink leaves
// its mark.
func afterLink(t *testing.T, plant func()) (opt approvals.Option, arm func()) {
	t.Helper()
	var armed, planted atomic.Bool
	steps := func(step string) {
		if step != approvals.StepLinked || !armed.Load() || !planted.CompareAndSwap(false, true) {
			return
		}
		plant()
	}
	t.Cleanup(func() {
		if armed.Load() && !planted.Load() {
			t.Error("the plant never ran: nothing was linked")
		}
	})
	return approvals.WithSteps(steps), func() { armed.Store(true) }
}

// heldWith holds firstApproval for req-1 on a plane opened with opts.
func heldWith(t *testing.T, opts ...approvals.Option) (*approvals.Plane, string, approvals.Hold) {
	t.Helper()
	p, dir := openPlane(t, opts...)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	return p, dir, h
}

func assertNames(t *testing.T, dir string, want ...string) {
	t.Helper()
	got := recordNames(t, dir)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("the directory holds %v, want %v", got, want)
	}
}

// TestANameThatOnceSaidSpentIsForeign: a writer of the directory who plants
// the name a 1.0 plane gave a spent or a given-up record, holding the plane's
// own record under its own approval id, is refused as any foreign name is, by
// every call that lists the directory; the plane never reads it as spent or
// as given up. The control is the same directory with the plant removed.
func TestANameThatOnceSaidSpentIsForeign(t *testing.T) {
	for _, planted := range []string{consumedName, notResumedName} {
		t.Run(planted, func(t *testing.T) {
			p, dir, h := heldWith(t)
			answerAt(t, dir, minted.Add(time.Minute))
			writeFile(t, dir, planted, readFile(t, dir, answeredName))
			if _, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute)); !errors.Is(err, approvals.ErrForeignFile) {
				t.Errorf("Find beside %s = %v, want ErrForeignFile", planted, err)
			}
			if _, err := p.Prune(t.Context(), minted.Add(time.Hour)); !errors.Is(err, approvals.ErrForeignFile) {
				t.Errorf("Prune beside %s = %v, want ErrForeignFile", planted, err)
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := approvals.OpenPlane(dir); !errors.Is(err, approvals.ErrForeignFile) {
				t.Errorf("a plane over a directory holding %s = %v, want ErrForeignFile", planted, err)
			}
			if err := os.Remove(filepath.Join(dir, planted)); err != nil {
				t.Fatal(err)
			}
			again := openPlaneAt(t, dir)
			found, err := again.Find(t.Context(), h.Binding, minted.Add(2*time.Minute))
			if err != nil || len(found) != 1 || found[0].Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_APPROVED {
				t.Errorf("Find with the plant removed = %v, %v; want the one answered record", found, err)
			}
		})
	}
}

// openPlaneAt opens a plane over dir and closes it with the test.
func openPlaneAt(t *testing.T, dir string) *approvals.Plane {
	t.Helper()
	p, err := approvals.OpenPlane(dir)
	if err != nil {
		t.Fatalf("opening the plane: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
