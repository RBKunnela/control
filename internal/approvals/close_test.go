package approvals_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
)

// TestACloseBesideCallsAnswersClosedAndNothingElse: Close may run beside any
// call on the same handle. A call either answers as it would on an open
// handle or answers ErrClosed; under the race detector this is also what
// shows that no call reads whether the handle is open while Close writes it.
func TestACloseBesideCallsAnswersClosedAndNothingElse(t *testing.T) {
	p, dir := openPlane(t)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	a, err := approvals.OpenApprover(dir)
	if err != nil {
		t.Fatalf("opening the approver: %v", err)
	}
	calls := map[string]func() error{
		"Find": func() error {
			_, err := p.Find(t.Context(), h.Binding, minted)
			return err
		},
		"Prune": func() error {
			_, err := p.Prune(t.Context(), minted)
			return err
		},
		"List": func() error {
			_, err := a.List(t.Context())
			return err
		},
		"Answer": func() error {
			_, err := a.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "signed off", minted.Add(time.Minute))
			if errors.Is(err, approvals.ErrApprovalAnswered) {
				return nil
			}
			return err
		},
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for name, call := range calls {
		wg.Go(func() {
			<-start
			for range 100 {
				if err := call(); err != nil && !errors.Is(err, approvals.ErrClosed) {
					t.Errorf("%s beside Close = %v, want nil or ErrClosed", name, err)
					return
				}
			}
		})
	}
	wg.Go(func() {
		<-start
		if err := p.Close(); err != nil {
			t.Errorf("closing the plane: %v", err)
		}
	})
	wg.Go(func() {
		<-start
		if err := a.Close(); err != nil {
			t.Errorf("closing the approver: %v", err)
		}
	})
	close(start)
	wg.Wait()
	if err := a.Close(); !errors.Is(err, approvals.ErrClosed) {
		t.Errorf("a second Close of the approver = %v, want ErrClosed", err)
	}
}
