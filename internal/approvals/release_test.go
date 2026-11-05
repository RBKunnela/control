package approvals_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
)

// TestReleaseForgetsOnlyThePlanesNamedRecord: the plane forgets its own
// record of a settled approval, answered or not, with its projection, and an
// approver's answer to it is then refused as one to an unknown approval. A
// call that names another request or binding, or no approval, removes
// nothing.
func TestReleaseForgetsOnlyThePlanesNamedRecord(t *testing.T) {
	p, dir, h := heldOne(t)
	answerAt(t, dir, minted.Add(time.Minute))
	other := approval.Binding("sha256:other")
	for name, c := range map[string]struct {
		call func() error
		want error
	}{
		"another request": {func() error { return p.Release(t.Context(), h.Binding, "req-2", firstApproval) }, approvals.ErrRecordMismatch},
		"another binding": {func() error { return p.Release(t.Context(), other, "req-1", firstApproval) }, approvals.ErrRecordMismatch},
		"no approval":     {func() error { return p.Release(t.Context(), h.Binding, "req-1", "") }, approvals.ErrRecordName},
		"an unknown one":  {func() error { return p.Release(t.Context(), h.Binding, "req-1", "APPROVAL9") }, approvals.ErrNoApproval},
	} {
		if err := c.call(); !errors.Is(err, c.want) {
			t.Errorf("Release of %s = %v, want %v", name, err, c.want)
		}
	}
	assertNames(t, dir, answeredName)
	if err := p.Release(t.Context(), h.Binding, "req-1", firstApproval); err != nil {
		t.Fatalf("Release: %v", err)
	}
	assertNames(t, dir)
	if names := keysOf(dirContents(t, dir)); slices.Contains(names, firstApproval+".view.json") {
		t.Errorf("the projection stayed: %v", names)
	}
	_, err := openApprover(t, dir).Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_REJECTED, "approver-2", "", minted.Add(2*time.Minute))
	if !errors.Is(err, approvals.ErrNoApproval) {
		t.Errorf("an answer to a released approval = %v, want ErrNoApproval", err)
	}
}
