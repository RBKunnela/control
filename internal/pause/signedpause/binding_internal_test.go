package signedpause

import (
	"errors"
	"testing"

	"github.com/guardana/control/internal/pause"
)

// TestAnEmptyPlaneIDOnBothSidesIsNoMatch: a binding that names no plane
// takes no document that names none either, though every other field is
// the same; the control, both naming one plane, is taken.
func TestAnEmptyPlaneIDOnBothSidesIsNoMatch(t *testing.T) {
	b := Binding{tenant: "t1", project: "A", file: "/srv/pause/pause.json"}
	h := pause.Header{KeyID: "k", Tenant: "t1", Project: "A", File: "/srv/pause/pause.json", Serial: 1}
	if err := b.Check(h); !errors.Is(err, pause.ErrOtherPlane) {
		t.Errorf("no plane on either side = %v, want ErrOtherPlane", err)
	}
	b.plane, h.PlaneID = "plane-a", "plane-a"
	if err := b.Check(h); err != nil {
		t.Errorf("the control, one plane on both sides = %v", err)
	}
}
