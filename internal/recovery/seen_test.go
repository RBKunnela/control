package recovery_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardana/control/internal/recovery"
	"github.com/guardana/control/internal/runs"
)

// TestSignedRestoreTakesAChildsFirstAdmission: a backup of a signed plane
// that admitted a child holds the child's .seen in state/, and a restore
// from it closes both runs rather than refuse the marker.
func TestSignedRestoreTakesAChildsFirstAdmission(t *testing.T) {
	var child string
	p, dir, rec := signedPlaneOf(t, signedBlock, func(p *plane, rec runs.Record) {
		a, err := runs.OpenAdmin(t.Context(), p.path("runs"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.Close() }()
		req := runs.OpenRequest{Who: alice, Parent: rec.ID, TTL: 10 * time.Minute, Now: t0}
		c, token, err := a.OpenSigned(t.Context(), req, aliceSigner(), takeAll{})
		if err != nil {
			t.Fatal(err)
		}
		child = c.ID
		pl, err := runs.OpenSignedPlane(p.path("runs"), runs.SignedOptions{Judge: takeAll{}, PlaneOwned: true})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pl.Close() }()
		if _, err := pl.Resolve(t.Context(), token, alice, t0.Add(time.Minute)); err != nil {
			t.Fatalf("the child's first call: %v", err)
		}
	})
	if _, err := os.Lstat(filepath.Join(dir, "runs", "state", child+".seen")); err != nil {
		t.Fatalf("the backup holds no .seen of the child: %v", err)
	}
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
		t.Fatalf("Restore over a .seen: %v", err)
	}
	for _, id := range []string{rec.ID, child} {
		if _, err := os.Lstat(p.path("runs/state/" + id + ".closed")); err != nil {
			t.Fatalf("the close of %s was not carried: %v", id, err)
		}
	}
}
