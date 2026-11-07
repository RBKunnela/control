package signedstops_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// grow appends a stop of run-1 to the first list and returns the list as
// judged after it.
func (c chainFixture) grow(t *testing.T) listAt {
	t.Helper()
	stops := filepath.Join(c.base, "stops")
	r := c.routeFor(t, c.plane.RouteFile, stops, reaction.VerifySignedRoute)
	_, _, _, err := stopwrite.AppendFinding(t.Context(), stops, r, func() time.Time { return now }, func(at time.Time) (reaction.Stop, error) {
		return reaction.Stop{EntryID: reaction.EntryID("f1"), TenantID: "t1", ProjectID: "A", Scope: reaction.ScopeRun, RunID: "run-1",
			FindingID: "f1", ProcedureID: "refund", ProcedureVersion: "3",
			ProcedureDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			RuleID:          "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: at, ExpiresAt: at.Add(time.Hour)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	grown := mustJudge(t, stops, r)
	if len(grown.l.Entries()) != 1 {
		t.Fatalf("the grown list holds %d stops", len(grown.l.Entries()))
	}
	return grown
}

// cutToHeader writes the first list back as its header line alone, as a
// writer of the stops directory can, and returns it as judged.
func (c chainFixture) cutToHeader(t *testing.T) listAt {
	t.Helper()
	stops := filepath.Join(c.base, "stops")
	raw, err := stoplist.Read(stops)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stops, stoplist.FileName), raw[:bytes.IndexByte(raw, '\n')+1], 0o600); err != nil {
		t.Fatal(err)
	}
	return mustJudge(t, stops, c.routeFor(t, c.plane.RouteFile, stops, reaction.VerifySignedRoute))
}

// TestAListCutBackAfterThePlaneTookItIsRefusedAcrossARestart: the plane
// takes a list holding a stop; the list cut back to its header, which the
// judge alone takes, is a broken chain against the floor, and the floor
// keeps the part with the stop.
func TestAListCutBackAfterThePlaneTookItIsRefusedAcrossARestart(t *testing.T) {
	c := newChain(t)
	full := c.grow(t)
	if _, err := c.take(t, full); err != nil {
		t.Fatalf("Take of the list with its stop: %v", err)
	}
	c.expectFloor(t, "the list with its stop", 1, full)
	cut := c.cutToHeader(t)
	if len(cut.l.Entries()) != 0 {
		t.Fatalf("the cut list holds %d stops", len(cut.l.Entries()))
	}
	if _, err := c.take(t, cut); !errors.Is(err, stoplist.ErrChain) {
		t.Fatalf("Take of the list cut to its header: %v, want %v", err, stoplist.ErrChain)
	}
	c.expectFloor(t, "after the cut list was refused", 1, full)
}

// TestTheFloorRisesWithEachGrowthOfTheAcceptedPart: the floor takes the
// header alone, then the list grown by a stop, and then refuses the header
// alone, which is shorter than what it holds.
func TestTheFloorRisesWithEachGrowthOfTheAcceptedPart(t *testing.T) {
	c := newChain(t)
	if _, err := c.take(t, c.first); err != nil {
		t.Fatal(err)
	}
	c.expectFloor(t, "the header alone", 1, c.first)
	grown := c.grow(t)
	if _, err := c.take(t, grown); err != nil {
		t.Fatalf("Take of the grown list: %v", err)
	}
	c.expectFloor(t, "the grown list", 1, grown)
	if _, err := c.take(t, c.first); !errors.Is(err, stoplist.ErrChain) {
		t.Fatalf("Take of the header alone over the grown floor: %v, want %v", err, stoplist.ErrChain)
	}
}

func TestHoldHoldsTheAcceptedPartAtTheFloorsSerial(t *testing.T) {
	c := newChain(t)
	l, raw := c.first.l, c.first.raw
	head := l.Header().Signed.Digest
	at := func(serial, length int64, prefix string) policystate.StopsFloor {
		return policystate.StopsFloor{Tenant: "t1", Project: "A", Serial: serial, Digest: head, Length: length, Prefix: prefix}
	}
	n := int64(len(raw))
	other := append(bytes.Clone(raw[:n-2]), 'X', '\n')
	for _, x := range []struct {
		name   string
		stored policystate.StopsFloor
		want   error
	}{
		{"the floor's own part", at(1, n, sha256Of(raw)), nil},
		{"a part that grew past the floor's", at(1, n-1, sha256Of(raw[:n-1])), nil},
		{"a floor with no serial", policystate.StopsFloor{Tenant: "t1", Project: "A"}, nil},
		{"one byte shorter than the floor's part", at(1, n+1, sha256Of(append(bytes.Clone(raw), 'x'))), stoplist.ErrChain},
		{"the floor's length with other bytes", at(1, n, sha256Of(other)), stoplist.ErrChain},
		{"the floor's serial with another head", policystate.StopsFloor{Tenant: "t1", Project: "A", Serial: 1, Digest: "sha256:other",
			Length: n, Prefix: sha256Of(raw)}, stoplist.ErrForked},
	} {
		err := signedstops.Hold(x.stored, l, raw)
		if (x.want == nil && err != nil) || (x.want != nil && !errors.Is(err, x.want)) {
			t.Errorf("%s: %v, want %v", x.name, err, x.want)
		}
	}
}

// TestACarryOfAListCutBackIsRefusedAgainstTheFloor: held to the plane's
// floor, a carry of the list cut back is refused and writes nothing; with no
// floor to hold it to, the cut list is carried as it stands.
func TestACarryOfAListCutBackIsRefusedAgainstTheFloor(t *testing.T) {
	c := newChain(t)
	if _, err := c.take(t, c.grow(t)); err != nil {
		t.Fatal(err)
	}
	c.cutToHeader(t)
	stored, err := policystate.ReadStops(c.floorDir, "t1", "A")
	if err != nil {
		t.Fatal(err)
	}
	from, into := filepath.Join(c.base, "stops"), c.dir(t, "stops2")
	fromRoute := c.routeFor(t, c.plane.RouteFile, from, reaction.VerifySignedCarrySource)
	r := c.routeFor(t, c.plane.RouteFile, into, reaction.VerifySignedRoute)
	hold := func(l reaction.List, content []byte) error { return signedstops.Hold(stored, l, content) }
	_, err = stopwrite.CarrySigned(t.Context(), from, fromRoute, into, r, now, alice(), hold)
	if !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, stoplist.ErrChain) {
		t.Fatalf("a carry of the cut list held to the floor: %v", err)
	}
	if entries, err := os.ReadDir(into); err != nil || len(entries) != 0 {
		t.Fatalf("a refused carry wrote %v, %v", entries, err)
	}
	got, err := stopwrite.CarrySigned(t.Context(), from, fromRoute, into, r, now, alice(), nil)
	if err != nil || got.Stops != 0 {
		t.Fatalf("a carry of the cut list held to nothing: %+v, %v", got, err)
	}
}
