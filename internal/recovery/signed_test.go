package recovery_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/recovery"
	"github.com/guardana/control/internal/runs"
)

type takeAll struct{}

func (takeAll) Judge(_ context.Context, r runs.SignedRecord) (runs.SignedBy, error) {
	return runs.SignedBy{Subject: "alice", KeyID: r.KeyID}, nil
}

func aliceSigner() runs.Signer {
	seed := sha256.Sum256([]byte("recovery-test/alice"))
	key := ed25519.NewKeyFromSeed(seed[:])
	return runs.Signer{KeyID: "key-alice", Sign: func(_ string, body []byte) ([]byte, error) { return ed25519.Sign(key, body), nil }}
}

// signedPlane is a plane of the signed authority at plane serial 1, roster
// serial 3 and pause serial 2, with one signed run and a pause file, and a
// backup of it.
func signedPlane(t *testing.T) (*plane, string, runs.Record) {
	t.Helper()
	return signedPlaneOf(t, signedBlock, nil)
}

// signedPlaneOf is signedPlane of the configuration base and block, more
// run on it before the backup.
func signedPlaneOf(t *testing.T, block string, more func(*plane, runs.Record)) (*plane, string, runs.Record) {
	t.Helper()
	p := newPlane(t, block)
	p.raiseFloor(t, 1, d1, t0)
	if err := policystate.InitAuthority(t.Context(), p.path("trust/floors"), "roster-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := policystate.RaiseAuthority(t.Context(), p.path("trust/floors"), "roster-a", 3, digestOf(3)); err != nil {
		t.Fatal(err)
	}
	if err := policystate.InitPause(t.Context(), p.path("pausefloor"), "acme", "orders"); err != nil {
		t.Fatal(err)
	}
	if _, err := policystate.RaisePause(t.Context(), p.path("pausefloor"), "acme", "orders", 2, digestOf(2)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.path("pause/pause.json"), []byte(`{"operator":"signed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.path("runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	a, err := runs.InitSignedAdmin(t.Context(), p.path("runs"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	rec, _, err := a.OpenSigned(t.Context(), runs.OpenRequest{Who: alice, TTL: time.Hour, Now: t0}, aliceSigner(), takeAll{})
	if err != nil {
		t.Fatal(err)
	}
	if more != nil {
		more(p, rec)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	return p, dir, rec
}

// TestSignedRestoreWritesOnlyWhatThePlaneOwns: the floors are raised and the
// run's close carried; the operator's pause file and records are left for an
// operator to put back.
func TestSignedRestoreWritesOnlyWhatThePlaneOwns(t *testing.T) {
	p, dir, rec := signedPlane(t)
	for _, lost := range []string{"floors", "trust/floors", "pausefloor", "pause/pause.json", "runs/records/" + rec.ID + ".run.json"} {
		if err := os.RemoveAll(p.path(lost)); err != nil {
			t.Fatal(err)
		}
	}
	report, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	requireSignedFloors(t, p)
	if _, err := os.Lstat(p.path("runs/state/" + rec.ID + ".closed")); err != nil {
		t.Fatalf("the run's close was not carried: %v", err)
	}
	for _, operators := range []string{"pause/pause.json", "runs/records/" + rec.ID + ".run.json"} {
		if _, err := os.Lstat(p.path(operators)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("restore wrote the operator's %s: %v", operators, err)
		}
	}
	if !slices.Equal(report.PutBack, []string{"runs.dir: records/", "pause.file"}) {
		t.Fatalf("PutBack = %q", report.PutBack)
	}
}

// requireSignedFloors holds the floors signedPlane raised to their serials,
// the plane floor stamped at the restore.
func requireSignedFloors(t *testing.T, p *plane) {
	t.Helper()
	if f := p.floor(t); f.Serial() != 1 || !f.IssuedAt().Equal(restoreAt) {
		t.Fatalf("floor = %s", describe(f))
	}
	if a, err := policystate.ReadAuthority(p.path("trust/floors"), "roster-a"); err != nil || a.Serial != 3 {
		t.Fatalf("authority floor = %+v, %v", a, err)
	}
	if pf, err := policystate.ReadPause(p.path("pausefloor"), "acme", "orders"); err != nil || pf.Serial != 2 {
		t.Fatalf("pause floor = %+v, %v", pf, err)
	}
}

// TestSignedRestoreRefusesADirectoryBackup: a backup of the directory
// authority is never restored into a signed plane, whose files it could not
// have signed.
func TestSignedRestoreRefusesADirectoryBackup(t *testing.T) {
	_, dir, _ := backedUp(t)
	p, _, _ := signedPlane(t)
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, recovery.ErrOtherPlane) {
		t.Fatalf("err = %v, want ErrOtherPlane", err)
	}
}

const signedStopsBlock = `reaction:
  route: route/route.json
  floor_dir: routefloor
  stops: stops
  stops_floor_dir: stopsfloor
`

// signedList is the stop list signedStops puts in reaction.stops; a restore
// under signed reads it only to show a floor's history.
var signedList = []byte("header\nstop one\nstop two\nlift\n")

func stopsFloorAt(serial, length int64) policystate.StopsFloor {
	return policystate.StopsFloor{Tenant: "acme", Project: "orders", Serial: serial, Digest: digestOf(serial), Length: length, Prefix: prefixOf(signedList[:length])}
}

func prefixOf(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%x", sum)
}

// setStopsFloor makes the plane's stop list floor f, or none at serial 0.
func (p *plane) setStopsFloor(t *testing.T, f policystate.StopsFloor) {
	t.Helper()
	if err := os.RemoveAll(p.path("stopsfloor")); err != nil {
		t.Fatal(err)
	}
	if err := policystate.InitStops(t.Context(), p.path("stopsfloor"), "acme", "orders"); err != nil {
		t.Fatal(err)
	}
	if f.Serial == 0 {
		return
	}
	if _, err := policystate.RaiseStops(t.Context(), p.path("stopsfloor"), f); err != nil {
		t.Fatal(err)
	}
}

func (p *plane) stopsFloor(t *testing.T) policystate.StopsFloor {
	t.Helper()
	f, err := policystate.ReadStops(p.path("stopsfloor"), "acme", "orders")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// setSignedState raises the state of the signed run root to s.
func (p *plane) setSignedState(t *testing.T, root string, s runs.State) {
	t.Helper()
	pl, err := runs.OpenSignedPlane(p.path("runs"), runs.SignedOptions{Judge: takeAll{}, PlaneOwned: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pl.Close() }()
	if err := pl.Raise(t.Context(), root, func(runs.State) runs.State { return s }); err != nil {
		t.Fatal(err)
	}
}

// signedStops is signedPlane with the run's state raised and a stop list
// floor at serial 2 holding 16 bytes of signedList, which reaction.stops
// holds.
func signedStops(t *testing.T) (*plane, string, runs.Record) {
	t.Helper()
	return signedPlaneOf(t, signedBlock+signedStopsBlock, func(p *plane, rec runs.Record) {
		p.setSignedState(t, rec.ID, confidential)
		p.setStopsFloor(t, stopsFloorAt(2, 16))
		if err := os.Mkdir(p.path("stops"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, p.path("stops/stops.jsonl"), signedList)
	})
}

// TestSignedRestoreRaisesTheStopListFloor: a lost stop list floor is the
// backup's again and the list is left for an operator to put back; a floor
// that grew past the backup's along the list, the live one or the backup's
// copy, is kept.
func TestSignedRestoreRaisesTheStopListFloor(t *testing.T) {
	t.Run("lost", func(t *testing.T) {
		p, dir, _ := signedStops(t)
		for _, lost := range []string{"stopsfloor", "stops/stops.jsonl"} {
			if err := os.RemoveAll(p.path(lost)); err != nil {
				t.Fatal(err)
			}
		}
		report, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
		if err != nil {
			t.Fatalf("Restore: %v", err)
		}
		if f := p.stopsFloor(t); f != stopsFloorAt(2, 16) {
			t.Fatalf("stop list floor = %+v", f)
		}
		if _, err := os.Lstat(p.path("stops/stops.jsonl")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("restore wrote the operator's stop list: %v", err)
		}
		if !slices.Contains(report.PutBack, "reaction.stops") {
			t.Fatalf("PutBack = %q names no stop list", report.PutBack)
		}
	})
	t.Run("grown", func(t *testing.T) {
		p, dir, _ := signedStops(t)
		p.setStopsFloor(t, stopsFloorAt(2, 25))
		if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
			t.Fatalf("Restore: %v", err)
		}
		if f := p.stopsFloor(t); f != stopsFloorAt(2, 25) {
			t.Fatalf("stop list floor = %+v, want the longer live part", f)
		}
	})
	t.Run("shown by the backup's list", func(t *testing.T) {
		p, dir, _ := signedStops(t)
		p.setStopsFloor(t, stopsFloorAt(2, 25))
		writeFile(t, p.path("stops/stops.jsonl"), []byte("another list of no history\n"))
		if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
			t.Fatalf("Restore: %v", err)
		}
		if f := p.stopsFloor(t); f != stopsFloorAt(2, 25) {
			t.Fatalf("stop list floor = %+v, want the longer live part", f)
		}
	})
}

// TestSignedRestoreRefusesTwoStopListHistories: a live floor's part that no
// list shows one history with the backup's is refused before anything is
// written.
func TestSignedRestoreRefusesTwoStopListHistories(t *testing.T) {
	p, dir, _ := signedStops(t)
	other := []byte("another list, 25 bytes...")
	p.setStopsFloor(t, policystate.StopsFloor{Tenant: "acme", Project: "orders", Serial: 2, Digest: digestOf(2), Length: 25, Prefix: prefixOf(other)})
	if err := os.RemoveAll(p.path("floors")); err != nil {
		t.Fatal(err)
	}
	before := tree(t, p.root)
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, policystate.ErrStopsRewritten) {
		t.Fatalf("err = %v, want ErrStopsRewritten", err)
	}
	if after := tree(t, p.root); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("a refused restore changed the plane's tree")
	}
}
