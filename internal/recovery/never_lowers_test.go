package recovery_test

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/recovery"
	"github.com/guardana/control/internal/runs"
)

// digestOf is the one digest of serial n in these tests, so two sides at one
// serial never fork.
func digestOf(n int64) string { return fmt.Sprintf("sha256:%064d", n) }

// rank orders the reads as the join must, unknown above every other, apart
// from the code under test.
var rank = map[controlv1.Sensitivity]int{
	controlv1.Sensitivity_SENSITIVITY_PUBLIC: 1, controlv1.Sensitivity_SENSITIVITY_INTERNAL: 2,
	controlv1.Sensitivity_SENSITIVITY_CONFIDENTIAL: 3, controlv1.Sensitivity_SENSITIVITY_RESTRICTED: 4,
	controlv1.Sensitivity_SENSITIVITY_SECRET: 5, controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED: 6,
}

type side struct {
	serial int64 // 0: no floor directory
	state  runs.State
	// lost removes the run's state file and keeps its record and lock file.
	lost   bool
	pauses []string
}

func randomSide(r *rand.Rand, floor bool) side {
	s := side{state: runs.State{Untrusted: r.IntN(2) == 1, MaxRead: controlv1.Sensitivity(r.Int32N(6))}, lost: !floor && r.IntN(4) == 0}
	if floor || r.IntN(4) > 0 {
		s.serial = 1 + r.Int64N(4)
	}
	for _, id := range []string{"p1", "p2", "p3", "p4"} {
		if r.IntN(2) == 1 {
			s.pauses = append(s.pauses, id)
		}
	}
	return s
}

// put makes the plane's floor, the run's state and the pause file s's.
func (p *plane) put(t *testing.T, root string, s side) {
	t.Helper()
	if err := os.RemoveAll(p.path("floors")); err != nil {
		t.Fatal(err)
	}
	if s.serial > 0 {
		p.raiseFloor(t, s.serial, digestOf(s.serial), t0)
	}
	p.setState(t, root, s.state)
	if s.lost {
		if err := os.Remove(p.path("runs/" + root + ".state.json")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(p.path("pause/pause.json")); err != nil {
		t.Fatal(err)
	}
	if err := pause.Init(t.Context(), p.path("pause/pause.json")); err != nil {
		t.Fatal(err)
	}
	for _, id := range s.pauses {
		p.addPause(t, id)
	}
}

// joined is the state a restore owes from the backup's and the live one, a
// lost live state counting as untrusted with an unknown read, apart from the
// code under test.
func joined(bk, live side) (bool, int) {
	if live.lost {
		return true, rank[controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED]
	}
	return bk.state.Untrusted || live.state.Untrusted, max(rank[bk.state.MaxRead], rank[live.state.MaxRead])
}

// TestRestoreNeverLowers draws a backup and a live state per class and
// requires each restored class at the higher of the two, under each
// authority: the floor's serial, the run's taint and read, a state lost
// beside its record or lock file as the worst, the union of the pauses, and
// the stop list floor's serial.
func TestRestoreNeverLowers(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 22)) //nolint:gosec // G404: a seeded draw, the same on every run
	lost := 0
	for i := range 16 {
		bk, live := randomSide(r, true), randomSide(r, false)
		if live.lost {
			lost++
		}
		t.Run(fmt.Sprintf("%d/signed", i), func(t *testing.T) { signedNeverLowers(t, bk, live) })
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			p := newPlane(t, directoryBlock)
			rec := p.openRun(t, bk.state)
			p.put(t, rec.ID, bk)
			dir := filepath.Join(t.TempDir(), "backup")
			if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); err != nil {
				t.Fatal(err)
			}
			p.put(t, rec.ID, live)
			if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
				t.Fatalf("backup %+v live %+v: %v", bk, live, err)
			}
			if f := p.floor(t); f.Serial() != max(bk.serial, live.serial) || !f.IssuedAt().Equal(restoreAt) {
				t.Errorf("floor = %s, want serial %d stamped at the restore", describe(f), max(bk.serial, live.serial))
			}
			_, s := p.run(t, rec.ID)
			if untrusted, read := joined(bk, live); s.Untrusted != untrusted || rank[s.MaxRead] != read {
				t.Errorf("state = %+v from backup %+v and live %+v", s, bk, live)
			}
			want := unionOf(live.pauses, bk.pauses)
			got := p.pauses(t)
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Errorf("pauses = %v, want %v", got, want)
			}
		})
	}
	if lost == 0 {
		t.Fatal("no draw lost a live state; that case was not examined")
	}
}

// unionOf is a and every id of b it lacks, sorted.
func unionOf(a, b []string) []string {
	out := slices.Clone(a)
	for _, id := range b {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// putSigned makes the signed plane's floor, stop list floor and run state
// s's.
func (p *plane) putSigned(t *testing.T, rec runs.Record, s side) {
	t.Helper()
	if err := os.RemoveAll(p.path("floors")); err != nil {
		t.Fatal(err)
	}
	if s.serial > 0 {
		p.raiseFloor(t, s.serial, digestOf(s.serial), t0)
	}
	p.setStopsFloor(t, stopsFloorAt(s.serial, 16))
	p.setSignedState(t, rec.ID, s.state)
	if s.lost {
		if err := os.Remove(p.path("runs/state/" + rec.ID + ".state.json")); err != nil {
			t.Fatal(err)
		}
	}
}

// signedNeverLowers is TestRestoreNeverLowers under signed: the plane floor,
// the stop list floor and the run's state, lost or not.
func signedNeverLowers(t *testing.T, bk, live side) {
	p, _, rec := signedStops(t)
	p.putSigned(t, rec, bk)
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); err != nil {
		t.Fatal(err)
	}
	p.putSigned(t, rec, live)
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
		t.Fatalf("backup %+v live %+v: %v", bk, live, err)
	}
	if f := p.floor(t); f.Serial() != max(bk.serial, live.serial) {
		t.Errorf("floor = %s, want serial %d", describe(f), max(bk.serial, live.serial))
	}
	if f := p.stopsFloor(t); f.Serial != max(bk.serial, live.serial) {
		t.Errorf("stop list floor = %+v, want serial %d", f, max(bk.serial, live.serial))
	}
	pl, err := runs.OpenSignedPlane(p.path("runs"), runs.SignedOptions{Judge: takeAll{}, PlaneOwned: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pl.Close() }()
	s, err := pl.State(t.Context(), rec.ID)
	if untrusted, read := joined(bk, live); err != nil || s.Untrusted != untrusted || rank[s.MaxRead] != read {
		t.Errorf("state = %+v, %v from backup %+v and live %+v", s, err, bk, live)
	}
}
