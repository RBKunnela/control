package policystate_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policystate"
)

// floorsAt is a plane floor directory whose idA floor took one statement of
// serial at digest, issued at issued.
func floorsAt(t *testing.T, serial int64, digest, issued string) string {
	t.Helper()
	dir := initDir(t, policystate.KindPlane)
	if _, err := open(t, dir).Raise(t.Context(), statement(t, idA, serial, digest, issued), noon(t)); err != nil {
		t.Fatalf("Raise to serial %d: %v", serial, err)
	}
	return dir
}

func floorOf(t *testing.T, dir, id string) (policy.Floor, error) {
	t.Helper()
	s, err := policystate.Open(dir, policystate.KindPlane)
	if err != nil {
		t.Fatalf("Open(%s): %v", dir, err)
	}
	defer func() { _ = s.Close() }()
	return s.Floor(t.Context(), id)
}

func TestRestorePlaneStampsTheHigherSerialAtTheRestore(t *testing.T) {
	cases := []struct {
		name               string
		live, backup       int64
		liveDig, backupDig string
		wantDigest         string
	}{
		{"the live floor is higher", 5, 3, d5, d3, d5},
		{"the backup is higher", 3, 5, d3, d5, d5},
		{"both are at one serial", 5, 5, d5, d5, d5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			live := floorsAt(t, c.live, c.liveDig, "10:00:00")
			backup := floorsAt(t, c.backup, c.backupDig, "11:00:00")
			if _, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), nil); err != nil {
				t.Fatalf("RestorePlane: %v", err)
			}
			got, err := floorOf(t, live, idA)
			if err != nil {
				t.Fatal(err)
			}
			want := "bundle-a serial 5 " + c.wantDigest + " issued 2026-09-11T13:00:00Z latest 2026-09-11T13:00:00Z"
			if describe(got) != want {
				t.Fatalf("restored floor = %s, want %s", describe(got), want)
			}
		})
	}
}

// TestRestoredFloorTakesOnlyAStatementIssuedAfterIt is the guarantee the
// stamp is for: the serial's own statement, issued before the restore,
// confirms nothing; one issued after it does.
func TestRestoredFloorTakesOnlyAStatementIssuedAfterIt(t *testing.T) {
	live := floorsAt(t, 5, d5, "11:00:00")
	backup := floorsAt(t, 3, d3, "10:00:00")
	if _, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), nil); err != nil {
		t.Fatalf("RestorePlane: %v", err)
	}
	s := open(t, live)
	if _, err := s.Raise(t.Context(), statement(t, idA, 5, d5, "11:00:00"), at(t, "14:00:00")); !errors.Is(err, policy.ErrBelowFloor) {
		t.Fatalf("the statement issued before the restore: err = %v, want ErrBelowFloor", err)
	}
	if _, err := s.Raise(t.Context(), statement(t, idA, 5, d5, "13:30:00"), at(t, "14:00:00")); err != nil {
		t.Fatalf("a statement issued after the restore: %v", err)
	}
}

// TestRestoreStampRoundsUpToTheSecond: a restore part of the way into a
// second stamps the next one, so a statement issued earlier in its own
// second is below the floor; one on the second exactly stamps that second.
func TestRestoreStampRoundsUpToTheSecond(t *testing.T) {
	live := floorsAt(t, 5, d5, "11:00:00")
	backup := floorsAt(t, 5, d5, "11:00:00")
	if _, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00").Add(time.Millisecond), nil); err != nil {
		t.Fatalf("RestorePlane: %v", err)
	}
	s := open(t, live)
	if _, err := s.Raise(t.Context(), statement(t, idA, 5, d5, "13:00:00"), at(t, "14:00:00")); !errors.Is(err, policy.ErrBelowFloor) {
		t.Fatalf("a statement of the restore's second: err = %v, want ErrBelowFloor", err)
	}
	if _, err := s.Raise(t.Context(), statement(t, idA, 5, d5, "13:00:01"), at(t, "14:00:00")); err != nil {
		t.Fatalf("a statement of the next second: %v", err)
	}
	exact := floorsAt(t, 5, d5, "11:00:00")
	if _, err := policystate.RestorePlane(t.Context(), exact, backup, at(t, "13:00:00"), nil); err != nil {
		t.Fatalf("RestorePlane: %v", err)
	}
	if got, err := floorOf(t, exact, idA); err != nil || !got.IssuedAt().Equal(at(t, "13:00:00")) {
		t.Fatalf("a restore on the second: floor = %s, %v", describe(got), err)
	}
}

func TestRestorePlaneRefusesBeforeWriting(t *testing.T) {
	cases := []struct {
		name   string
		backup func(t *testing.T) string
		at     string
		want   error
	}{
		{"one serial, two digests", func(t *testing.T) string { return floorsAt(t, 5, d6, "10:00:00") }, "13:00:00", policy.ErrFloorSerialReused},
		{"a clock behind the live floor", func(t *testing.T) string { return floorsAt(t, 3, d3, "09:00:00") }, "10:59:59", policy.ErrClockBehindFloor},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			live := floorsAt(t, 5, d5, "11:00:00")
			before := readFile(t, filepath.Join(live, fileA))
			_, err := policystate.RestorePlane(t.Context(), live, c.backup(t), at(t, c.at), nil)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if after := readFile(t, filepath.Join(live, fileA)); after != before {
				t.Fatalf("the floor file changed on a refusal:\n%s\n%s", before, after)
			}
		})
	}
}

func TestRestorePlaneBuildsAMissingDirectory(t *testing.T) {
	backup := floorsAt(t, 3, d3, "10:00:00")
	if err := policystate.Init(t.Context(), backup, policystate.KindPlane, idB); err != nil {
		t.Fatal(err)
	}
	live := newDir(t)
	got, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), nil)
	if err != nil {
		t.Fatalf("RestorePlane: %v", err)
	}
	if !got.Built || !slices.Equal(got.Written, []string{idA}) || !slices.Equal(got.Listed, []string{idA, idB}) {
		t.Fatalf("Restored = %+v, want built, %s written, both listed", got, idA)
	}
	f, err := floorOf(t, live, idA)
	if err != nil || describe(f) != "bundle-a serial 3 "+d3+" issued 2026-09-11T13:00:00Z latest 2026-09-11T13:00:00Z" {
		t.Fatalf("floor = %s, %v", describe(f), err)
	}
	// idB held no serial anywhere: it is listed with no file, so a start
	// refuses it until the operator resets it.
	if _, err := floorOf(t, live, idB); !errors.Is(err, policystate.ErrNoFloor) {
		t.Fatalf("idB: err = %v, want ErrNoFloor", err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(live), ".floors.restoring")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the temporary sibling is left: %v", err)
	}
}

func TestRestorePlaneLeavesAnIDOnlyLiveLists(t *testing.T) {
	live := floorsAt(t, 5, d5, "11:00:00")
	if err := policystate.Init(t.Context(), live, policystate.KindPlane, idB); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, filepath.Join(live, fileB))
	backup := floorsAt(t, 3, d3, "10:00:00")
	if _, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), nil); err != nil {
		t.Fatal(err)
	}
	if after := readFile(t, filepath.Join(live, fileB)); after != before {
		t.Fatalf("idB's file changed:\n%s\n%s", before, after)
	}
}

func TestRestorePlaneMendsARemovedFile(t *testing.T) {
	live := floorsAt(t, 5, d5, "11:00:00")
	if err := os.Remove(filepath.Join(live, fileA)); err != nil {
		t.Fatal(err)
	}
	backup := floorsAt(t, 3, d3, "10:00:00")
	if _, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), nil); err != nil {
		t.Fatal(err)
	}
	f, err := floorOf(t, live, idA)
	if err != nil || f.Serial() != 3 {
		t.Fatalf("floor = %s, %v; want the backup's serial 3", describe(f), err)
	}
}

// TestRestorePlaneKilledAtEveryStepConverges stops a restore before each of
// its writes, then runs it again, and requires what an unbroken restore
// leaves.
func TestRestorePlaneKilledAtEveryStepConverges(t *testing.T) {
	backup := floorsAt(t, 5, d5, "10:00:00")
	if err := policystate.Init(t.Context(), backup, policystate.KindPlane, idB); err != nil {
		t.Fatal(err)
	}
	var steps []string
	record := func(what string) error { steps = append(steps, what); return nil }
	for _, missing := range []bool{false, true} {
		steps = nil
		mk := func(t *testing.T) string {
			if missing {
				return newDir(t)
			}
			return floorsAt(t, 3, d3, "09:00:00")
		}
		want := mk(t)
		if _, err := policystate.RestorePlane(t.Context(), want, backup, at(t, "13:00:00"), record); err != nil {
			t.Fatal(err)
		}
		if len(steps) < 2 {
			t.Fatalf("missing=%v: %d steps %q, want at least two", missing, len(steps), steps)
		}
		for i := range steps {
			live := mk(t)
			stop := errors.New("killed")
			n := 0
			_, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), func(string) error {
				if n == i {
					return stop
				}
				n++
				return nil
			})
			if !errors.Is(err, stop) {
				t.Fatalf("missing=%v step %d %q: err = %v, want the kill", missing, i, steps[i], err)
			}
			if _, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), nil); err != nil {
				t.Fatalf("missing=%v rerun after step %d: %v", missing, i, err)
			}
			for _, name := range []string{"floors.meta", fileA} {
				if a, b := readFile(t, filepath.Join(want, name)), readFile(t, filepath.Join(live, name)); a != b {
					t.Fatalf("missing=%v killed at %q: %s differs:\n%s\n%s", missing, steps[i], name, a, b)
				}
			}
		}
	}
}

const (
	routeID  = "route-a"
	rosterID = "roster-a"
)

func routeFloors(t *testing.T, serial int64, digest string) string {
	t.Helper()
	dir := newDir(t)
	if err := policystate.InitRoute(t.Context(), dir, routeID); err != nil {
		t.Fatal(err)
	}
	if serial > 0 {
		if _, err := policystate.RaiseRoute(t.Context(), dir, routeID, serial, digest); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRestoreRouteTakesTheHigherSerial(t *testing.T) {
	cases := []struct {
		name         string
		live, backup int64
		backupDigest string
		want         int64
		wantErr      error
	}{
		{"backup higher", 3, 5, d5, 5, nil},
		{"live higher", 5, 3, d3, 5, nil},
		{"live holds none", 0, 3, d3, 3, nil},
		{"forked", 5, 5, d6, 5, policystate.ErrRouteForked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			liveDigest := d3
			if c.live == 5 {
				liveDigest = d5
			}
			live := routeFloors(t, c.live, liveDigest)
			_, err := policystate.RestoreRoute(t.Context(), live, routeFloors(t, c.backup, c.backupDigest), nil)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
			got, err := policystate.ReadRoute(live, routeID)
			if err != nil || got.Serial != c.want {
				t.Fatalf("floor = %+v, %v; want serial %d", got, err, c.want)
			}
		})
	}
}

func TestRestoreAuthorityTakesTheHigherSerialAndBuilds(t *testing.T) {
	backup := newDir(t)
	if err := policystate.InitAuthority(t.Context(), backup, rosterID); err != nil {
		t.Fatal(err)
	}
	if _, err := policystate.RaiseAuthority(t.Context(), backup, rosterID, 7, d7); err != nil {
		t.Fatal(err)
	}
	live := newDir(t)
	if _, err := policystate.RestoreAuthority(t.Context(), live, backup, nil); err != nil {
		t.Fatal(err)
	}
	got, err := policystate.ReadAuthority(live, rosterID)
	if err != nil || got.Serial != 7 || got.Digest != d7 {
		t.Fatalf("floor = %+v, %v; want serial 7", got, err)
	}
	if _, err := policystate.RaiseAuthority(t.Context(), live, rosterID, 6, d6); !errors.Is(err, policystate.ErrAuthorityBelowFloor) {
		t.Fatalf("a roster below the restored floor: err = %v", err)
	}
}

func pauseFloors(t *testing.T, tenant string, serial int64, digest string) string {
	t.Helper()
	dir := newDir(t)
	if err := policystate.InitPause(t.Context(), dir, tenant, "project-a"); err != nil {
		t.Fatal(err)
	}
	if serial > 0 {
		if _, err := policystate.RaisePause(t.Context(), dir, tenant, "project-a", serial, digest); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRestorePauseRaisesAndRefusesAnotherScope(t *testing.T) {
	live := pauseFloors(t, "tenant-a", 3, d3)
	if _, err := policystate.RestorePause(t.Context(), live, pauseFloors(t, "tenant-a", 5, d5), "tenant-a", "project-a", nil); err != nil {
		t.Fatal(err)
	}
	got, err := policystate.ReadPause(live, "tenant-a", "project-a")
	if err != nil || got.Serial != 5 {
		t.Fatalf("floor = %+v, %v; want serial 5", got, err)
	}
	other := pauseFloors(t, "tenant-b", 9, d7)
	if _, err := policystate.RestorePause(t.Context(), live, other, "tenant-a", "project-a", nil); !errors.Is(err, policystate.ErrPauseScope) {
		t.Fatalf("another tenant's backup: err = %v, want ErrPauseScope", err)
	}
	if got, _ := policystate.ReadPause(live, "tenant-a", "project-a"); got.Serial != 5 {
		t.Fatalf("a refused restore moved the floor to %d", got.Serial)
	}
}
