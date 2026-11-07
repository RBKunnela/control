package policystate_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/policystate"
)

const (
	pauseMarkerT1A = `{"schema_version":"1.0","kind":"pause","tenant":"t1","project":"A"}` + "\n"
	pauseEmptyT1A  = `{"schema_version":"1.0","tenant":"t1","project":"A","serial":null,"digest":null}` + "\n"
	pauseAt5T1A    = `{"schema_version":"1.0","tenant":"t1","project":"A","serial":5,"digest":"` + d5 + `"}` + "\n"
)

func pauseDir(t testing.TB) string {
	t.Helper()
	dir := newDir(t)
	if err := policystate.InitPause(t.Context(), dir, "t1", "A"); err != nil {
		t.Fatalf("InitPause(%s): %v", dir, err)
	}
	return dir
}

func TestInitPauseMakesAFloorWithNoSerialAndNeverAgain(t *testing.T) {
	dir := pauseDir(t)
	if got := readFile(t, filepath.Join(dir, "pause.meta")); got != pauseMarkerT1A {
		t.Errorf("the marker = %q, want %q", got, pauseMarkerT1A)
	}
	if got := readFile(t, filepath.Join(dir, "pause.floor.json")); got != pauseEmptyT1A {
		t.Errorf("the floor file = %q, want %q", got, pauseEmptyT1A)
	}
	f, err := policystate.ReadPause(dir, "t1", "A")
	if err != nil || f.HasSerial() {
		t.Errorf("ReadPause = %+v, %v; want no serial", f, err)
	}
	if err := policystate.InitPause(t.Context(), dir, "t1", "A"); !errors.Is(err, policystate.ErrExists) {
		t.Errorf("InitPause again = %v, want ErrExists", err)
	}
	if err := os.Remove(filepath.Join(dir, "pause.floor.json")); err != nil {
		t.Fatal(err)
	}
	if err := policystate.InitPause(t.Context(), dir, "t1", "A"); !errors.Is(err, policystate.ErrFloorRemoved) {
		t.Errorf("InitPause over a removed floor = %v, want ErrFloorRemoved", err)
	}
	if _, err := policystate.ReadPause(dir, "t1", "A"); !errors.Is(err, policystate.ErrNoFloor) {
		t.Errorf("ReadPause of a removed floor = %v, want ErrNoFloor", err)
	}
}

// TestRaisePauseRefusesAReplayAndAFork: the floor takes only a higher serial,
// or the one it holds with its digest, and is left as it was otherwise.
func TestRaisePauseRefusesAReplayAndAFork(t *testing.T) {
	dir := pauseDir(t)
	if f, err := policystate.RaisePause(t.Context(), dir, "t1", "A", 5, d5); err != nil || f.Serial != 5 {
		t.Fatalf("RaisePause to 5 = %+v, %v", f, err)
	}
	if got := readFile(t, filepath.Join(dir, "pause.floor.json")); got != pauseAt5T1A {
		t.Errorf("the floor file = %q, want %q", got, pauseAt5T1A)
	}
	if f, err := policystate.RaisePause(t.Context(), dir, "t1", "A", 5, d5); err != nil || f.Serial != 5 {
		t.Errorf("RaisePause at the floor = %+v, %v; want it taken as it is", f, err)
	}
	if _, err := policystate.RaisePause(t.Context(), dir, "t1", "A", 4, d6); !errors.Is(err, policystate.ErrPauseBelowFloor) {
		t.Errorf("RaisePause to 4 = %v, want ErrPauseBelowFloor", err)
	}
	if _, err := policystate.RaisePause(t.Context(), dir, "t1", "A", 5, d6); !errors.Is(err, policystate.ErrPauseForked) {
		t.Errorf("RaisePause to 5 of another digest = %v, want ErrPauseForked", err)
	}
	if got := readFile(t, filepath.Join(dir, "pause.floor.json")); got != pauseAt5T1A {
		t.Errorf("a refused raise changed the floor file to %q", got)
	}
	if f, err := policystate.RaisePause(t.Context(), dir, "t1", "A", 6, d6); err != nil || f.Serial != 6 {
		t.Errorf("RaisePause to 6 = %+v, %v", f, err)
	}
}

func TestAPauseFloorIsItsTenantsAndProjectsAlone(t *testing.T) {
	dir := pauseDir(t)
	for _, c := range []struct{ tenant, project string }{{"t2", "A"}, {"t1", "B"}} {
		if _, err := policystate.ReadPause(dir, c.tenant, c.project); !errors.Is(err, policystate.ErrPauseScope) {
			t.Errorf("ReadPause(%s/%s) = %v, want ErrPauseScope", c.tenant, c.project, err)
		}
		if _, err := policystate.RaisePause(t.Context(), dir, c.tenant, c.project, 1, d5); !errors.Is(err, policystate.ErrPauseScope) {
			t.Errorf("RaisePause(%s/%s) = %v, want ErrPauseScope", c.tenant, c.project, err)
		}
	}
	if _, err := policystate.ReadPause(dir, "", "A"); !errors.Is(err, policystate.ErrPauseInvalid) {
		t.Errorf("ReadPause of an empty tenant = %v, want ErrPauseInvalid", err)
	}
	if _, err := policystate.RaisePause(t.Context(), dir, "t1", "A", 0, d5); !errors.Is(err, policystate.ErrPauseInvalid) {
		t.Errorf("RaisePause to 0 = %v, want ErrPauseInvalid", err)
	}
}

func TestAPauseFloorDirectoryIsNoOtherKindsAndHoldsNothingElse(t *testing.T) {
	route := newDir(t)
	if err := policystate.InitRoute(t.Context(), route, "route-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := policystate.ReadPause(route, "t1", "A"); !errors.Is(err, policystate.ErrWrongKind) {
		t.Errorf("ReadPause of a route floor directory = %v, want ErrWrongKind", err)
	}
	if err := policystate.InitPause(t.Context(), route, "t1", "A"); !errors.Is(err, policystate.ErrWrongKind) {
		t.Errorf("InitPause over a route floor directory = %v, want ErrWrongKind", err)
	}
	if _, err := policystate.ReadAuthority(pauseDir(t), rosterA); err == nil {
		t.Error("ReadAuthority took a pause floor directory")
	}
	dir := pauseDir(t)
	writeFile(t, filepath.Join(dir, "stray"), "x")
	if _, err := policystate.ReadPause(dir, "t1", "A"); !errors.Is(err, policystate.ErrForeignFile) {
		t.Errorf("ReadPause beside a stray file = %v, want ErrForeignFile", err)
	}
}
