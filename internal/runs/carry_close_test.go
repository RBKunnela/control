//go:build unix

package runs_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// closedThenReadOnly is a signed layout whose run alice closed, the open
// record's bytes as they were, and the layout's state/ made read-only so no
// close can be carried into it until the test's cleanup.
func closedThenReadOnly(t *testing.T) (dir string, rec runs.Record, token string, open []byte) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the superuser writes a directory whatever its mode")
	}
	dir, a := newSigned(t)
	rec, token = openSignedRoot(t, a, "alice")
	open = readBytes(t, recordPath(dir, rec.ID))
	if _, _, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("alice"), alicesJudge); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	if err := os.Chmod(state, 0o500); err != nil { //nolint:gosec // G302: read and search only, so no close can be carried
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(state, 0o700) }) //nolint:gosec // G302: as the layout made it
	return dir, rec, token, open
}

func writable(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(filepath.Join(dir, "state"), 0o700); err != nil { //nolint:gosec // G302: as the layout made it
		t.Fatal(err)
	}
}

// TestACloseThePlaneFailedToCarryStillRefusesTheOpenRecord: the plane takes
// a closed record while state/ refuses the carried close; once state/ is
// writable again, the run's open record put back is refused as replayed by
// the same plane all the same.
func TestACloseThePlaneFailedToCarryStillRefusesTheOpenRecord(t *testing.T) {
	dir, rec, token, open := closedThenReadOnly(t)
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(2 * time.Minute)
	if _, err := p.Resolve(t.Context(), token, alice, at); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve of the closed record = %v, want closed", err)
	}
	if got := p.SignedCounts()["carry_failed"]; got != 1 {
		t.Fatalf("carry_failed = %d, want 1", got)
	}
	writable(t, dir)
	writeFile(t, recordPath(dir, rec.ID), open)
	_, err := p.Resolve(t.Context(), token, alice, at)
	if err == nil {
		t.Fatal("the open record put back after a close the plane failed to carry resolved")
	}
	if causeOf(t, err) != runs.CauseClosed || !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("Resolve of the open record put back = %v, want closed, ErrReplayed", err)
	}
	if _, err := p.Lookup(t.Context(), rec.ID); !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("Lookup of the open record put back = %v, want ErrReplayed", err)
	}
}

// TestAStartThatCannotCarryACloseRefuses: the survey a serving plane runs at
// its start fails, naming the run, when a close it takes cannot be carried,
// and the plane that ran it still refuses that run's open record put back.
func TestAStartThatCannotCarryACloseRefuses(t *testing.T) {
	dir, rec, token, open := closedThenReadOnly(t)
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(2 * time.Minute)
	_, err := p.CarryCloses(t.Context(), 100, at)
	if err == nil {
		t.Fatal("CarryCloses with a close it could not carry = nil, want an error naming the run")
	}
	if !strings.Contains(err.Error(), rec.ID) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("CarryCloses = %v, want the run %s and the write's own cause", err, rec.ID)
	}
	writable(t, dir)
	writeFile(t, recordPath(dir, rec.ID), open)
	if _, err := p.Resolve(t.Context(), token, alice, at); !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("Resolve of the open record put back = %v, want ErrReplayed", err)
	}
}
