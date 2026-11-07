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

// heldClose is a signed layout with an open run y whose root a plane already
// started, and a run x alice closed whose close that plane failed to carry
// while state/ was read-only; state/ is writable again on return.
func heldClose(t *testing.T) (dir string, p *runs.Plane, x runs.Record, xToken string, xOpen []byte, yToken string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the superuser writes a directory whatever its mode")
	}
	dir, a := newSigned(t)
	xRec, xTok := openSignedRoot(t, a, "alice")
	_, yToken = openSignedRoot(t, a, "alice")
	xOpen = readBytes(t, recordPath(dir, xRec.ID))
	p = signedPlane(t, dir, alicesJudge)
	at := opened.Add(2 * time.Minute)
	if _, err := p.Resolve(t.Context(), yToken, alice, at); err != nil {
		t.Fatalf("Resolve of y: %v", err)
	}
	if _, _, err := a.CloseSigned(t.Context(), xRec.ID, opened.Add(time.Minute), testSigner("alice"), alicesJudge); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	if err := os.Chmod(state, 0o500); err != nil { //nolint:gosec // G302: read and search only, so no close can be carried
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(state, 0o700) }) //nolint:gosec // G302: as the layout made it
	if _, err := p.Resolve(t.Context(), xTok, alice, at); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve of the closed x = %v, want closed", err)
	}
	if got := p.SignedCounts()["carry_failed"]; got != 1 {
		t.Fatalf("carry_failed = %d, want 1", got)
	}
	writable(t, dir)
	return dir, p, xRec, xTok, xOpen, yToken
}

func closeCarried(t *testing.T, dir, id string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(dir, "state", id+".closed"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// requireReplayRefusedAfterRestart puts x's open record back, starts a new
// plane as a serving one does, and requires the record refused as replayed.
func requireReplayRefusedAfterRestart(t *testing.T, dir string, x runs.Record, xToken string, xOpen []byte) {
	t.Helper()
	writeFile(t, recordPath(dir, x.ID), xOpen)
	at := opened.Add(3 * time.Minute)
	p2 := signedPlane(t, dir, alicesJudge)
	if _, err := p2.CarryCloses(t.Context(), 100, at); err != nil {
		t.Fatalf("the restarted plane's survey: %v", err)
	}
	if _, err := p2.Resolve(t.Context(), xToken, alice, at); !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("after a restart the open record of %s put back: err = %v, want ErrReplayed", x.ID, err)
	}
}

// TestAHeldCloseIsWrittenAtTheNextResolveOfAnyRun: once state/ takes writes
// again, the next resolve of another run writes the held close, so a plane
// started after the open record is put back refuses it.
func TestAHeldCloseIsWrittenAtTheNextResolveOfAnyRun(t *testing.T) {
	dir, p, x, xToken, xOpen, yToken := heldClose(t)
	if _, err := p.Resolve(t.Context(), yToken, alice, opened.Add(3*time.Minute)); err != nil {
		t.Fatalf("Resolve of y: %v", err)
	}
	if !closeCarried(t, dir, x.ID) {
		t.Fatalf("the close of %s is not in state/ after the next resolve", x.ID)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	requireReplayRefusedAfterRestart(t, dir, x, xToken, xOpen)
}

// TestAHeldCloseIsWrittenByTheSurvey: the open record is put back before
// anything resolves; the survey, which sees only that open record, writes
// the held close and refuses the record all the same.
func TestAHeldCloseIsWrittenByTheSurvey(t *testing.T) {
	dir, p, x, xToken, xOpen, _ := heldClose(t)
	writeFile(t, recordPath(dir, x.ID), xOpen)
	s, err := p.CarryCloses(t.Context(), 100, opened.Add(3*time.Minute))
	if err != nil || s.Refused["replayed"] != 1 {
		t.Fatalf("CarryCloses = %+v, %v; want x refused as replayed", s, err)
	}
	if !closeCarried(t, dir, x.ID) {
		t.Fatalf("the close of %s is not in state/ after the survey", x.ID)
	}
	if _, err := p.Resolve(t.Context(), xToken, alice, opened.Add(3*time.Minute)); !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("Resolve of the open record put back = %v, want ErrReplayed", err)
	}
}

// TestAHeldCloseIsWrittenWhenThePlaneCloses: nothing resolves between the
// open record put back and a restart; the plane's Close writes the held
// close, so the restarted plane refuses the record.
func TestAHeldCloseIsWrittenWhenThePlaneCloses(t *testing.T) {
	dir, p, x, xToken, xOpen, _ := heldClose(t)
	writeFile(t, recordPath(dir, x.ID), xOpen)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	requireReplayRefusedAfterRestart(t, dir, x, xToken, xOpen)
}

// TestAHeldCloseStateStillRefusesIsReported: while state/ still refuses the
// held close, the survey refuses the start and Close returns the error, each
// naming the run.
func TestAHeldCloseStateStillRefusesIsReported(t *testing.T) {
	dir, p, x, _, xOpen, _ := heldClose(t)
	writeFile(t, recordPath(dir, x.ID), xOpen)
	if err := os.Chmod(filepath.Join(dir, "state"), 0o500); err != nil { //nolint:gosec // G302: read and search only, so no close can be carried
		t.Fatal(err)
	}
	if _, err := p.CarryCloses(t.Context(), 100, opened.Add(3*time.Minute)); err == nil || !strings.Contains(err.Error(), x.ID) {
		t.Fatalf("CarryCloses with the close of %s held and state/ read-only = %v, want an error naming it", x.ID, err)
	}
	if err := p.Close(); err == nil || !strings.Contains(err.Error(), x.ID) {
		t.Fatalf("Close with the close of %s held and state/ read-only = %v, want an error naming it", x.ID, err)
	}
}
