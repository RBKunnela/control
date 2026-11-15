//go:build unix

package runs_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// TestRestoreSignedCarriesACloseOnlyTheBackupsStateHolds: a run's close was
// carried and its record removed before the backup, so the backup names the
// run only by state/<id>.closed. Once live's state/ is lost and restored, the
// run's old open record put back is refused as replayed.
func TestRestoreSignedCarriesACloseOnlyTheBackupsStateHolds(t *testing.T) {
	live, a := newSigned(t)
	rec, token := openSignedRoot(t, a, "alice")
	open := readBytes(t, recordPath(live, rec.ID))
	if _, _, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("alice"), alicesJudge); err != nil {
		t.Fatal(err)
	}
	if s, err := signedPlane(t, live, alicesJudge).CarryCloses(t.Context(), 100, opened.Add(2*time.Minute)); err != nil || s.Carried != 1 {
		t.Fatalf("CarryCloses = %+v, %v", s, err)
	}
	if err := os.Remove(recordPath(live, rec.ID)); err != nil {
		t.Fatal(err)
	}
	backup := copyTree(t, live)
	if err := os.Remove(filepath.Join(live, "state", rec.ID+".closed")); err != nil {
		t.Fatal(err)
	}
	got, err := runs.RestoreSigned(t.Context(), live, backup, nil)
	if err != nil {
		t.Fatalf("RestoreSigned: %v", err)
	}
	if got.Carried != 1 {
		t.Errorf("Restored = %+v, want the one close the backup's state/ holds carried", got)
	}
	writeFile(t, recordPath(live, rec.ID), open)
	_, err = signedPlane(t, live, alicesJudge).Resolve(t.Context(), token, alice, opened.Add(3*time.Minute))
	if !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("the open record put back after the restore: err = %v, want ErrReplayed", err)
	}
}
