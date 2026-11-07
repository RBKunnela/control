//go:build unix

package runs_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/runs"
)

const (
	unknown = controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED
	secret  = controlv1.Sensitivity_SENSITIVITY_SECRET
)

var restoredAt = time.Date(2026, time.March, 1, 12, 30, 0, 0, time.UTC)

// copyTree copies the directory from to a new path beside it, files and
// modes as they are, as a backup holds them.
func copyTree(t *testing.T, from string) string {
	t.Helper()
	to := filepath.Join(t.TempDir(), "copy")
	err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Mkdir(filepath.Join(to, rel), info.Mode().Perm())
		}
		raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), raw, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
	return to
}

func setState(t *testing.T, p *runs.Plane, root string, s runs.State) {
	t.Helper()
	if err := p.Raise(t.Context(), root, func(runs.State) runs.State { return s }); err != nil {
		t.Fatalf("Raise(%s): %v", root, err)
	}
}

func lookup(t *testing.T, dir, id string) runs.Record {
	t.Helper()
	rec, err := openAdmin(t, dir).Lookup(t.Context(), id)
	if err != nil {
		t.Fatalf("Lookup(%s): %v", id, err)
	}
	return rec
}

func stateOf(t *testing.T, dir, root string) runs.State {
	t.Helper()
	s, err := openPlane(t, dir).State(t.Context(), root)
	if err != nil {
		t.Fatalf("State(%s): %v", root, err)
	}
	return s
}

// TestRestoreUnsignedClosesEveryRunAndKeepsTheHigherTaint: a run the backup
// holds and live lost, and one only live holds, both end closed at the
// restore, and each root's state is not lower than either side's.
func TestRestoreUnsignedClosesEveryRunAndKeepsTheHigherTaint(t *testing.T) {
	live, a, p := setup(t)
	kept, keptToken := openRoot(t, a)
	lost, _ := openRoot(t, a)
	setState(t, p, kept.ID, runs.State{Untrusted: true, MaxRead: confidential})
	setState(t, p, lost.ID, runs.State{Untrusted: false, MaxRead: secret})
	backup := copyTree(t, live)
	setState(t, p, kept.ID, runs.State{Untrusted: false, MaxRead: secret})
	if err := os.Remove(filepath.Join(live, lost.ID+".run.json")); err != nil {
		t.Fatal(err)
	}
	later, laterToken := openRoot(t, a)

	got, err := runs.RestoreUnsigned(t.Context(), live, backup, restoredAt, nil)
	if err != nil {
		t.Fatalf("RestoreUnsigned: %v", err)
	}
	if got.Closed != 3 {
		t.Fatalf("closed %d records, want 3", got.Closed)
	}
	for _, id := range []string{kept.ID, lost.ID, later.ID} {
		if rec := lookup(t, live, id); !rec.ClosedAt.Equal(restoredAt) {
			t.Fatalf("%s closed at %v, want %v", id, rec.ClosedAt, restoredAt)
		}
	}
	for _, token := range []string{keptToken, laterToken} {
		if _, err := openPlane(t, live).Resolve(t.Context(), token, alice, restoredAt.Add(time.Minute)); err == nil {
			t.Fatal("a restored run resolved")
		}
	}
	if s := stateOf(t, live, kept.ID); s != (runs.State{Untrusted: true, MaxRead: secret}) {
		t.Fatalf("kept's state = %+v, want untrusted and SECRET", s)
	}
	if s := stateOf(t, live, lost.ID); s != (runs.State{Untrusted: false, MaxRead: secret}) {
		t.Fatalf("lost's state = %+v, want the backup's", s)
	}
}

func TestRestoreUnsignedKeepsAnEarlierClose(t *testing.T) {
	live, a, _ := setup(t)
	rec, _ := openRoot(t, a)
	backup := copyTree(t, live)
	closedAt := opened.Add(10 * time.Minute)
	if err := a.CloseRun(t.Context(), rec.ID, closedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.RestoreUnsigned(t.Context(), live, backup, restoredAt, nil); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, live, rec.ID); !got.ClosedAt.Equal(closedAt) {
		t.Fatalf("closed at %v, want the earlier close %v", got.ClosedAt, closedAt)
	}
}

// TestRestoreUnsignedKeepsTheBackupsClose: a close only the backup holds is
// kept over a live copy that holds the run open.
func TestRestoreUnsignedKeepsTheBackupsClose(t *testing.T) {
	live, a, _ := setup(t)
	rec, _ := openRoot(t, a)
	stillOpen := copyTree(t, live)
	closedAt := opened.Add(10 * time.Minute)
	if err := a.CloseRun(t.Context(), rec.ID, closedAt); err != nil {
		t.Fatal(err)
	}
	backup := copyTree(t, live)
	if err := os.RemoveAll(live); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(stillOpen, live); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, live, rec.ID); got.Closed() {
		t.Fatal("the live copy holds the run closed; nothing is examined")
	}
	if _, err := runs.RestoreUnsigned(t.Context(), live, backup, restoredAt, nil); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, live, rec.ID); !got.ClosedAt.Equal(closedAt) {
		t.Fatalf("closed at %v, want the backup's close %v", got.ClosedAt, closedAt)
	}
}

func TestRestoreUnsignedBuildsALostDirectory(t *testing.T) {
	live, a, p := setup(t)
	rec, _ := openRoot(t, a)
	setState(t, p, rec.ID, runs.State{Untrusted: true, MaxRead: public})
	backup := copyTree(t, live)
	if err := os.RemoveAll(live); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.RestoreUnsigned(t.Context(), live, backup, restoredAt, nil); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, live, rec.ID); !got.Closed() {
		t.Fatal("the restored run is open")
	}
	if s := stateOf(t, live, rec.ID); s != (runs.State{Untrusted: true, MaxRead: public}) {
		t.Fatalf("state = %+v", s)
	}
}

// TestRestoreUnsignedTakesALostStateAsTheWorst: a root whose state file is
// gone beside its record has taken in anything, as far as a restore knows.
func TestRestoreUnsignedTakesALostStateAsTheWorst(t *testing.T) {
	live, a, _ := setup(t)
	rec, _ := openRoot(t, a)
	if err := os.Remove(filepath.Join(live, rec.ID+".state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.RestoreUnsigned(t.Context(), live, "", restoredAt, nil); err != nil {
		t.Fatal(err)
	}
	if s := stateOf(t, live, rec.ID); s != (runs.State{Untrusted: true, MaxRead: unknown}) {
		t.Fatalf("state = %+v, want untrusted and unknown", s)
	}
}

func TestRestoreUnsignedRefusesTwoHistoriesBeforeWriting(t *testing.T) {
	live, a, _ := setup(t)
	rec, _ := openRoot(t, a)
	backup := copyTree(t, live)
	rewrite(t, backup, rec.ID+".run.json", func(m map[string]json.RawMessage) {
		m["secret_sha256"] = json.RawMessage(`"` + strings.Repeat("0", 64) + `"`)
	})
	before := readBytes(t, filepath.Join(live, rec.ID+".run.json"))
	if _, err := runs.RestoreUnsigned(t.Context(), live, backup, restoredAt, nil); !errors.Is(err, runs.ErrTwoHistories) {
		t.Fatalf("err = %v, want ErrTwoHistories", err)
	}
	if after := readBytes(t, filepath.Join(live, rec.ID+".run.json")); string(after) != string(before) {
		t.Fatal("a refused restore rewrote the record")
	}
}

func TestRestoreUnsignedRefusesASignedLayout(t *testing.T) {
	signed, _ := newSigned(t)
	live, _, _ := setup(t)
	if _, err := runs.RestoreUnsigned(t.Context(), live, signed, restoredAt, nil); !errors.Is(err, runs.ErrLayout) {
		t.Fatalf("a signed backup: err = %v, want ErrLayout", err)
	}
	if _, err := runs.RestoreUnsigned(t.Context(), signed, "", restoredAt, nil); !errors.Is(err, runs.ErrLayout) {
		t.Fatalf("a signed live: err = %v, want ErrLayout", err)
	}
}

// TestRestoreSignedRefusesTheOpenRecordPutBack: a record the backup holds
// open, put back into records/ after the restore, is refused by the plane's
// replay check, and a state lost beside its lock file joins as the worst.
func TestRestoreSignedRefusesTheOpenRecordPutBack(t *testing.T) {
	live, a := newSigned(t)
	rec, token := openSignedRoot(t, a, "alice")
	setState(t, signedPlane(t, live, alicesJudge), rec.ID, runs.State{Untrusted: true, MaxRead: confidential})
	backup := copyTree(t, live)
	saved := readBytes(t, recordPath(live, rec.ID))
	if err := os.Remove(recordPath(live, rec.ID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(live, "state", rec.ID+".state.json")); err != nil {
		t.Fatal(err)
	}
	got, err := runs.RestoreSigned(t.Context(), live, backup, nil)
	if err != nil {
		t.Fatalf("RestoreSigned: %v", err)
	}
	if got.Carried != 1 || got.States != 1 {
		t.Fatalf("Restored = %+v, want one close carried and one state", got)
	}
	writeFile(t, recordPath(live, rec.ID), saved)
	p := signedPlane(t, live, alicesJudge)
	if _, err := p.Resolve(t.Context(), token, alice, opened.Add(time.Minute)); !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("the open record put back: err = %v, want ErrReplayed", err)
	}
	if s, err := p.State(t.Context(), rec.ID); err != nil || s != (runs.State{Untrusted: true, MaxRead: unknown}) {
		t.Fatalf("state = %+v, %v, want untrusted and unknown", s, err)
	}
}

// TestRestoreSignedTakesALostStateAsTheWorst: live's state of a root is
// gone while its lock file or its record stays, so the plane refuses it;
// a restore never turns it into the backup's lower taint.
func TestRestoreSignedTakesALostStateAsTheWorst(t *testing.T) {
	for _, kept := range []string{"lock", "record"} {
		t.Run(kept, func(t *testing.T) {
			live, a := newSigned(t)
			rec, _ := openSignedRoot(t, a, "alice")
			setState(t, signedPlane(t, live, alicesJudge), rec.ID, runs.State{Untrusted: false, MaxRead: confidential})
			backup := copyTree(t, live)
			setState(t, signedPlane(t, live, alicesJudge), rec.ID, runs.State{Untrusted: true, MaxRead: secret})
			lost := []string{filepath.Join(live, "state", rec.ID+".state.json")}
			if kept == "record" {
				lost = append(lost, filepath.Join(live, "state", rec.ID+".lock"))
			} else {
				lost = append(lost, recordPath(live, rec.ID))
			}
			for _, path := range lost {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := runs.RestoreSigned(t.Context(), live, backup, nil); err != nil {
				t.Fatalf("RestoreSigned: %v", err)
			}
			s, err := signedPlane(t, live, alicesJudge).State(t.Context(), rec.ID)
			if err != nil || s != (runs.State{Untrusted: true, MaxRead: unknown}) {
				t.Fatalf("state = %+v, %v, want untrusted and unknown", s, err)
			}
		})
	}
}

// TestRestoreSignedStartsARootLiveNeverHeldFromTheBackup: a root live holds
// no record, state or lock file of is the backup's, not the worst.
func TestRestoreSignedStartsARootLiveNeverHeldFromTheBackup(t *testing.T) {
	live, a := newSigned(t)
	rec, _ := openSignedRoot(t, a, "alice")
	setState(t, signedPlane(t, live, alicesJudge), rec.ID, runs.State{Untrusted: false, MaxRead: confidential})
	backup := copyTree(t, live)
	for _, path := range []string{recordPath(live, rec.ID), filepath.Join(live, "state", rec.ID+".state.json"), filepath.Join(live, "state", rec.ID+".lock")} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := runs.RestoreSigned(t.Context(), live, backup, nil); err != nil {
		t.Fatalf("RestoreSigned: %v", err)
	}
	if s, err := signedPlane(t, live, alicesJudge).State(t.Context(), rec.ID); err != nil || s != (runs.State{Untrusted: false, MaxRead: confidential}) {
		t.Fatalf("state = %+v, %v, want the backup's", s, err)
	}
}

// TestRestoreSignedClosesARunOnlyLiveRecords: a run opened after the backup,
// whose record only live's records/ holds, is closed by the restore.
func TestRestoreSignedClosesARunOnlyLiveRecords(t *testing.T) {
	live, a := newSigned(t)
	openSignedRoot(t, a, "alice")
	backup := copyTree(t, live)
	later, token := openSignedRoot(t, a, "alice")
	got, err := runs.RestoreSigned(t.Context(), live, backup, nil)
	if err != nil {
		t.Fatalf("RestoreSigned: %v", err)
	}
	if got.Carried != 2 {
		t.Fatalf("Restored = %+v, want two closes carried", got)
	}
	if _, err := os.Lstat(filepath.Join(live, "state", later.ID+".closed")); err != nil {
		t.Fatalf("the close of the run only live records: %v", err)
	}
	if _, err := signedPlane(t, live, alicesJudge).Resolve(t.Context(), token, alice, opened.Add(time.Minute)); !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("the run only live records: err = %v, want ErrReplayed", err)
	}
}

func TestCarryClosedRefusesABadIDBeforeWriting(t *testing.T) {
	live, a := newSigned(t)
	rec, _ := openSignedRoot(t, a, "alice")
	if err := runs.CarryClosed(live, []string{rec.ID, "run-not-hex"}); !errors.Is(err, runs.ErrRunID) {
		t.Fatalf("err = %v, want ErrRunID", err)
	}
	if _, err := os.Lstat(filepath.Join(live, "state", rec.ID+".closed")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused carry wrote a close: %v", err)
	}
	if err := runs.CarryClosed(live, []string{rec.ID}); err != nil {
		t.Fatal(err)
	}
	if err := runs.CarryClosed(live, []string{rec.ID}); err != nil {
		t.Fatalf("a close carried twice: %v", err)
	}
}

// TestJoinStatesNeverLowers holds the join to an order computed apart from
// it, over every pair of states.
func TestJoinStatesNeverLowers(t *testing.T) {
	rank := map[controlv1.Sensitivity]int{public: 1, controlv1.Sensitivity_SENSITIVITY_INTERNAL: 2, confidential: 3,
		controlv1.Sensitivity_SENSITIVITY_RESTRICTED: 4, secret: 5, unknown: 6}
	var all []runs.State
	for s := range rank {
		all = append(all, runs.State{Untrusted: false, MaxRead: s}, runs.State{Untrusted: true, MaxRead: s})
	}
	for _, x := range all {
		for _, y := range all {
			j := runs.JoinStates(x, y)
			if j.Untrusted != (x.Untrusted || y.Untrusted) {
				t.Fatalf("JoinStates(%+v, %+v).Untrusted = %v", x, y, j.Untrusted)
			}
			if rank[j.MaxRead] != max(rank[x.MaxRead], rank[y.MaxRead]) {
				t.Fatalf("JoinStates(%+v, %+v).MaxRead = %v", x, y, j.MaxRead)
			}
		}
	}
}
