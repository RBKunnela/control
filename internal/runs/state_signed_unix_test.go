//go:build unix

package runs_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

func statePath(dir, root string) string { return filepath.Join(dir, "state", root+".state.json") }

// TestARootsStateIsWrittenAtItsFirstAdmission: the plane writes a root's
// state and lock file the first time it admits a call of it, and nothing for
// a call it refuses.
func TestARootsStateIsWrittenAtItsFirstAdmission(t *testing.T) {
	dir, a := newSigned(t)
	rec, token := openSignedRoot(t, a, "alice")
	p := signedPlane(t, dir, alicesJudge)
	if _, err := p.Resolve(t.Context(), token, alice, opened.Add(2*time.Hour)); causeOf(t, err) != runs.CauseExpired {
		t.Fatalf("Resolve past expiry = %v, want expired", err)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "state")); err != nil || len(entries) != 0 {
		t.Fatalf("state/ after a refused call = %v, %v; want it empty", entries, err)
	}
	if _, err := p.Resolve(t.Context(), token, alice, opened.Add(time.Minute)); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, path := range []string{statePath(dir, rec.ID), filepath.Join(dir, "state", rec.ID+".lock")} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("after the first admission: %v", err)
		}
	}
	if s, err := p.State(t.Context(), rec.ID); err != nil || s.Untrusted {
		t.Errorf("State after the first admission = %+v, %v; want the initial state", s, err)
	}
}

// TestARemovedStateIsRefusedNotReadClean: once a root was admitted, its
// state removed from state/ is refused by State, Raise and a later call
// alike, never read as the clean start a root has before its first call.
func TestARemovedStateIsRefusedNotReadClean(t *testing.T) {
	dir, a := newSigned(t)
	rec, token := openSignedRoot(t, a, "alice")
	p := signedPlane(t, dir, alicesJudge)
	if _, err := p.Resolve(t.Context(), token, alice, opened.Add(time.Minute)); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := p.Raise(t.Context(), rec.ID, taint); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath(dir, rec.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Resolve(t.Context(), token, alice, opened.Add(2*time.Minute)); err != nil {
		t.Fatalf("Resolve after the removal: %v", err)
	}
	if s, err := p.State(t.Context(), rec.ID); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("State after the removal = %+v, %v; want refused", s, err)
	}
	if err := p.Raise(t.Context(), rec.ID, taint); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Raise after the removal = %v; want refused", err)
	}
	if _, err := os.Lstat(statePath(dir, rec.ID)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a state made again after the removal: %v", err)
	}
}

// standingJudge takes alice's records and refuses bob's as signed by an
// operator key who may no longer operate there.
var standingJudge = judgeFunc(func(_ context.Context, r runs.SignedRecord) (runs.SignedBy, error) {
	switch r.KeyID {
	case "key-alice":
		return runs.SignedBy{Subject: "alice", KeyID: r.KeyID}, nil
	case "key-bob":
		return runs.SignedBy{}, runs.ErrUnauthorized
	}
	return runs.SignedBy{}, runs.ErrUnauthenticated
})

// TestACloseByASignerNoLongerAuthorizedIsCarried: a close signed by an
// operator key of the roster for this directory is carried at the start and
// at a call even once its signer may no longer operate, so the open record
// put back stays refused as replayed.
func TestACloseByASignerNoLongerAuthorizedIsCarried(t *testing.T) {
	for _, atStart := range []bool{true, false} {
		dir, a := newSigned(t)
		rec, token := openSignedRoot(t, a, "alice")
		open := readBytes(t, recordPath(dir, rec.ID))
		if _, _, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("bob"), takeKey("alice", "bob")); err != nil {
			t.Fatal(err)
		}
		p := signedPlane(t, dir, standingJudge)
		at := opened.Add(2 * time.Minute)
		if atStart {
			s, err := p.CarryCloses(t.Context(), 100, at)
			if err != nil || s.Carried != 1 || s.Refused["unauthorized"] != 1 {
				t.Fatalf("CarryCloses = %+v, %v; want the close carried and its record refused", s, err)
			}
		} else if _, err := p.Resolve(t.Context(), token, alice, at); !errors.Is(err, runs.ErrUnauthorized) {
			t.Fatalf("Resolve of the closed record = %v, want ErrUnauthorized", err)
		}
		writeFile(t, recordPath(dir, rec.ID), open)
		_, err := p.Resolve(t.Context(), token, alice, at)
		if causeOf(t, err) != runs.CauseClosed || !errors.Is(err, runs.ErrReplayed) {
			t.Errorf("at start %v: Resolve of the open record put back = %v, want closed, ErrReplayed", atStart, err)
		}
	}
}
