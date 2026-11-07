//go:build unix

package runs_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/runs"
)

// testSigner signs with a key drawn from a fixed seed. The judges of these
// tests read who signed from the record's key id; whether the signature
// verifies is internal/runs/signedruns' to test.
func testSigner(name string) runs.Signer {
	seed := sha256.Sum256([]byte("runs-test/" + name))
	key := ed25519.NewKeyFromSeed(seed[:])
	return runs.Signer{KeyID: "key-" + name, Sign: func(_ string, body []byte) ([]byte, error) {
		return ed25519.Sign(key, body), nil
	}}
}

// judgeFunc is a judge of these tests.
type judgeFunc func(context.Context, runs.SignedRecord) (runs.SignedBy, error)

func (f judgeFunc) Judge(ctx context.Context, r runs.SignedRecord) (runs.SignedBy, error) {
	return f(ctx, r)
}

// takeKey takes a record signed by the key of one of names and refuses any
// other with ErrUnauthenticated.
func takeKey(names ...string) runs.Judge {
	return judgeFunc(func(_ context.Context, r runs.SignedRecord) (runs.SignedBy, error) {
		for _, name := range names {
			if r.KeyID == "key-"+name && len(r.Envelope.Signatures) == 1 && r.Envelope.Signatures[0].KeyID == r.KeyID {
				return runs.SignedBy{Subject: name, KeyID: r.KeyID}, nil
			}
		}
		return runs.SignedBy{}, runs.ErrUnauthenticated
	})
}

var alicesJudge = takeKey("alice")

// ownedHere opens a signed layout as alice's judge, with records/ this
// test's own account's, as a plane on the operator's one account reads it.
var ownedHere = runs.SignedOptions{Judge: alicesJudge, PlaneOwned: true}

// newSigned is a signed layout opened for the operator, and its directory.
func newSigned(t *testing.T) (string, *runs.Admin) {
	t.Helper()
	dir := newDir(t)
	a, err := runs.InitSignedAdmin(t.Context(), dir)
	if err != nil {
		t.Fatalf("InitSignedAdmin: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return dir, a
}

func signedPlane(t *testing.T, dir string, j runs.Judge) *runs.Plane {
	t.Helper()
	p, err := runs.OpenSignedPlane(dir, runs.SignedOptions{Judge: j, PlaneOwned: true})
	if err != nil {
		t.Fatalf("OpenSignedPlane: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func openSignedRoot(t *testing.T, a *runs.Admin, signer string) (runs.Record, string) {
	t.Helper()
	rec, token, err := a.OpenSigned(t.Context(), runs.OpenRequest{Who: alice, TTL: time.Hour, Now: opened}, testSigner(signer), takeKey(signer))
	if err != nil {
		t.Fatalf("OpenSigned: %v", err)
	}
	return rec, token
}

func recordPath(dir, id string) string { return filepath.Join(dir, "records", id+".run.json") }

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestASignedRecordOpensARunTheJudgeTakes: a record opened with a signer
// resolves on a plane whose judge takes its signer, and the plane counts it.
func TestASignedRecordOpensARunTheJudgeTakes(t *testing.T) {
	dir, a := newSigned(t)
	rec, token := openSignedRoot(t, a, "alice")
	p := signedPlane(t, dir, alicesJudge)
	run, err := p.Resolve(t.Context(), token, alice, opened.Add(time.Minute))
	if err != nil || run.ID != rec.ID || run.Root != rec.ID {
		t.Fatalf("Resolve = %+v, %v", run, err)
	}
	if got := p.SignedCounts()["judged"]; got != 1 {
		t.Errorf("judged = %d, want 1", got)
	}
	if !strings.Contains(string(readBytes(t, recordPath(dir, rec.ID))), `"payloadType":"`+runs.RecordPayloadType+`"`) {
		t.Errorf("the record is not a signed envelope")
	}
}

// TestARecordTheJudgeRefusesOpensNothing: a record of a signer the judge does
// not take, read where no judge was given, or one that is not signed at all,
// refuses its call as unreadable with its cause, after the secret is shown
// right, and is counted by that cause.
func TestARecordTheJudgeRefusesOpensNothing(t *testing.T) {
	dir, a := newSigned(t)
	_, token := openSignedRoot(t, a, "mallory")
	for name, c := range map[string]struct {
		j     runs.Judge
		want  error
		label string
	}{
		"another signer": {alicesJudge, runs.ErrUnauthenticated, "unauthenticated"},
		"no judge":       {nil, runs.ErrUnjudged, "unjudged"},
	} {
		p := signedPlane(t, dir, c.j)
		_, err := p.Resolve(t.Context(), token, alice, opened.Add(time.Minute))
		if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, c.want) {
			t.Errorf("%s: Resolve = %v, want unreadable and %v", name, err, c.want)
		}
		if got := p.SignedCounts()["refused_"+c.label]; got != 1 {
			t.Errorf("%s: refused_%s = %d, want 1", name, c.label, got)
		}
	}
	p := signedPlane(t, dir, takeKey("mallory"))
	if _, err := p.Resolve(t.Context(), token, alice, opened.Add(time.Minute)); err != nil {
		t.Fatalf("the same record under a judge that takes it: %v", err)
	}
}

// TestAnUnsignedRecordIsRefusedInASignedLayout: a record of major 2, which
// an unsigned directory reads, put into records/ is refused as unsigned.
func TestAnUnsignedRecordIsRefusedInASignedLayout(t *testing.T) {
	flat, fa, _ := setup(t)
	rec, token := openRoot(t, fa)
	dir, _ := newSigned(t)
	writeFile(t, recordPath(dir, rec.ID), readBytes(t, filepath.Join(flat, rec.ID+".run.json")))
	p := signedPlane(t, dir, alicesJudge)
	_, err := p.Resolve(t.Context(), token, alice, opened.Add(time.Minute))
	if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, runs.ErrUnsigned) {
		t.Fatalf("Resolve of a 2.0 record in records/ = %v, want unreadable, ErrUnsigned", err)
	}
	if _, err := p.Lookup(t.Context(), rec.ID); !errors.Is(err, runs.ErrUnsigned) {
		t.Errorf("Lookup = %v, want ErrUnsigned", err)
	}
}

// TestARecordSignedForAnotherDirectoryIsRefused: two signed layouts of one
// tenant and project; a record copied from one into the other is refused by
// the second's plane however its signer stands, and still resolves where it
// was signed for.
func TestARecordSignedForAnotherDirectoryIsRefused(t *testing.T) {
	dirA, a := newSigned(t)
	dirB, _ := newSigned(t)
	rec, token := openSignedRoot(t, a, "alice")
	raw := readBytes(t, recordPath(dirA, rec.ID))
	if err := os.WriteFile(recordPath(dirB, rec.ID), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := signedPlane(t, dirB, alicesJudge).Resolve(t.Context(), token, alice, opened.Add(time.Minute))
	if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, runs.ErrOtherDirectory) {
		t.Fatalf("Resolve in another directory = %v, want unreadable, ErrOtherDirectory", err)
	}
	if _, err := signedPlane(t, dirA, alicesJudge).Resolve(t.Context(), token, alice, opened.Add(time.Minute)); err != nil {
		t.Fatalf("Resolve where it was signed: %v", err)
	}
}

// TestTheOpenRecordPutBackAfterItsCloseIsRefused: a plane that took the
// closed record carries the close into state/, so the open record written
// back over it is refused as closed and replayed, and is counted so.
func TestTheOpenRecordPutBackAfterItsCloseIsRefused(t *testing.T) {
	dir, a := newSigned(t)
	rec, token := openSignedRoot(t, a, "alice")
	open := readBytes(t, recordPath(dir, rec.ID))
	if _, _, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("alice"), alicesJudge); err != nil {
		t.Fatal(err)
	}
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(2 * time.Minute)
	if _, err := p.Resolve(t.Context(), token, alice, at); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve after the close = %v, want closed", err)
	}
	writeFile(t, recordPath(dir, rec.ID), open)
	_, err := p.Resolve(t.Context(), token, alice, at)
	if causeOf(t, err) != runs.CauseClosed || !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("Resolve of the open record put back = %v, want closed, ErrReplayed", err)
	}
	if _, err := p.Lookup(t.Context(), rec.ID); !errors.Is(err, runs.ErrReplayed) {
		t.Errorf("Lookup of the open record put back = %v, want ErrReplayed", err)
	}
	counts := p.SignedCounts()
	if counts["closes_carried"] != 1 || counts["refused_replayed"] != 2 {
		t.Errorf("counts = %v, want one close carried and two replays refused", counts)
	}
	if _, err := os.Lstat(filepath.Join(dir, "state", rec.ID+".closed")); err != nil {
		t.Errorf("the carried close: %v", err)
	}
}

// TestAStartCarriesTheClosesNoCallSaw: a run closed while no plane resolved
// it is closed for a plane that carried the closes at its start, and the open
// record put back is refused; a record the judge does not take is counted
// and carries nothing.
func TestAStartCarriesTheClosesNoCallSaw(t *testing.T) {
	dir, a := newSigned(t)
	rec, token := openSignedRoot(t, a, "alice")
	open := readBytes(t, recordPath(dir, rec.ID))
	if _, _, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("alice"), alicesJudge); err != nil {
		t.Fatal(err)
	}
	other, _ := openSignedRoot(t, a, "mallory")
	if _, _, err := a.CloseSigned(t.Context(), other.ID, opened.Add(time.Minute), testSigner("mallory"), takeKey("mallory")); err != nil {
		t.Fatal(err)
	}
	p := signedPlane(t, dir, alicesJudge)
	s, err := p.CarryCloses(t.Context(), 100, opened.Add(2*time.Minute))
	if err != nil || s.Carried != 1 || s.Closed != 1 || s.Refused["unauthenticated"] != 1 || !s.Complete {
		t.Fatalf("CarryCloses = %+v, %v", s, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "state", other.ID+".closed")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a close the judge refused was carried: %v", err)
	}
	writeFile(t, recordPath(dir, rec.ID), open)
	_, err = p.Resolve(t.Context(), token, alice, opened.Add(2*time.Minute))
	if causeOf(t, err) != runs.CauseClosed || !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("Resolve of the open record put back = %v, want closed, ErrReplayed", err)
	}
}

// TestInspectWritesNothing: Inspect reads what CarryCloses would, and leaves
// state/ as it was.
func TestInspectWritesNothing(t *testing.T) {
	dir, a := newSigned(t)
	rec, _ := openSignedRoot(t, a, "alice")
	if _, _, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("alice"), alicesJudge); err != nil {
		t.Fatal(err)
	}
	openSignedRoot(t, a, "alice")
	s, err := signedPlane(t, dir, alicesJudge).Inspect(t.Context(), 100, opened.Add(2*time.Minute))
	if err != nil || s.Records != 2 || s.Closed != 1 || s.Open != 1 || s.Carried != 0 || s.Signers["alice"] != 2 {
		t.Fatalf("Inspect = %+v, %v", s, err)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "state")); err != nil || len(entries) != 0 {
		t.Errorf("state/ after Inspect = %v, %v; want it empty", entries, err)
	}
}

// TestInspectStopsAtItsBound: a bound under the records read says the read
// is incomplete.
func TestInspectStopsAtItsBound(t *testing.T) {
	dir, a := newSigned(t)
	openSignedRoot(t, a, "alice")
	openSignedRoot(t, a, "alice")
	if s, err := signedPlane(t, dir, alicesJudge).Inspect(t.Context(), 1, opened); err != nil || s.Complete || s.Records != 1 {
		t.Errorf("Inspect bound 1 = %+v, %v; want one record, incomplete", s, err)
	}
	if s, err := signedPlane(t, dir, alicesJudge).Inspect(t.Context(), 2, opened); err != nil || !s.Complete || s.Records != 2 {
		t.Errorf("Inspect bound 2 = %+v, %v; want both, complete", s, err)
	}
}

// TestASignedCommandVerifiesWhatItSignsOver: a close and a child's opening
// read a record and sign over what it holds, so each refuses a record its
// judge does not take and writes nothing; an opening also refuses to write a
// record its judge would not take.
func TestASignedCommandVerifiesWhatItSignsOver(t *testing.T) {
	dir, a := newSigned(t)
	rec, _ := openSignedRoot(t, a, "mallory")
	before := readBytes(t, recordPath(dir, rec.ID))
	if _, _, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("alice"), alicesJudge); !errors.Is(err, runs.ErrUnauthenticated) {
		t.Errorf("CloseSigned over another signer's record = %v, want ErrUnauthenticated", err)
	}
	if _, _, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("alice"), nil); !errors.Is(err, runs.ErrUnjudged) {
		t.Errorf("CloseSigned with no judge = %v, want ErrUnjudged", err)
	}
	_, _, err := a.OpenSigned(t.Context(), runs.OpenRequest{Who: alice, Parent: rec.ID, TTL: time.Minute, Now: opened},
		testSigner("alice"), alicesJudge)
	if !errors.Is(err, runs.ErrUnauthenticated) {
		t.Errorf("OpenSigned under another signer's parent = %v, want ErrUnauthenticated", err)
	}
	if _, _, err := a.OpenSigned(t.Context(), runs.OpenRequest{Who: alice, TTL: time.Minute, Now: opened}, testSigner("mallory"), alicesJudge); !errors.Is(err, runs.ErrUnauthenticated) {
		t.Errorf("OpenSigned of a record its judge refuses = %v, want ErrUnauthenticated", err)
	}
	if got := readBytes(t, recordPath(dir, rec.ID)); string(got) != string(before) {
		t.Errorf("the refused close rewrote the record")
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "records")); len(entries) != 2 {
		t.Errorf("records/ holds %d entries after the refusals, want the marker and one record", len(entries))
	}
	closed, by, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("alice"), takeKey("mallory", "alice"))
	if err != nil || !closed.Closed() || by.Subject != "mallory" {
		t.Fatalf("CloseSigned under a judge that takes the record = %+v, %+v, %v", closed, by, err)
	}
}

// TestALayoutIsWrittenOnlyAsItIs: an unsigned write to a signed layout is
// refused naming the signature it needs, a signed one to an unsigned
// directory is refused, and each plane opener refuses the other layout.
func TestALayoutIsWrittenOnlyAsItIs(t *testing.T) {
	dir, a := newSigned(t)
	if _, _, err := a.Open(t.Context(), runs.OpenRequest{Who: alice, TTL: time.Hour, Now: opened}); !errors.Is(err, runs.ErrSigned) {
		t.Errorf("Open on a signed layout = %v, want ErrSigned", err)
	}
	rec, _ := openSignedRoot(t, a, "alice")
	if err := a.CloseRun(t.Context(), rec.ID, opened.Add(time.Minute)); !errors.Is(err, runs.ErrSigned) {
		t.Errorf("CloseRun on a signed layout = %v, want ErrSigned", err)
	}
	if _, err := runs.OpenPlane(dir); !errors.Is(err, runs.ErrLayout) {
		t.Errorf("OpenPlane of a signed layout = %v, want ErrLayout", err)
	}
	if opened, err := runs.OpenAdmin(t.Context(), dir); err != nil || !opened.Signed() {
		t.Errorf("OpenAdmin of a signed layout = signed %v, %v", opened.Signed(), err)
	} else {
		_ = opened.Close()
	}
	flat, fa, _ := setup(t)
	if _, _, err := fa.OpenSigned(t.Context(), runs.OpenRequest{Who: alice, TTL: time.Hour, Now: opened}, testSigner("alice"), alicesJudge); !errors.Is(err, runs.ErrLayout) {
		t.Errorf("OpenSigned on an unsigned directory = %v, want ErrLayout", err)
	}
	if _, err := runs.OpenSignedPlane(flat, ownedHere); !errors.Is(err, runs.ErrLayout) {
		t.Errorf("OpenSignedPlane of an unsigned directory = %v, want ErrLayout", err)
	}
	openRoot(t, fa)
	if _, err := runs.InitSignedAdmin(t.Context(), flat); !errors.Is(err, runs.ErrLayout) {
		t.Errorf("InitSignedAdmin of a directory of unsigned runs = %v, want ErrLayout", err)
	}
}

// TestASignedLayoutHoldsOnlyItsTwoDirectories: anything beside records/ and
// state/ refuses the plane, and so does a missing state/.
func TestASignedLayoutHoldsOnlyItsTwoDirectories(t *testing.T) {
	dir, _ := newSigned(t)
	writeFile(t, filepath.Join(dir, "notes"), []byte("x"))
	if _, err := runs.OpenSignedPlane(dir, ownedHere); !errors.Is(err, runs.ErrForeignFile) {
		t.Errorf("a file beside records/ = %v, want ErrForeignFile", err)
	}
	if err := os.Remove(filepath.Join(dir, "notes")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "state")); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.OpenSignedPlane(dir, ownedHere); !errors.Is(err, runs.ErrLayout) {
		t.Errorf("no state/ = %v, want ErrLayout", err)
	}
}

// TestThePlaneWritesItsStateInStateOnly: under a umask that narrows
// everything, a root's state starts clean, its first raise makes its lock and
// state in state/ for this user alone, and records/ and its record stay
// readable by their group.
func TestThePlaneWritesItsStateInStateOnly(t *testing.T) {
	old := syscall.Umask(0o077)
	dir, a := newSigned(t)
	rec, _ := openSignedRoot(t, a, "alice")
	syscall.Umask(old)
	p := signedPlane(t, dir, alicesJudge)
	if s, err := p.State(t.Context(), rec.ID); err != nil || s.Untrusted || s.MaxRead != controlv1.Sensitivity_SENSITIVITY_PUBLIC {
		t.Fatalf("State before any raise = %+v, %v", s, err)
	}
	if err := p.Raise(t.Context(), rec.ID, taint); err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if s, err := p.State(t.Context(), rec.ID); err != nil || !s.Untrusted {
		t.Fatalf("State after the raise = %+v, %v", s, err)
	}
	for path, want := range map[string]fs.FileMode{
		filepath.Join(dir, "records"):                     0o750,
		recordPath(dir, rec.ID):                           0o640,
		filepath.Join(dir, "records", "runs.meta"):        0o640,
		filepath.Join(dir, "state"):                       0o700,
		filepath.Join(dir, "state", rec.ID+".state.json"): 0o600,
		filepath.Join(dir, "state", rec.ID+".lock"):       0o600,
	} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: %v, %v; want mode %04o", path, info, err, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "records", rec.ID+".state.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a state in records/: %v", err)
	}
}

// TestAStateDirectoryAnotherUserOwnsIsRefused: state/ is the plane's own,
// while records/ may be another account's.
func TestAStateDirectoryAnotherUserOwnsIsRefused(t *testing.T) {
	dir, _ := newSigned(t)
	restore := runs.SetEffectiveUID(func() int { return os.Geteuid() + 1 })
	_, err := runs.OpenSignedPlane(dir, ownedHere)
	restore()
	if !errors.Is(err, runs.ErrOwner) || !strings.Contains(err.Error(), "state") {
		t.Fatalf("OpenSignedPlane with state/ another user's = %v, want ErrOwner naming state/", err)
	}
}

// TestPruneOverTheSplitRemovesRecordsOnly: an expired signed tree goes from
// records/ into the archive, and the plane's state of it stays in state/.
func TestPruneOverTheSplitRemovesRecordsOnly(t *testing.T) {
	dir, a := newSigned(t)
	rec, _ := openSignedRoot(t, a, "alice")
	child, _, err := a.OpenSigned(t.Context(), runs.OpenRequest{Who: alice, Parent: rec.ID, TTL: time.Minute, Now: opened}, testSigner("alice"), alicesJudge)
	if err != nil {
		t.Fatal(err)
	}
	if err := signedPlane(t, dir, alicesJudge).Raise(t.Context(), rec.ID, taint); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "archive")
	cut := opened.Add(2 * time.Hour)
	got, err := a.Prune(t.Context(), runs.PruneRequest{ExpiredBefore: cut, Archive: archive, Now: cut})
	if err != nil || len(got.Trees) != 1 || got.Runs != 2 || len(got.Refused) != 0 {
		t.Fatalf("Prune = %+v, %v", got, err)
	}
	for _, id := range []string{rec.ID, child.ID} {
		if _, err := os.Lstat(recordPath(dir, id)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("record %s after the prune: %v", id, err)
		}
		if _, err := os.Lstat(filepath.Join(archive, id+".run.json")); err != nil {
			t.Errorf("record %s in the archive: %v", id, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "state", rec.ID+".state.json")); err != nil {
		t.Errorf("the plane's state after the prune: %v", err)
	}
	if _, err := a.Prune(t.Context(), runs.PruneRequest{ExpiredBefore: cut, Archive: filepath.Join(dir, "archive"), Now: cut}); !errors.Is(err, runs.ErrArchive) {
		t.Errorf("an archive beside records/ = %v, want ErrArchive", err)
	}
}

// TestALongestSignedRecordFitsItsBound: a record at every identity bound,
// under the longest records/ path, is signed and read back.
func TestALongestSignedRecordFitsItsBound(t *testing.T) {
	dir := resolvedTempDir(t)
	for left := runs.MaxRecordsPathBytes - len(dir) - len("/records"); left > 1; {
		n := min(left-1, 100)
		dir = filepath.Join(dir, strings.Repeat("d", n))
		left -= n + 1
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := len(dir) + len("/records"); got < runs.MaxRecordsPathBytes-1 {
		t.Fatalf("records/ is %d bytes, want the bound %d", got, runs.MaxRecordsPathBytes)
	}
	a, err := runs.InitSignedAdmin(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	long := strings.Repeat("x", runs.MaxIdentityBytes)
	who := runs.Identity{ProjectID: long, TenantID: long, PrincipalType: long, PrincipalID: long, AgentID: long}
	rec, _, err := a.OpenSigned(t.Context(), runs.OpenRequest{Who: who, TTL: time.Hour, Now: opened}, testSigner("alice"), alicesJudge)
	if err != nil {
		t.Fatalf("OpenSigned at every bound: %v", err)
	}
	a.JudgeWith(alicesJudge)
	if got, err := a.Lookup(t.Context(), rec.ID); err != nil || got.Who != who {
		t.Fatalf("Lookup = %+v, %v", got, err)
	}
}

// TestARecordsPathPastItsBoundIsRefused: a records/ one byte past the bound
// a signed record may name is refused before anything is signed.
func TestARecordsPathPastItsBoundIsRefused(t *testing.T) {
	dir := resolvedTempDir(t)
	for target := runs.MaxRecordsPathBytes + 1 - len("/records"); len(dir) < target; {
		dir = filepath.Join(dir, strings.Repeat("d", max(1, min(100, target-len(dir)-1))))
	}
	if got := len(dir) + len("/records"); got <= runs.MaxRecordsPathBytes {
		t.Fatalf("records/ is %d bytes, want past the bound %d", got, runs.MaxRecordsPathBytes)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.InitSignedAdmin(t.Context(), dir); !errors.Is(err, runs.ErrMalformed) {
		t.Fatalf("InitSignedAdmin past the bound = %v, want ErrMalformed", err)
	}
}

// TestARecordIsReadAsTheRecordsOwnersWhoeverThePlaneIs: a plane reads
// records/ as the account that owns it, so a plane of another user reads a
// record that account wrote.
func TestARecordIsReadAsTheRecordsOwnersWhoeverThePlaneIs(t *testing.T) {
	dir, a := newSigned(t)
	rec, _ := openSignedRoot(t, a, "alice")
	p := signedPlane(t, dir, alicesJudge)
	restore := runs.SetEffectiveUID(func() int { return os.Geteuid() + 1 })
	_, err := p.Lookup(t.Context(), rec.ID)
	restore()
	if err != nil {
		t.Fatalf("Lookup by a plane of another user = %v", err)
	}
}

// resolvedTempDir is a temporary directory with every link on its path
// resolved, as a signed record names it.
func resolvedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestRecordsThePlanesOwnAccountOwnsAreRefused: a plane that does not let
// its own account own records/ refuses to open one it owns, before it reads
// anything there, and refuses a record it owns at the read, counted by that
// cause; the control, the same directory opened with PlaneOwned, resolves
// the run.
func TestRecordsThePlanesOwnAccountOwnsAreRefused(t *testing.T) {
	dir, a := newSigned(t)
	_, token := openSignedRoot(t, a, "alice")
	if _, err := runs.OpenSignedPlane(dir, runs.SignedOptions{Judge: alicesJudge}); !errors.Is(err, runs.ErrPlaneOwned) {
		t.Fatalf("OpenSignedPlane of records/ this account owns = %v, want ErrPlaneOwned", err)
	}
	p := signedPlane(t, dir, alicesJudge)
	if _, err := p.Resolve(t.Context(), token, alice, opened.Add(time.Minute)); err != nil {
		t.Fatalf("the control, opened with PlaneOwned: %v", err)
	}
	p.RecordsOwnedByAnother()
	_, err := p.Resolve(t.Context(), token, alice, opened.Add(time.Minute))
	if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, runs.ErrPlaneOwned) {
		t.Fatalf("Resolve of a record this account owns = %v, want unreadable, ErrPlaneOwned", err)
	}
	if got := p.SignedCounts()["refused_plane_owned"]; got != 1 {
		t.Errorf("refused_plane_owned = %d, want 1", got)
	}
	empty, _ := newSigned(t)
	if err := os.Remove(filepath.Join(empty, "records", "runs.meta")); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.OpenSignedPlane(empty, runs.SignedOptions{Judge: alicesJudge}); !errors.Is(err, runs.ErrPlaneOwned) {
		t.Errorf("OpenSignedPlane of an empty records/ this account owns = %v, want ErrPlaneOwned before anything in it is read", err)
	}
}

// TestALayoutSpelledThroughALinkBindsAlike: an operator who opens a run
// through a link on the way to the runs directory signs it for the directory
// the link leads to, so a plane that spells the directory by its own path
// takes it.
func TestALayoutSpelledThroughALinkBindsAlike(t *testing.T) {
	target := newDir(t)
	link := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(filepath.Dir(target), link); err != nil {
		t.Fatal(err)
	}
	a, err := runs.InitSignedAdmin(t.Context(), filepath.Join(link, filepath.Base(target)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	_, token := openSignedRoot(t, a, "alice")
	if _, err := signedPlane(t, target, alicesJudge).Resolve(t.Context(), token, alice, opened.Add(time.Minute)); err != nil {
		t.Fatalf("Resolve by the directory's own path of a run opened through a link: %v", err)
	}
}

// TestAClosedRunStaysClosedAcrossARestart: the close a plane carried into
// state/ outlives the plane, so a plane opened after it refuses the open
// record put back without reading the close again.
func TestAClosedRunStaysClosedAcrossARestart(t *testing.T) {
	dir, a := newSigned(t)
	rec, token := openSignedRoot(t, a, "alice")
	open := readBytes(t, recordPath(dir, rec.ID))
	if _, _, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("alice"), alicesJudge); err != nil {
		t.Fatal(err)
	}
	at := opened.Add(2 * time.Minute)
	first, err := runs.OpenSignedPlane(dir, ownedHere)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Resolve(t.Context(), token, alice, at); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve of the closed record = %v, want closed", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, recordPath(dir, rec.ID), open)
	_, err = signedPlane(t, dir, alicesJudge).Resolve(t.Context(), token, alice, at)
	if causeOf(t, err) != runs.CauseClosed || !errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("Resolve after a restart of the open record put back = %v, want closed, ErrReplayed", err)
	}
}
