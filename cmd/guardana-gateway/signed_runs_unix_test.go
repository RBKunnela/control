//go:build unix

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/runs"
)

// takesAny is the judge a fixture writes its records through, so a record
// the plane under test refuses is written all the same.
type takesAny struct{}

func (takesAny) Judge(context.Context, runs.SignedRecord) (runs.SignedBy, error) {
	return runs.SignedBy{}, nil
}

// signedRunsTree is signedPlaneTree with alice an operator of acme/orders and
// runs.dir a signed layout.
func signedRunsTree(t *testing.T) (tree, *runs.Admin) {
	t.Helper()
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	dir := filepath.Join(tr.dir, "runs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	a, err := runs.InitSignedAdmin(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, tr.config, append(raw, []byte("\nruns:\n  dir: runs\n")...))
	return tr, a
}

func runSigner(name string) runs.Signer {
	key := signedTestKey(name)
	return runs.Signer{KeyID: policykey.KeyID(signedTestPublic(name)), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key)
	}}
}

// openSignedRun opens a root run of the fixture listener's identity signed by
// name.
func openSignedRun(t *testing.T, tr tree, a *runs.Admin, name string) (runs.Record, string) {
	t.Helper()
	cfg := tr.load(t)
	who := listenerRunIdentity(cfg)
	rec, token, err := a.OpenSigned(t.Context(), runs.OpenRequest{Who: runs.Identity{
		ProjectID: cfg.ProjectID, TenantID: who.TenantID, PrincipalType: who.PrincipalType, PrincipalID: who.PrincipalID, AgentID: who.AgentID,
	}, TTL: time.Hour, Now: time.Now()}, runSigner(name), takesAny{})
	if err != nil {
		t.Fatal(err)
	}
	return rec, token
}

func resolveOn(t *testing.T, p *plane, token string) error {
	t.Helper()
	_, err := planeRuns(p.cfg, p.runsDir).Resolve(t.Context(), token, listenerRunIdentity(p.cfg), time.Now())
	return err
}

// TestASignedStartRefusesARecordsDirectoryThePlanesAccountMayWrite: records/
// or a directory on its path the plane's account may write refuses the
// start, naming runs.dir; placed apart, a records/ the plane's own account
// owns refuses it too; on one account, as dev runs, the plane resolves
// alice's run and refuses mallory's, whom the roster does not name, and
// /healthz counts both.
func TestASignedStartRefusesARecordsDirectoryThePlanesAccountMayWrite(t *testing.T) {
	tr, a := signedRunsTree(t)
	_, token := openSignedRun(t, tr, a, "alice")
	_, forged := openSignedRun(t, tr, a, "mallory")
	placedApart(t, filepath.Join("runs", runs.RecordsDir))
	if _, err := buildSigned(t, tr); err == nil || !strings.Contains(err.Error(), "runs.dir: under the signed authority the plane's own account may not be able to change it") {
		t.Fatalf("build over a plane-writable records/ = %v", err)
	}
	placedApart(t)
	if _, err := buildSigned(t, tr); !errors.Is(err, runs.ErrPlaneOwned) || !strings.Contains(err.Error(), "runs.dir") {
		t.Fatalf("build over a records/ the plane's account owns = %v, want ErrPlaneOwned naming runs.dir", err)
	}
	p, err := buildOneAccount(t, tr)
	if err != nil {
		t.Fatalf("build on one account = %v", err)
	}
	if err := resolveOn(t, p, token); err != nil {
		t.Fatalf("alice's run = %v", err)
	}
	err = resolveOn(t, p, forged)
	var refusal *gateway.RunRefusal
	if !errors.As(err, &refusal) || refusal.Cause != gateway.RunUnreadable || !errors.Is(err, runs.ErrUnauthenticated) {
		t.Fatalf("mallory's run = %v, want unreadable and unauthenticated", err)
	}
	signed, _ := p.health(p.pauseSource(), time.Now)
	counts, _ := signed.Runs["signed"].(map[string]uint64)
	if counts["judged"] != 1 || counts["refused_unauthenticated"] != 1 {
		t.Errorf("runs.signed on /healthz = %v", signed.Runs["signed"])
	}
}

// TestASignedPlaneCarriesTheClosesItFindsAtItsStart: a run closed while no
// plane served is closed for the plane that starts after, and the open record
// put back is refused, and again after a restart.
func TestASignedPlaneCarriesTheClosesItFindsAtItsStart(t *testing.T) {
	tr, a := signedRunsTree(t)
	rec, token := openSignedRun(t, tr, a, "alice")
	path := filepath.Join(tr.dir, "runs", runs.RecordsDir, rec.ID+".run.json")
	open, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.CloseSigned(t.Context(), rec.ID, time.Now(), runSigner("alice"), takesAny{}); err != nil {
		t.Fatal(err)
	}
	p, err := buildOneAccount(t, tr)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, open)
	for _, when := range []string{"after the start", "after a restart"} {
		err := resolveOn(t, p, token)
		var refusal *gateway.RunRefusal
		if !errors.As(err, &refusal) || refusal.Cause != gateway.RunClosed || !errors.Is(err, runs.ErrReplayed) {
			t.Errorf("%s: the open record put back = %v, want closed and replayed", when, err)
		}
		if err := p.close(); err != nil {
			t.Fatal(err)
		}
		if p, err = buildOneAccount(t, tr); err != nil {
			t.Fatal(err)
		}
	}
}

// closedPastTheBound opens two runs signed by alice, closes the one whose
// record comes last in filename order, puts its open record back, and
// lowers the bound to one record, so the start never reads the close. It
// returns the put-back run's token.
func closedPastTheBound(t *testing.T, tr tree, a *runs.Admin) string {
	t.Helper()
	first, firstToken := openSignedRun(t, tr, a, "alice")
	second, secondToken := openSignedRun(t, tr, a, "alice")
	late, token := first, firstToken
	if second.ID > first.ID {
		late, token = second, secondToken
	}
	path := filepath.Join(tr.dir, "runs", runs.RecordsDir, late.ID+".run.json")
	open, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.CloseSigned(t.Context(), late.ID, time.Now(), runSigner("alice"), takesAny{}); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, open)
	saved := runsCarryBound
	runsCarryBound = 1
	t.Cleanup(func() { runsCarryBound = saved })
	return token
}

// TestASignedStartThatCannotReadEveryRecordRefuses: records/ holds more
// records than the start reads, so a close past the bound would go
// uncarried and the open record put back after it would resolve; the start
// refuses instead, naming runs.dir.
func TestASignedStartThatCannotReadEveryRecordRefuses(t *testing.T) {
	tr, a := signedRunsTree(t)
	token := closedPastTheBound(t, tr, a)
	p, err := buildOneAccount(t, tr)
	if err == nil {
		t.Fatalf("build over more records than the start reads = nil; the open record put back past the bound resolves: %v", resolveOn(t, p, token))
	}
	if !errors.Is(err, runs.ErrCarryBound) || !strings.Contains(err.Error(), "runs.dir") {
		t.Fatalf("build over more records than the start reads = %v, want ErrCarryBound naming runs.dir", err)
	}
}

// TestDoctorFailsASignedLayoutItCannotReadWhole: doctor reads no more
// records than the start, and fails what the start refuses.
func TestDoctorFailsASignedLayoutItCannotReadWhole(t *testing.T) {
	tr, a := signedRunsTree(t)
	closedPastTheBound(t, tr, a)
	doctorPlaneOwned = true
	t.Cleanup(func() { doctorPlaneOwned = false })
	d := &examination{cfg: tr.load(t)}
	verdict, _, line := d.runs(t.Context())
	if verdict != verdictFail || !strings.Contains(line, "only the first 1 were read") || !strings.Contains(line, "run refuses to start on it") ||
		!strings.Contains(line, brand.CLI+" runs prune") {
		t.Fatalf("doctor's runs line over more records than it reads = %s, %q; want fail, naming the bound, the start and the way out", verdict, line)
	}
}

// TestASignedStopOfAnotherProjectsRunIsUnheld: on a signed layout the judge
// refuses a record of another project as of another scope; a stop of that
// run matches no call of this plane, so it is unheld, never unread, beside
// the stop of the plane's own run, which is held.
func TestASignedStopOfAnotherProjectsRunIsUnheld(t *testing.T) {
	tr, a := signedRunsTree(t)
	own, _ := openSignedRun(t, tr, a, "alice")
	cfg := tr.load(t)
	who := listenerRunIdentity(cfg)
	other, _, err := a.OpenSigned(t.Context(), runs.OpenRequest{Who: runs.Identity{
		ProjectID: "billing", TenantID: who.TenantID, PrincipalType: who.PrincipalType, PrincipalID: who.PrincipalID, AgentID: who.AgentID,
	}, TTL: time.Hour, Now: time.Now()}, runSigner("alice"), takesAny{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := buildOneAccount(t, tr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.runsDir.Lookup(t.Context(), other.ID); !errors.Is(err, runs.ErrOtherScope) {
		t.Fatalf("Lookup of the other project's run = %v, want ErrOtherScope", err)
	}
	stopOfRun := func(line int64, id string) reaction.Entry {
		return reaction.Entry{Line: line, Stop: reaction.Stop{Scope: reaction.ScopeRun, Subject: id, RunID: id, TenantID: who.TenantID}}
	}
	unheld, unread := unheldStops(p.runsDir, p.cfg, []reaction.Entry{stopOfRun(2, own.ID), stopOfRun(3, other.ID)})
	if len(unheld) != 1 || unheld[0].RunID != other.ID || len(unread) != 0 {
		t.Fatalf("unheld %+v, unread %+v; want the other project's run alone unheld and nothing unread", unheld, unread)
	}
}

// TestASignedStartRefusesAnUnsignedRunsDirectory: under signed a runs
// directory of unsigned runs refuses the start.
func TestASignedStartRefusesAnUnsignedRunsDirectory(t *testing.T) {
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	dir := filepath.Join(tr.dir, "runs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	a, err := runs.InitAdmin(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, tr.config, append(raw, []byte("\nruns:\n  dir: runs\n")...))
	placedApart(t)
	if _, err := buildSigned(t, tr); !errors.Is(err, runs.ErrLayout) || !strings.Contains(err.Error(), "runs.dir") {
		t.Fatalf("build over an unsigned runs directory = %v, want ErrLayout naming runs.dir", err)
	}
}

// TestDoctorCountsASignedLayoutsRecordsAndSigners: doctor refuses a records/
// the plane's own account owns, as run does, and writes nothing; over records
// an operators' account owns it reads them as the plane would judge them,
// names who signed them and how many count for nothing.
func TestDoctorCountsASignedLayoutsRecordsAndSigners(t *testing.T) {
	tr, a := signedRunsTree(t)
	openSignedRun(t, tr, a, "alice")
	openSignedRun(t, tr, a, "mallory")
	d := &examination{cfg: tr.load(t)}
	verdict, _, line := d.runs(t.Context())
	if verdict != verdictFail || !strings.Contains(line, runs.ErrPlaneOwned.Error()) {
		t.Fatalf("doctor's runs line over records/ this account owns = %s, %q", verdict, line)
	}
	if entries, err := os.ReadDir(filepath.Join(tr.dir, "runs", runs.StateDir)); err != nil || len(entries) != 0 {
		t.Errorf("state/ after doctor = %v, %v; want it untouched", entries, err)
	}
	doctorPlaneOwned = true
	t.Cleanup(func() { doctorPlaneOwned = false })
	verdict, _, line = d.runs(t.Context())
	if verdict != verdictOK {
		t.Fatalf("doctor's runs line, records/ allowed to be this account's = %s, %q", verdict, line)
	}
	if entries, err := os.ReadDir(filepath.Join(tr.dir, "runs", runs.StateDir)); err != nil || len(entries) != 0 {
		t.Errorf("state/ after doctor read it = %v, %v; want it untouched", entries, err)
	}
	if !strings.Contains(line, "2 record(s), 1 open, 0 closed, 0 expired, signed by 1 operator(s) (operator-a 1)") ||
		!strings.Contains(line, "1 count for nothing and refuse their calls (unauthenticated 1)") {
		t.Fatalf("doctor's line over that survey = %q", line)
	}
}
