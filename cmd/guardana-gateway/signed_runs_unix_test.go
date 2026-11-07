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

	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
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
