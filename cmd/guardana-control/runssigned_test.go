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

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/runs/signedruns"
	"github.com/guardana/control/internal/trust"
)

// signedRuns is a roster signed now in which alice operates t1/p1, t2/p1
// and t1/p2, alice's key file, the trust root's public key file, and an
// empty runs directory.
type signedRuns struct {
	dir, key, roster, root string
	doc                    trust.Document
}

// tenantP1 is the identity of the runs these tests sign: alice may operate
// there.
var tenantP1 = runs.Identity{ProjectID: "p1", TenantID: "t1", PrincipalType: "user", PrincipalID: "bob", AgentID: "planner"}

func newSignedRuns(t *testing.T) signedRuns {
	t.Helper()
	tr := newRosterTree(t)
	writeFixture(t, tr.source, strings.Replace(rosterSource(seeded(0x61).Public().(ed25519.PublicKey)),
		`{"tenant":"t1","project":"p1","level":"operate"}`,
		`{"tenant":"t1","project":"p1","level":"operate"},{"tenant":"t2","project":"p1","level":"operate"},{"tenant":"t1","project":"p2","level":"operate"}`, 1))
	if code, _, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, time.Now().Add(-time.Minute).Truncate(time.Second)); code != exitOK {
		t.Fatalf("roster sign answered %d: %q", code, stderr)
	}
	operator := filepath.Join(tr.dir, "operator")
	if err := policykey.WriteKeyPair(operator, seeded(0x61)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(tr.out)
	if err != nil {
		t.Fatal(err)
	}
	env, err := trust.ParseFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.VerifyDocument(env, seeded(0x72).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return signedRuns{dir: runsDir(t), key: filepath.Join(operator, policykey.PrivateFile), roster: tr.out,
		root: filepath.Join(filepath.Dir(tr.key), policykey.PublicFile), doc: doc}
}

func (s signedRuns) flags() []string {
	return []string{"--key", s.key, "--roster", s.roster, "--root-key", s.root}
}

// closeArgs is runs close of run id in dir with every flag of a signed close
// for the plane of t1/p1.
func (s signedRuns) closeArgs(dir, id string) []string {
	return append(append([]string{"runs", "close"}, s.flags()...), "--tenant", "t1", "--project", "p1", dir, id)
}

// resolves reports how a plane of t1/p1 judging with the roster answers token.
func (s signedRuns) resolve(t *testing.T, token string) error {
	t.Helper()
	p, err := runs.OpenSignedPlane(s.dir, runs.SignedOptions{Judge: signedruns.Roster{Document: s.doc, Tenant: "t1", Project: "p1"}, PlaneOwned: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	_, err = p.Resolve(t.Context(), token, tenantP1, time.Now())
	return err
}

// TestRunsOpenWithAKeySignsARecordThePlaneTakes: runs open with the three
// flags makes an empty directory a signed layout and writes a record a plane
// judging with the roster resolves, saying on stderr what it signed; runs
// close with them signs the close, saying what it signed and who signed the
// open record, and the token is closed after.
func TestRunsOpenWithAKeySignsARecordThePlaneTakes(t *testing.T) {
	s := newSignedRuns(t)
	code, stdout, stderr := invoke(t, openArgs(s.dir, tenantP1, "1h", s.flags()...)...)
	if code != exitOK {
		t.Fatalf("runs open --key answered %d: %q %q", code, stdout, stderr)
	}
	id, token := fieldAfter(t, stdout, "run_id: "), fieldAfter(t, stdout, "token: ")
	binding, err := filepath.EvalSymlinks(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	key := keyLabel(seeded(0x61).Public().(ed25519.PublicKey))
	line := oneStderrLine(t, stderr)
	for _, want := range []string{"runs open: signed run " + id + " open, expires_at ", ", root " + id + ", tenant t1 project p1, for " + filepath.Join(binding, runs.RecordsDir) + ", with key " + key} {
		if !strings.Contains(line, want) {
			t.Errorf("runs open --key said %q, which lacks %q", line, want)
		}
	}
	if err := s.resolve(t, token); err != nil {
		t.Fatalf("the plane refuses the signed run: %v", err)
	}
	code, stdout, stderr = invoke(t, s.closeArgs(s.dir, id)...)
	if code != exitOK || stdout != "closed "+id+"\n" {
		t.Fatalf("runs close --key answered %d: %q %q", code, stdout, stderr)
	}
	for _, want := range []string{"runs close: signed run " + id + " closed at ", ", tenant t1 project p1, for ", ", with key " + key + "\n",
		"runs close: over the open record alice signed with key " + key + "\n"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("runs close --key said %q, which lacks %q", stderr, want)
		}
	}
	if err := s.resolve(t, token); causeOf(err) != runs.CauseClosed {
		t.Errorf("the token after the signed close = %v, want closed", err)
	}
}

// TestASignedLayoutRefusesAnUnsignedWriteNamingTheKey: runs open and runs
// close without --key on a signed layout fail and name the flags, and a
// partial set of them is a usage error.
func TestASignedLayoutRefusesAnUnsignedWriteNamingTheKey(t *testing.T) {
	s := newSignedRuns(t)
	o := openRunOK(t, s, tenantP1)
	for name, args := range map[string][]string{
		"open":  openArgs(s.dir, tenantP1, "1h"),
		"close": {"runs", "close", s.dir, o},
	} {
		code, _, stderr := invoke(t, args...)
		if code == exitOK || !strings.Contains(stderr, "--key <operator key file> --roster") {
			t.Errorf("unsigned runs %s answered %d: %q; want a refusal naming --key", name, code, stderr)
		}
	}
	code, _, stderr := invoke(t, openArgs(s.dir, tenantP1, "1h", "--key", s.key)...)
	if code != exitUsage || !strings.Contains(stderr, "all three") {
		t.Errorf("runs open --key alone answered %d: %q; want a usage error", code, stderr)
	}
	for name, args := range map[string][]string{
		"a signed close without --project":     append(append([]string{"runs", "close"}, s.flags()...), "--tenant", "t1", s.dir, o),
		"--tenant and --project without --key": {"runs", "close", "--tenant", "t1", "--project", "p1", s.dir, o},
	} {
		if code, _, stderr := invoke(t, args...); code != exitUsage || !strings.Contains(stderr, "--tenant and --project") {
			t.Errorf("%s answered %d: %q; want a usage error naming --tenant and --project", name, code, stderr)
		}
	}
}

// TestRunsCloseWithAKeyNeverSignsOverARecordTheRosterRefuses: a signed close
// reads the open record it signs over and refuses, signing nothing and
// leaving the runs directory as it was, a record whose signature no roster
// key makes, one of another tenant or project than the plane's, though alice
// may operate there, one signed for another runs directory, and one that is
// not signed at all; each refusal names its cause.
func TestRunsCloseWithAKeyNeverSignsOverARecordTheRosterRefuses(t *testing.T) {
	s := newSignedRuns(t)
	elsewhere := runsDir(t)
	copied := openRunOK(t, signedRuns{dir: elsewhere, key: s.key, roster: s.roster, root: s.root, doc: s.doc}, tenantP1)
	flat := runsDir(t)
	unsigned := openRun(t, flat, tenantP1, "1h").runID
	for _, c := range []struct {
		name  string
		plant func(t *testing.T) string
		want  error
	}{
		{"a signature no roster key makes", func(t *testing.T) string {
			id := openRunOK(t, s, tenantP1)
			path := filepath.Join(s.dir, runs.RecordsDir, id+".run.json")
			raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, path, strings.Replace(string(raw), `"sig":"`, `"sig":"AAAA`, 1))
			return id
		}, runs.ErrUnauthenticated},
		{"a key the roster does not name", func(t *testing.T) string {
			return openSignedBy(t, s.dir, seeded(0x6d))
		}, runs.ErrUnauthenticated},
		{"another tenant", func(t *testing.T) string {
			return openRunOK(t, s, runs.Identity{ProjectID: "p1", TenantID: "t2", PrincipalType: "user", PrincipalID: "bob", AgentID: "planner"})
		}, runs.ErrOtherScope},
		{"another project", func(t *testing.T) string {
			return openRunOK(t, s, runs.Identity{ProjectID: "p2", TenantID: "t1", PrincipalType: "user", PrincipalID: "bob", AgentID: "planner"})
		}, runs.ErrOtherScope},
		{"another runs directory", func(t *testing.T) string {
			copyFile(t, filepath.Join(elsewhere, runs.RecordsDir, copied+".run.json"), filepath.Join(s.dir, runs.RecordsDir, copied+".run.json"))
			return copied
		}, runs.ErrOtherDirectory},
		{"an unsigned record", func(t *testing.T) string {
			copyFile(t, filepath.Join(flat, unsigned+".run.json"), filepath.Join(s.dir, runs.RecordsDir, unsigned+".run.json"))
			return unsigned
		}, runs.ErrUnsigned},
	} {
		id := c.plant(t)
		before := snapshot(t, s.dir)
		code, stdout, stderr := invoke(t, s.closeArgs(s.dir, id)...)
		if code != exitFail || stdout != "" || !strings.Contains(stderr, runs.ErrNotVouched.Error()) || !strings.Contains(stderr, c.want.Error()) ||
			!strings.Contains(stderr, id) || !strings.Contains(stderr, "nothing was signed") {
			t.Errorf("%s: runs close --key answered %d: %q %q; want it refused, naming the run and %v", c.name, code, stdout, stderr, c.want)
		}
		if after := snapshot(t, s.dir); after != before {
			t.Errorf("%s: the refused close changed the runs directory:\n%s\nwas\n%s", c.name, after, before)
		}
	}
}

// TestRunsOpenWithAKeyNeverSignsUnderAParentTheRosterRefuses: a child opened
// under a parent of another tenant's run, one alice may operate in, is
// refused before anything is signed.
func TestRunsOpenWithAKeyNeverSignsUnderAParentTheRosterRefuses(t *testing.T) {
	s := newSignedRuns(t)
	other := openRunOK(t, s, runs.Identity{ProjectID: "p1", TenantID: "t2", PrincipalType: "user", PrincipalID: "bob", AgentID: "planner"})
	before := snapshot(t, s.dir)
	code, stdout, stderr := invoke(t, openArgs(s.dir, tenantP1, "1m", append(s.flags(), "--parent", other)...)...)
	if code != exitFail || stdout != "" || !strings.Contains(stderr, runs.ErrNotVouched.Error()) || !strings.Contains(stderr, runs.ErrOtherScope.Error()) {
		t.Errorf("runs open --key under another tenant's parent answered %d: %q %q", code, stdout, stderr)
	}
	if after := snapshot(t, s.dir); after != before {
		t.Errorf("the refused open changed the runs directory")
	}
}

// anyRecord is a judge that takes every record, so a fixture writes one the
// command under test refuses.
type anyRecord struct{}

func (anyRecord) Judge(context.Context, runs.SignedRecord) (runs.SignedBy, error) {
	return runs.SignedBy{}, nil
}

// openSignedBy opens a run of t1/p1 in the signed layout dir signed by key,
// as anyone who may write records/ can, and returns its id.
func openSignedBy(t *testing.T, dir string, key ed25519.PrivateKey) string {
	t.Helper()
	a, err := runs.OpenAdmin(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	signer := runs.Signer{KeyID: policykey.KeyID(key.Public().(ed25519.PublicKey)), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key)
	}}
	rec, _, err := a.OpenSigned(t.Context(), runs.OpenRequest{Who: tenantP1, TTL: time.Hour, Now: time.Now()}, signer, anyRecord{})
	if err != nil {
		t.Fatal(err)
	}
	return rec.ID
}

// snapshot is every file under dir with its bytes, one per line.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
		b.WriteString(path + " " + string(raw) + "\n")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(from) //nolint:gosec // G304: a file under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, to, string(raw))
}

// TestRunsListAndPruneReadASignedLayout: list prints a signed layout's runs
// and prune archives an expired tree's records, leaving state/ alone.
func TestRunsListAndPruneReadASignedLayout(t *testing.T) {
	s := newSignedRuns(t)
	id := openRunOK(t, s, tenantP1)
	code, stdout, stderr := invoke(t, "runs", "list", s.dir)
	if code != exitOK || !strings.HasPrefix(stdout, id+" open ") {
		t.Fatalf("runs list answered %d: %q %q", code, stdout, stderr)
	}
	archive := filepath.Join(t.TempDir(), "archive")
	cutoff := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	code, _, stderr = invoke(t, "runs", "prune", "--expired-before", cutoff, "--archive", archive, s.dir)
	if code == exitOK || !strings.Contains(stderr, "cutoff") {
		t.Fatalf("a prune past now answered %d: %q; want the cutoff refused", code, stderr)
	}
	admin, err := runs.OpenAdmin(t.Context(), s.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	cut := time.Now().Add(2 * time.Hour)
	got, err := admin.Prune(t.Context(), runs.PruneRequest{ExpiredBefore: cut, Archive: archive, Now: cut})
	if err != nil || len(got.Trees) != 1 || got.Trees[0] != id {
		t.Fatalf("Prune over the signed layout = %+v, %v", got, err)
	}
	if entries, err := os.ReadDir(filepath.Join(s.dir, runs.StateDir)); err != nil || len(entries) != 0 {
		t.Errorf("state/ after the prune = %v, %v; want it untouched and empty", entries, err)
	}
}

func openRunOK(t *testing.T, s signedRuns, w runs.Identity) string {
	t.Helper()
	code, stdout, stderr := invoke(t, openArgs(s.dir, w, "1h", s.flags()...)...)
	if code != exitOK {
		t.Fatalf("runs open --key answered %d: %q", code, stderr)
	}
	return fieldAfter(t, stdout, "run_id: ")
}

func fieldAfter(t *testing.T, stdout, label string) string {
	t.Helper()
	for _, line := range strings.Split(stdout, "\n") {
		if v, ok := strings.CutPrefix(line, label); ok {
			return v
		}
	}
	t.Fatalf("stdout %q has no %q line", stdout, label)
	return ""
}

func causeOf(err error) runs.Cause {
	var r *runs.Refusal
	if errors.As(err, &r) {
		return r.Cause
	}
	return ""
}
