package recovery_test

import (
	"crypto/ed25519"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/holdjournal"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/runs"
)

const (
	bundleID = "fixture"
	d1       = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	d2       = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// base is a plane's configuration with every directory relative to the
// file, so a copy of the tree is a plane of its own.
const base = `mode: OBSERVE
project_id: orders
tenant_id: acme
listener:
  kind: stateless_http
  principal:
    id: agent-runner
    type: service
  agent:
    id: orders-assistant
policy:
  bundle_id: fixture
  bundle_file: policy.bundle
  key_id: k1
  public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  statement_file: policy.statement
  state_dir: floors
  freshness_key_id: f1
  freshness_public_key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
  poll_interval: 5s
evidence:
  dir: spool
export:
  endpoint: https://127.0.0.1:4318/v1/logs
runs:
  dir: runs
upstreams:
  - name: orders
    endpoint: http://127.0.0.1:1/mcp
`

const directoryBlock = `approvals:
  authority: directory
  dir: approvals
  hold_journal_dir: holds
pause:
  file: pause/pause.json
`

const signedBlock = `plane_id: plane-a
approvals:
  authority: signed
  dir: approvals
  hold_journal_dir: holds
  inbox_dir: inbox
trust:
  root_public_key: trust/root.pub
  roster: trust/roster.json
  roster_id: roster-a
  floor_dir: trust/floors
operators:
  authenticator:
    kind: roster
  authorizer:
    kind: roster
pause:
  file: pause/pause.json
  floor_dir: pausefloor
`

// t0 is when every fixture state was written; a restore runs later.
var t0 = time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)

var freshKey = ed25519.NewKeyFromSeed([]byte("recovery-test-freshness-key-0001"))

// plane is a configuration file and the directories it names, under root.
type plane struct {
	root string
	cfg  *gatewayconfig.Config
}

func (p *plane) path(rel string) string { return filepath.Join(p.root, rel) }

// newPlane writes the configuration with block appended and makes the
// directories a plane needs to start: an empty spool, a hold journal and an
// approvals directory.
func newPlane(t *testing.T, block string) *plane {
	t.Helper()
	p := &plane{root: filepath.Join(t.TempDir(), "plane")}
	for _, d := range []string{"", "spool", "approvals", "pause", "trust"} {
		if err := os.Mkdir(p.path(d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p.path("plane.yaml"), []byte(base+block), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := holdjournal.Open(p.path("holds"))
	if err != nil {
		if err := os.Mkdir(p.path("holds"), 0o700); err != nil {
			t.Fatal(err)
		}
		if j, err = holdjournal.Open(p.path("holds")); err != nil {
			t.Fatalf("holdjournal.Open: %v", err)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	p.load(t)
	return p
}

func (p *plane) load(t *testing.T) {
	t.Helper()
	cfg, err := gatewayconfig.Load(p.path("plane.yaml"), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p.cfg = cfg
}

func statement(t *testing.T, serial int64, digest string, issued time.Time) policy.Statement {
	t.Helper()
	env, err := policy.SignStatement(bundleID, serial, digest, issued, freshKey, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	st, err := policy.VerifyStatement(env, bundle.Keyring{"fresh": freshKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// raiseFloor takes a statement of serial into the plane floor, making the
// floor directory first where it is missing.
func (p *plane) raiseFloor(t *testing.T, serial int64, digest string, issued time.Time) {
	t.Helper()
	dir := p.path("floors")
	if _, err := os.Lstat(dir); err != nil {
		if err := policystate.Init(t.Context(), dir, policystate.KindPlane, bundleID); err != nil {
			t.Fatal(err)
		}
	}
	s, err := policystate.Open(dir, policystate.KindPlane)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.Raise(t.Context(), statement(t, serial, digest, issued), issued); err != nil {
		t.Fatalf("Raise to %d: %v", serial, err)
	}
}

func (p *plane) floor(t *testing.T) policy.Floor {
	t.Helper()
	s, err := policystate.Open(p.path("floors"), policystate.KindPlane)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	f, err := s.Floor(t.Context(), bundleID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

var alice = runs.Identity{ProjectID: "orders", TenantID: "acme", PrincipalType: "service", PrincipalID: "agent-runner", AgentID: "orders-assistant"}

// openRun opens a root run in the unsigned runs directory and sets its state.
func (p *plane) openRun(t *testing.T, s runs.State) runs.Record {
	t.Helper()
	a, err := runs.InitAdmin(t.Context(), p.path("runs"))
	if err != nil {
		if err := os.Mkdir(p.path("runs"), 0o700); err != nil {
			t.Fatal(err)
		}
		if a, err = runs.InitAdmin(t.Context(), p.path("runs")); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _ = a.Close() }()
	rec, _, err := a.Open(t.Context(), runs.OpenRequest{Who: alice, TTL: time.Hour, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	p.setState(t, rec.ID, s)
	return rec
}

func (p *plane) setState(t *testing.T, root string, s runs.State) {
	t.Helper()
	pl, err := runs.OpenPlane(p.path("runs"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pl.Close() }()
	if err := pl.Raise(t.Context(), root, func(runs.State) runs.State { return s }); err != nil {
		t.Fatal(err)
	}
}

func (p *plane) run(t *testing.T, id string) (runs.Record, runs.State) {
	t.Helper()
	a, err := runs.OpenAdmin(t.Context(), p.path("runs"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	rec, err := a.Lookup(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := runs.OpenPlane(p.path("runs"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pl.Close() }()
	s, err := pl.State(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return rec, s
}

func (p *plane) addPause(t *testing.T, id string) {
	t.Helper()
	path := p.path("pause/pause.json")
	if _, err := os.Lstat(path); err != nil {
		if err := pause.Init(t.Context(), path); err != nil {
			t.Fatal(err)
		}
	}
	e := pause.Entry{ID: id, Scope: pause.Scope{Kind: pause.ScopeProvider, Provider: "orders"}, CreatedAt: t0, Reason: "test"}
	if err := pause.Add(t.Context(), path, e); err != nil {
		t.Fatal(err)
	}
}

func (p *plane) pauses(t *testing.T) []string {
	t.Helper()
	l, err := pause.List(p.path("pause/pause.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range l.Entries {
		out = append(out, e.ID)
	}
	return out
}

// tree is every file under dir by its slash path, with its bytes, leaving
// out the paths skip names.
func tree(t *testing.T, dir string, skip ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		for _, s := range skip {
			if rel == s || strings.HasPrefix(rel, s+"/") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(p) //nolint:gosec // G304: a file under the test's own directory
		out[rel] = string(raw)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
