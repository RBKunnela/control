package runs_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// opened is the clock reading every run in these tests opens at.
var opened = time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)

var alice = runs.Identity{ProjectID: "project-a", TenantID: "tenant-a", PrincipalType: "user", PrincipalID: "alice", AgentID: "agent-1"}

// newDir is an empty directory only its owner may write.
func newDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "runs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openAdmin(t *testing.T, dir string) *runs.Admin {
	t.Helper()
	a, err := runs.InitAdmin(context.Background(), dir)
	if err != nil {
		t.Fatalf("InitAdmin(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func openPlane(t *testing.T, dir string) *runs.Plane {
	t.Helper()
	p, err := runs.OpenPlane(dir)
	if err != nil {
		t.Fatalf("OpenPlane(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// setup is a runs directory with both handles open on it.
func setup(t *testing.T) (string, *runs.Admin, *runs.Plane) {
	t.Helper()
	dir := newDir(t)
	a := openAdmin(t, dir)
	return dir, a, openPlane(t, dir)
}

// openRoot opens a root run for alice that lives an hour from opened.
func openRoot(t *testing.T, a *runs.Admin) (runs.Record, string) {
	t.Helper()
	return openUnder(t, a, "", alice)
}

func openUnder(t *testing.T, a *runs.Admin, parent string, who runs.Identity) (runs.Record, string) {
	t.Helper()
	rec, token, err := a.Open(t.Context(), runs.OpenRequest{Who: who, Parent: parent, TTL: time.Hour, Now: opened})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return rec, token
}

// causeOf is the cause of a refusal, failing the test on any other error.
func causeOf(t *testing.T, err error) runs.Cause {
	t.Helper()
	var r *runs.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("got %v, want a *runs.Refusal", err)
	}
	return r.Cause
}

// rewrite edits the JSON object in dir/name the way a writer of the directory
// could, keeping every key it does not touch.
func rewrite(t *testing.T, dir, name string, edit func(map[string]json.RawMessage)) {
	t.Helper()
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, out)
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// idOf is the run id a token names.
func idOf(t *testing.T, token string) string {
	t.Helper()
	id, _, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("token %q has no separator", token)
	}
	return id
}
