package runs_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

func TestResolveReturnsTheRunItsTokenNames(t *testing.T) {
	_, a, p := setup(t)
	_, token := openRoot(t, a)
	id := idOf(t, token)
	lastInstant := time.Date(2026, time.March, 1, 12, 59, 59, 999999999, time.UTC)
	got, err := p.Resolve(t.Context(), token, alice, lastInstant)
	if err != nil {
		t.Fatalf("Resolve one nanosecond before expiry: %v", err)
	}
	want := runs.Run{
		ID:      id,
		Root:    id,
		Who:     runs.Identity{ProjectID: "project-a", TenantID: "tenant-a", PrincipalType: "user", PrincipalID: "alice", AgentID: "agent-1"},
		Expires: time.Date(2026, time.March, 1, 13, 0, 0, 0, time.UTC),
	}
	if got != want {
		t.Fatalf("Resolve = %+v, want %+v", got, want)
	}
}

func TestResolveRefusesEachCauseInOrder(t *testing.T) {
	_, a, p := setup(t)
	_, token := openRoot(t, a)
	closedRec, closedToken := openRoot(t, a)
	if err := a.CloseRun(t.Context(), closedRec.ID, opened.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	id, secret, _ := strings.Cut(token, ".")
	otherSecret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	at := opened.Add(time.Minute)
	expires := opened.Add(time.Hour)
	with := func(edit func(*runs.Identity)) runs.Identity {
		w := alice
		edit(&w)
		return w
	}
	otherAgent := with(func(w *runs.Identity) { w.AgentID = "agent-2" })
	cases := []struct {
		name  string
		token string
		who   runs.Identity
		now   time.Time
		want  runs.Cause
	}{
		{"empty", "", alice, at, runs.CauseMissing},
		{"no separator", id + secret, alice, at, runs.CauseMalformed},
		{"upper-case id", "run-" + strings.ToUpper(strings.TrimPrefix(id, "run-")) + "." + secret, alice, at, runs.CauseMalformed},
		{"short id", id[:len(id)-1] + "." + secret, alice, at, runs.CauseMalformed},
		{"short secret", id + "." + secret[:42], alice, at, runs.CauseMalformed},
		{"padded secret", id + "." + secret + "=", alice, at, runs.CauseMalformed},
		{"standard alphabet", id + ".+" + strings.Repeat("A", 42), alice, at, runs.CauseMalformed},
		{"stray low bits", id + "." + strings.Repeat("A", 42) + "B", alice, at, runs.CauseMalformed},
		{"trailing newline", token + "\n", alice, at, runs.CauseMalformed},
		{"second separator", token + ".x", alice, at, runs.CauseMalformed},
		{"unknown id", "run-" + strings.Repeat("0", 32) + "." + secret, alice, at, runs.CauseUnknown},
		{"wrong secret", id + "." + otherSecret, alice, at, runs.CauseUnknown},
		{"wrong secret, other agent", id + "." + otherSecret, otherAgent, at, runs.CauseUnknown},
		{"wrong secret, closed", idOf(t, closedToken) + "." + otherSecret, alice, at, runs.CauseUnknown},
		{"wrong secret, other project", id + "." + otherSecret, with(func(w *runs.Identity) { w.ProjectID = "project-b" }), at, runs.CauseUnknown},
		{"other project", token, with(func(w *runs.Identity) { w.ProjectID = "project-b" }), at, runs.CauseIdentity},
		{"no project", token, with(func(w *runs.Identity) { w.ProjectID = "" }), at, runs.CauseIdentity},
		{"closed, other project", closedToken, with(func(w *runs.Identity) { w.ProjectID = "project-b" }), at, runs.CauseIdentity},
		{"other tenant", token, with(func(w *runs.Identity) { w.TenantID = "tenant-b" }), at, runs.CauseIdentity},
		{"other principal type", token, with(func(w *runs.Identity) { w.PrincipalType = "service" }), at, runs.CauseIdentity},
		{"other principal", token, with(func(w *runs.Identity) { w.PrincipalID = "bob" }), at, runs.CauseIdentity},
		{"other agent", token, otherAgent, at, runs.CauseIdentity},
		{"closed, other agent", closedToken, otherAgent, at, runs.CauseIdentity},
		{"closed", closedToken, alice, at, runs.CauseClosed},
		{"closed and expired", closedToken, alice, expires, runs.CauseClosed},
		{"closed, zero clock", closedToken, alice, time.Time{}, runs.CauseClosed},
		{"zero clock", token, alice, time.Time{}, runs.CauseExpired},
		{"at expiry", token, alice, expires, runs.CauseExpired},
		{"past expiry", token, alice, expires.Add(time.Hour), runs.CauseExpired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := p.Resolve(t.Context(), c.token, c.who, c.now)
			if cause := causeOf(t, err); cause != c.want {
				t.Fatalf("cause %q, want %q (err %v)", cause, c.want, err)
			}
			if got != (runs.Run{}) {
				t.Fatalf("a refusal returned a run: %+v", got)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the refusal repeats the secret: %v", err)
			}
		})
	}
}

func TestResolveOfARecordThatDoesNotDecodeIsUnreadable(t *testing.T) {
	cases := map[string]func(map[string]json.RawMessage){
		"absent key":     func(m map[string]json.RawMessage) { delete(m, "closed_at") },
		"unknown key":    func(m map[string]json.RawMessage) { m["note"] = json.RawMessage(`"x"`) },
		"schema major 1": func(m map[string]json.RawMessage) { m["schema_version"] = json.RawMessage(`"1.0"`) },
		"schema major 1, no project": func(m map[string]json.RawMessage) {
			m["schema_version"] = json.RawMessage(`"1.0"`)
			delete(m, "project_id")
		},
		"schema major 3": func(m map[string]json.RawMessage) { m["schema_version"] = json.RawMessage(`"3.0"`) },
		"no project":     func(m map[string]json.RawMessage) { delete(m, "project_id") },
		"empty project":  func(m map[string]json.RawMessage) { m["project_id"] = json.RawMessage(`""`) },
		"null field":     func(m map[string]json.RawMessage) { m["closed_at"] = json.RawMessage(`null`) },
		"another run id": func(m map[string]json.RawMessage) {
			m["run_id"] = json.RawMessage(`"run-` + strings.Repeat("1", 32) + `"`)
			m["root"] = m["run_id"]
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			dir, a, p := setup(t)
			_, token := openRoot(t, a)
			rewrite(t, dir, idOf(t, token)+".run.json", edit)
			_, err := p.Resolve(t.Context(), token, alice, opened)
			if cause := causeOf(t, err); cause != runs.CauseUnreadable {
				t.Fatalf("cause %q, want unreadable (err %v)", cause, err)
			}
		})
	}
}

// Two runs of one tenant, principal and agent in one directory, opened for
// two projects: each token resolves for its own project and is refused as
// another identity for the other, whichever project asks first.
func TestResolveHoldsARunToItsProject(t *testing.T) {
	_, a, p := setup(t)
	other := alice
	other.ProjectID = "project-b"
	_, tokenA := openUnder(t, a, "", alice)
	_, tokenB := openUnder(t, a, "", other)
	at := opened.Add(time.Minute)
	for _, c := range []struct {
		name, token string
		who         runs.Identity
		resolves    bool
	}{
		{"A's run for project B", tokenA, other, false},
		{"A's run for project A", tokenA, alice, true},
		{"B's run for project A", tokenB, alice, false},
		{"B's run for project B", tokenB, other, true},
	} {
		run, err := p.Resolve(t.Context(), c.token, c.who, at)
		switch {
		case c.resolves && (err != nil || run.ID != idOf(t, c.token) || run.Who.ProjectID != c.who.ProjectID):
			t.Errorf("%s: %+v, %v; want the run", c.name, run, err)
		case !c.resolves && causeOf(t, err) != runs.CauseIdentity:
			t.Errorf("%s: %v; want a refusal as another identity", c.name, err)
		}
	}
}

// A record of major 1 on disk resolves for nobody: refused as unreadable,
// with its version named, for every project that could ask.
func TestResolveOfARecordOfMajorOneIsUnreadableForEveryProject(t *testing.T) {
	dir, a, p := setup(t)
	_, token := openRoot(t, a)
	rewrite(t, dir, idOf(t, token)+".run.json", func(m map[string]json.RawMessage) {
		m["schema_version"] = json.RawMessage(`"1.0"`)
		delete(m, "project_id")
	})
	for _, project := range []string{"project-a", "project-b", ""} {
		who := alice
		who.ProjectID = project
		_, err := p.Resolve(t.Context(), token, who, opened)
		if cause := causeOf(t, err); cause != runs.CauseUnreadable || !errors.Is(err, runs.ErrSchemaVersion) {
			t.Errorf("project %q: cause %q, err %v; want unreadable and ErrSchemaVersion", project, cause, err)
		}
	}
	if _, err := p.Lookup(t.Context(), idOf(t, token)); !errors.Is(err, runs.ErrSchemaVersion) {
		t.Errorf("Lookup of a major-1 record: %v, want ErrSchemaVersion", err)
	}
}

func TestResolveOfAGarbledRecordIsUnreadable(t *testing.T) {
	dir, a, p := setup(t)
	_, token := openRoot(t, a)
	writeFile(t, filepath.Join(dir, idOf(t, token)+".run.json"), []byte("{\"schema_version\":"))
	_, err := p.Resolve(t.Context(), token, alice, opened)
	if cause := causeOf(t, err); cause != runs.CauseUnreadable || !errors.Is(err, runs.ErrMalformed) {
		t.Fatalf("cause %q, err %v; want unreadable and ErrMalformed", cause, err)
	}
}

func TestResolveOnAHandleThatIsNotOpenIsUnreadable(t *testing.T) {
	_, a, p := setup(t)
	_, token := openRoot(t, a)
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	for name, call := range map[string]func() error{
		"zero value": func() error { _, err := new(runs.Plane).Resolve(t.Context(), token, alice, opened); return err },
		"nil":        func() error { _, err := (*runs.Plane)(nil).Resolve(t.Context(), token, alice, opened); return err },
		"ended ctx":  func() error { _, err := p.Resolve(ended, token, alice, opened); return err },
	} {
		if cause := causeOf(t, call()); cause != runs.CauseUnreadable {
			t.Errorf("%s: cause %q, want unreadable", name, cause)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := p.Resolve(t.Context(), token, alice, opened)
	if cause := causeOf(t, err); cause != runs.CauseUnreadable || !errors.Is(err, runs.ErrClosed) {
		t.Fatalf("after Close: cause %q, err %v", cause, err)
	}
}

func TestCausesAreTheFixedLabelSet(t *testing.T) {
	want := []runs.Cause{"missing", "malformed", "unknown", "identity", "closed", "expired", "unreadable"}
	got := runs.Causes()
	if len(got) != len(want) {
		t.Fatalf("Causes() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Causes() = %v, want %v", got, want)
		}
	}
}
