package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/runs"
)

// who is the identity the fixtures open runs for.
var who = runs.Identity{ProjectID: "orders", TenantID: "acme", PrincipalType: "user", PrincipalID: "alice", AgentID: "planner"}

var runIDShape = regexp.MustCompile(`^run-[0-9a-f]{32}$`)

// runsDir is an empty directory the operator owns, as runs open wants it.
func runsDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "runs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// openFlags names every flag runs open requires.
func openFlags(w runs.Identity, ttl string) []string {
	return []string{"--project", w.ProjectID, "--tenant", w.TenantID, "--principal-type", w.PrincipalType, "--principal", w.PrincipalID, "--agent", w.AgentID, "--ttl", ttl}
}

// openArgs is a whole runs open call: the required flags, then extra flags,
// which win over the required ones they repeat, then the directory.
func openArgs(dir string, w runs.Identity, ttl string, extra ...string) []string {
	args := append([]string{"runs", "open"}, openFlags(w, ttl)...)
	return append(append(args, extra...), dir)
}

// opened is what runs open printed, line by line.
type opened struct{ runID, root, expiresAt, token string }

func openRun(t *testing.T, dir string, w runs.Identity, ttl string, extra ...string) opened {
	t.Helper()
	code, stdout, stderr := invoke(t, openArgs(dir, w, ttl, extra...)...)
	if code != exitOK || stderr != "" {
		t.Fatalf("runs open answered %d: %q", code, stderr)
	}
	return parseOpened(t, stdout)
}

// parseOpened holds stdout to exactly four `name: value` lines in their order.
func parseOpened(t *testing.T, stdout string) opened {
	t.Helper()
	lines := strings.Split(stdout, "\n")
	names := []string{"run_id", "root", "expires_at", "token"}
	if len(lines) != len(names)+1 || lines[len(names)] != "" {
		t.Fatalf("runs open printed %q, want four lines", stdout)
	}
	values := make([]string, len(names))
	for i, name := range names {
		v, ok := strings.CutPrefix(lines[i], name+": ")
		if !ok || v == "" || strings.Contains(v, " ") {
			t.Fatalf("line %d is %q, want %s: <value>", i+1, lines[i], name)
		}
		values[i] = v
	}
	return opened{values[0], values[1], values[2], values[3]}
}

// secret is the part of a token after the run id.
func (o opened) secret(t *testing.T) string {
	t.Helper()
	id, s, ok := strings.Cut(o.token, ".")
	if !ok || id != o.runID || len(s) < 40 {
		t.Fatalf("token %q is not the run id, a dot and a secret", o.token)
	}
	return s
}

func resolve(t *testing.T, dir, token string, w runs.Identity) (runs.Run, error) {
	t.Helper()
	plane, err := runs.OpenPlane(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plane.Close() }()
	return plane.Resolve(context.Background(), token, w, time.Now())
}

// TestRunsOpenPrintsWhatTheTokenResolvesTo: the four lines name the run the
// token resolves to.
func TestRunsOpenPrintsWhatTheTokenResolvesTo(t *testing.T) {
	dir := runsDir(t)
	before := time.Now()
	o := openRun(t, dir, who, "90m")
	after := time.Now()
	if !runIDShape.MatchString(o.runID) || o.root != o.runID {
		t.Errorf("a root run printed run_id %q and root %q; want one run id twice", o.runID, o.root)
	}
	expires, err := time.Parse(time.RFC3339Nano, o.expiresAt)
	if err != nil || !strings.HasSuffix(o.expiresAt, "Z") {
		t.Fatalf("expires_at %q is not RFC 3339 in UTC: %v", o.expiresAt, err)
	}
	if expires.Before(before.Add(90*time.Minute).Truncate(time.Second)) || expires.After(after.Add(90*time.Minute)) {
		t.Errorf("expires_at %s is not 90 minutes after the opening", o.expiresAt)
	}
	o.secret(t)
	run, err := resolve(t, dir, o.token, who)
	if err != nil {
		t.Fatalf("the printed token does not resolve: %v", err)
	}
	if run.ID != o.runID || run.Root != o.root || !run.Expires.Equal(expires) || run.Who != who {
		t.Errorf("the token resolves to %+v, not to what was printed %+v", run, o)
	}
}

// TestTheTokenResolvesForItsIdentityAlone: each flag lands in its own field
// of the run's identity, so a token presented under any other is refused.
func TestTheTokenResolvesForItsIdentityAlone(t *testing.T) {
	dir := runsDir(t)
	o := openRun(t, dir, who, "1h")
	for name, other := range map[string]runs.Identity{
		"another project":        {ProjectID: "billing", TenantID: who.TenantID, PrincipalType: who.PrincipalType, PrincipalID: who.PrincipalID, AgentID: who.AgentID},
		"no project":             {TenantID: who.TenantID, PrincipalType: who.PrincipalType, PrincipalID: who.PrincipalID, AgentID: who.AgentID},
		"project and tenant":     {ProjectID: who.TenantID, TenantID: who.ProjectID, PrincipalType: who.PrincipalType, PrincipalID: who.PrincipalID, AgentID: who.AgentID},
		"another tenant":         {ProjectID: who.ProjectID, TenantID: "globex", PrincipalType: who.PrincipalType, PrincipalID: who.PrincipalID, AgentID: who.AgentID},
		"another principal type": {ProjectID: who.ProjectID, TenantID: who.TenantID, PrincipalType: "service", PrincipalID: who.PrincipalID, AgentID: who.AgentID},
		"principal and agent":    {ProjectID: who.ProjectID, TenantID: who.TenantID, PrincipalType: who.PrincipalType, PrincipalID: who.AgentID, AgentID: who.PrincipalID},
	} {
		var refusal *runs.Refusal
		if _, err := resolve(t, dir, o.token, other); !errors.As(err, &refusal) || refusal.Cause != runs.CauseIdentity {
			t.Errorf("%s: the token resolved with %v, want a refusal for its identity", name, err)
		}
	}
}

// TestRunsOpenUnderAParent: a run opened under another gets an id of its own
// and the parent's root.
func TestRunsOpenUnderAParent(t *testing.T) {
	dir := runsDir(t)
	o := openRun(t, dir, who, "1h")
	child := openRun(t, dir, who, "1m", "--parent", o.runID)
	if !runIDShape.MatchString(child.runID) || child.runID == o.runID || child.root != o.root {
		t.Errorf("a child printed run_id %q and root %q; want a new id under root %q", child.runID, child.root, o.root)
	}
	if run, err := resolve(t, dir, child.token, who); err != nil || run.ID != child.runID || run.Root != o.root {
		t.Errorf("the child's token resolves to %+v, %v", run, err)
	}
}

// TestTheTokenIsPrintedOnce: after runs open printed it, neither the token nor
// its secret shows in any output, a refusal of a token given where a run id
// belongs included, nor in any file under the directory.
func TestTheTokenIsPrintedOnce(t *testing.T) {
	dir := runsDir(t)
	o := openRun(t, dir, who, "1h")
	secret := o.secret(t)
	var seen []string
	call := func(args ...string) {
		_, stdout, stderr := invoke(t, args...)
		seen = append(seen, stdout, stderr)
	}
	call("runs", "list", dir)
	call(openArgs(dir, who, "1h", "--parent", o.token)...)
	call(openArgs(dir, who, "1h", "--parent", secret)...)
	call("runs", "close", dir, o.token)
	call("runs", "close", dir, secret)
	call("runs", "close", dir, o.runID)
	call("runs", "close", dir, o.runID)
	call("runs", "list", dir)
	for _, out := range seen {
		if leaks(out, secret) {
			t.Errorf("output %q repeats part of the secret", out)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: a file of the test's own directory
		if err != nil {
			t.Fatal(err)
		}
		if leaks(string(raw), secret) {
			t.Errorf("%s holds part of the secret", e.Name())
		}
	}
}

// leaks reports whether out holds any eight characters of secret in a row.
func leaks(out, secret string) bool {
	for i := 0; i+8 <= len(secret); i++ {
		if strings.Contains(out, secret[i:i+8]) {
			return true
		}
	}
	return false
}

// TestRunsOpenRefusesAndWritesNothing: every refusal leaves the directory with
// the records it had. A missing flag or a malformed value is a usage error; a
// lifetime one step past either bound, an identity, a parent that is unknown,
// closed, another tenant's or another project's, and a child that would
// outlive its parent are refusals of the input, each naming what was
// refused. Each bound also lets its own value through.
func TestRunsOpenRefusesAndWritesNothing(t *testing.T) {
	dir := runsDir(t)
	parent := openRun(t, dir, who, "1h")
	closed := openRun(t, dir, who, "1h")
	if code, _, stderr := invoke(t, "runs", "close", dir, closed.runID); code != exitOK {
		t.Fatalf("closing a fixture answered %d: %s", code, stderr)
	}
	other := who
	other.TenantID = "globex"
	foreign := openRun(t, dir, other, "1h")
	unknown := "run-" + strings.Repeat("ab", 16)

	cases := map[string]struct {
		args []string
		code int
		want string
	}{
		"a ttl of 59s":           {openArgs(dir, who, "59s"), exitFail, "lifetime is outside its bounds: 59s"},
		"a ttl of 720h1m":        {openArgs(dir, who, "720h1m"), exitFail, "lifetime is outside its bounds: 720h1m0s"},
		"a ttl of zero":          {openArgs(dir, who, "0s"), exitFail, "lifetime is outside its bounds"},
		"a ttl that is no time":  {openArgs(dir, who, "soon"), exitUsage, `invalid value "soon" for flag -ttl`},
		"an empty principal":     {openArgs(dir, who, "1h", "--principal", ""), exitFail, "the identity has an empty"},
		"an empty project":       {openArgs(dir, who, "1h", "--project", ""), exitFail, "project_id is 0 bytes"},
		"another project's":      {openArgs(dir, who, "1h", "--project", "billing", "--parent", parent.runID), exitFail, "belongs to another project"},
		"an unknown parent":      {openArgs(dir, who, "1h", "--parent", unknown), exitFail, "the parent run does not exist: " + unknown},
		"a closed parent":        {openArgs(dir, who, "1h", "--parent", closed.runID), exitFail, "the parent run is closed"},
		"another tenant's":       {openArgs(dir, who, "1h", "--parent", foreign.runID), exitFail, "belongs to another tenant"},
		"outliving the parent":   {openArgs(dir, who, "2h", "--parent", parent.runID), exitFail, "would outlive its parent"},
		"a parent that is no id": {openArgs(dir, who, "1h", "--parent", "run-1"), exitFail, "--parent is not a run id"},
		"no directory":           {append([]string{"runs", "open"}, openFlags(who, "1h")...), exitUsage, "takes the runs directory"},
		"a flag after the dir":   {append(openArgs(dir, who, "1h"), "--parent", parent.runID), exitUsage, "takes the runs directory"},
	}
	for i, name := range []string{"--project", "--tenant", "--principal-type", "--principal", "--agent", "--ttl"} {
		flags := openFlags(who, "1h")
		args := append(append([]string{"runs", "open"}, append(flags[:2*i:2*i], flags[2*i+2:]...)...), dir)
		cases["no "+name] = struct {
			args []string
			code int
			want string
		}{args, exitUsage, name + " is missing"}
	}
	records := recordNames(t, dir)
	for name, c := range cases {
		code, stdout, stderr := invoke(t, c.args...)
		if code != c.code || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q; want %d and nothing", name, code, stdout, c.code)
		}
		if !strings.Contains(stderr, c.want) || !strings.HasPrefix(stderr, brand.CLI+": runs open: ") && c.code == exitFail {
			t.Errorf("%s: stderr %q, want a line saying %q", name, stderr, c.want)
		}
		if got := recordNames(t, dir); got != records {
			t.Errorf("%s: the directory's records went from %s to %s", name, records, got)
		}
	}
	openRun(t, dir, who, "1m", "--parent", parent.runID)
	openRun(t, dir, who, "720h")
}

// recordNames lists the records under dir, in the order the directory gives.
func recordNames(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.run.json"))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(matches)
}

// TestRunsCloseThenList: a closed run lists as closed beside one still open.
func TestRunsCloseThenList(t *testing.T) {
	dir := runsDir(t)
	a, b := openRun(t, dir, who, "2h"), openRun(t, dir, who, "2h")
	code, stdout, stderr := invoke(t, "runs", "close", dir, a.runID)
	if code != exitOK || stdout != "closed "+a.runID+"\n" || stderr != "" {
		t.Errorf("close answered %d, %q, %q", code, stdout, stderr)
	}
	code, stdout, stderr = invoke(t, "runs", "list", dir)
	if code != exitOK || stderr != "" {
		t.Fatalf("list answered %d: %q", code, stderr)
	}
	want := map[string]string{a.runID: "closed", b.runID: "open"}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("list printed %q, want two lines", stdout)
	}
	for _, line := range lines {
		id, rest, _ := strings.Cut(line, " ")
		if state, _, _ := strings.Cut(rest, " "); want[id] == "" || state != want[id] {
			t.Errorf("line %q, want run %s %s", line, id, want[id])
		}
	}
}

// TestRunsCloseRefusals: closing a closed run, an id no record names and a
// malformed id each fail and print nothing on stdout.
func TestRunsCloseRefusals(t *testing.T) {
	dir := runsDir(t)
	a := openRun(t, dir, who, "1h")
	if code, _, stderr := invoke(t, "runs", "close", dir, a.runID); code != exitOK {
		t.Fatalf("close answered %d: %s", code, stderr)
	}
	for name, c := range map[string]struct{ id, want string }{
		"again":       {a.runID, "the run is closed already: " + a.runID},
		"an unknown":  {"run-" + strings.Repeat("0", 32), "no such run"},
		"a malformed": {"run-XYZ", "the argument is not a run id"},
	} {
		code, stdout, stderr := invoke(t, "runs", "close", dir, c.id)
		if line := oneStderrLine(t, stderr); code != exitFail || stdout != "" || !strings.HasPrefix(line, brand.CLI+": runs close: ") || !strings.Contains(line, c.want) {
			t.Errorf("closing %s: exit %d, stdout %q, stderr %q; want 1 and %q", name, code, stdout, line, c.want)
		}
	}
}

// TestRunsListPrintsEachField: a line holds every field of the run, the
// opening time being the expiry less the lifetime asked for.
func TestRunsListPrintsEachField(t *testing.T) {
	dir := runsDir(t)
	a, err := runs.InitAdmin(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := invoke(t, "runs", "list", dir); code != exitOK || stdout != "no runs\n" || stderr != "" {
		t.Errorf("a runs directory with no run lists as %d, %q, %q", code, stdout, stderr)
	}
	o := openRun(t, dir, who, "3h")
	expires, err := time.Parse(time.RFC3339Nano, o.expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	opened := expires.Add(-3 * time.Hour).Format(time.RFC3339Nano)
	want := o.runID + " open root " + o.runID + " project_id orders tenant_id acme principal_type user principal_id alice agent_id planner" +
		" opened_at " + opened + " expires_at " + o.expiresAt + "\n"
	if code, stdout, stderr := invoke(t, "runs", "list", dir); code != exitOK || stdout != want || stderr != "" {
		t.Errorf("list answered %d, %q, %q; want %q", code, stdout, stderr, want)
	}
}
