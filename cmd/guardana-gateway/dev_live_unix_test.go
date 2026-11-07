//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/scenario"
)

// callOnce makes one call to the plane at mcpURL as an agent does, and reads
// the answer the way the scenario runner reads one.
func callOnce(t *testing.T, mcpURL, tool, id string) answered {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "dev-test", Version: "0"}, nil).Connect(ctx,
		&sdk.StreamableClientTransport{Endpoint: mcpURL}, &sdk.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatalf("connecting to %s: %v", mcpURL, err)
	}
	defer func() { _ = cs.Close() }()
	res, callErr := cs.CallTool(ctx, &sdk.CallToolParams{Name: tool, Arguments: map[string]any{"id": id}})
	a, err := classify(res, callErr)
	if err != nil {
		t.Fatalf("calling %s: %v", tool, err)
	}
	return a
}

// devDemo starts one interactive dev over a fresh demo and waits for it.
func devDemo(t *testing.T, linger string) (*devProcess, map[string]string, string) {
	t.Helper()
	d := writeDemo(t, newLiveUpstream(t).url, linger, "")
	state := filepath.Join(t.TempDir(), "state")
	p := startDev(t, "--config", d.config, "--policy", d.policy, "--state", state)
	return p, p.ready(t), state
}

// processText is a process's arguments and environment as another process
// of the same user reads them: from /proc where the system has it, else from
// ps. Text that holds neither the command's name nor a PATH variable is not
// what was asked for, and fails the test.
func processText(t *testing.T, pid int) string {
	t.Helper()
	var text string
	args, errArgs := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	env, errEnv := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if errArgs == nil && errEnv == nil {
		text = string(args) + "\n" + string(env)
	} else {
		out, err := exec.Command("ps", "-E", "-ww", "-o", "command=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec // G204: ps over a process this test started
		if err != nil {
			t.Fatalf("ps -E -p %d: %v", pid, err)
		}
		text = string(out)
	}
	if !strings.Contains(text, brand.Gateway) && !strings.Contains(text, brand.CLI) || !strings.Contains(text, "PATH=") {
		t.Fatalf("what the system shows of %d holds no command or no environment: %q", pid, text)
	}
	return text
}

// refused reports whether nothing answers at addr any more.
func refused(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = conn.Close()
	}
	return err != nil
}

// TestDevStopsWhenThePageDies: the page interrupted, which it answers by
// exiting 0, dev still stops every part in order and exits 1: a call
// answered just before is in the trail file although the exporter holds each
// batch for a second, dev says what the spool still holds, and nothing
// answers where the plane listened. The last check alone holds whatever dev
// does, since the system closes an exited process's listeners.
func TestDevStopsWhenThePageDies(t *testing.T) {
	t.Parallel()
	p, values, state := devDemo(t, "1s")
	a := callOnce(t, values["mcp"], "read_order", "ord-1")
	if a.kind != scenario.AnswerResult {
		t.Fatalf("the read answered %+v", a)
	}
	if err := syscall.Kill(p.pagePID(t), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if code := p.exit(t, 20*time.Second); code != exitFail || !strings.Contains(p.stderr.String(), "console exited, so dev stopped every part") {
		t.Fatalf("exit %d, want 1 naming the page:\n%s", code, p.stderr.String())
	}
	trail, err := readTrail(filepath.Join(state, "trail"), false)
	if err != nil {
		t.Fatal(err)
	}
	events, err := trail.trail(a.requestID)
	if err != nil || kindList(kindsOf(events)) != "[ACTION_PROPOSED, POLICY_DECIDED, ACTION_STARTED, ACTION_COMPLETED]" {
		t.Fatalf("the trail of the last call is %s, %v", kindList(kindsOf(events)), err)
	}
	if !strings.Contains(p.stdout.String(), "\nunshipped: 0 bytes the collector did not acknowledge are left in ") {
		t.Errorf("dev did not say what the spool holds:\n%s", p.stdout.String())
	}
	for _, name := range []string{"mcp", "healthz"} {
		addr := strings.TrimPrefix(strings.TrimSuffix(values[name], "/healthz"), "http://")
		if !refused(addr) {
			t.Errorf("%s at %s still answers after dev exited", name, addr)
		}
	}
}

// TestDevRenewsEveryThirdOfTheSmallerBudget: a document whose
// maxStaleSeconds is below the operator's policy.max_stale is renewed every
// third of the document's budget, which dev says; the plane starts
// confirmed by the statement dev wrote before it, and a later statement
// replaces it on disk without a new bundle.
func TestDevRenewsEveryThirdOfTheSmallerBudget(t *testing.T) {
	t.Parallel()
	d := writeDemo(t, newLiveUpstream(t).url, "5ms", "")
	rewrite(t, d.config, "  bundle_id: scenario-fixture\n", "  bundle_id: scenario-fixture\n  max_stale: 30m\n")
	rewrite(t, d.policy, `"maxStaleSeconds":600`, `"maxStaleSeconds":6`)
	state := filepath.Join(t.TempDir(), "state")
	p := startDev(t, "--config", d.config, "--policy", d.policy, "--state", state)
	values := p.ready(t)
	settings, err := os.ReadFile(filepath.Join(state, "settings.txt")) //nolint:gosec // G304: the state directory this test's dev laid out
	if err != nil || !slices.ContainsFunc(lines(string(settings)), func(l string) bool { return strings.HasPrefix(l, "policy.max_stale: 30m") }) {
		t.Fatalf("the operator's budget is not in the settings dev resolved: %v\n%s", err, settings)
	}
	if want := "every 2s of the 6s budget; a statement confirms the policy for the budget"; values["renewal"] != want {
		t.Errorf("renewal is %q, want %q", values["renewal"], want)
	}
	if values["statement"] != filepath.Join(state, "policy.statement") || values["state_dir"] != filepath.Join(state, "floors") {
		t.Errorf("statement %q, state_dir %q; want them under %s", values["statement"], values["state_dir"], state)
	}
	changes(t, values["statement"], 10*time.Second)
}

// rewrite replaces the first from in the file at path with to, and fails
// when the file holds no from.
func rewrite(t *testing.T, path, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), from) {
		t.Fatalf("%s holds no %q", path, from)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), from, to, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// changes fails unless the file at path holds other bytes within limit.
func changes(t *testing.T, path string, limit time.Duration) {
	t.Helper()
	first, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(limit)
	for {
		now, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
		if err == nil && !bytes.Equal(now, first) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not change within %v: %v", path, limit, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestThePageStopsWhenDevIsKilled: dev killed with no chance to stop
// anything, the page sees its input end and exits within two seconds.
func TestThePageStopsWhenDevIsKilled(t *testing.T) {
	t.Parallel()
	p, _, _ := devDemo(t, "5ms")
	page := p.pagePID(t)
	if err := p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if !gone(page, 2*time.Second) {
		_ = syscall.Kill(page, syscall.SIGKILL)
		t.Fatalf("the page %d still runs two seconds after dev was killed", page)
	}
}

// TestDevDrainsOnAnInterrupt: a call answered just before the interrupt is
// in the trail file once dev exits 0, although the exporter holds each batch
// for a second before it sends it, and dev says what the spool still holds.
func TestDevDrainsOnAnInterrupt(t *testing.T) {
	t.Parallel()
	p, values, state := devDemo(t, "1s")
	a := callOnce(t, values["mcp"], "read_order", "ord-1")
	if a.kind != scenario.AnswerResult {
		t.Fatalf("the read answered %+v", a)
	}
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if code := p.exit(t, 20*time.Second); code != exitOK {
		t.Fatalf("exit %d after an interrupt, want 0:\n%s", code, p.stderr.String())
	}
	trail, err := readTrail(filepath.Join(state, "trail"), false)
	if err != nil {
		t.Fatal(err)
	}
	events, err := trail.trail(a.requestID)
	if err != nil || kindList(kindsOf(events)) != "[ACTION_PROPOSED, POLICY_DECIDED, ACTION_STARTED, ACTION_COMPLETED]" {
		t.Fatalf("the trail of the last call is %s, %v", kindList(kindsOf(events)), err)
	}
	if !strings.Contains(p.stdout.String(), "\nunshipped: 0 bytes the collector did not acknowledge are left in ") {
		t.Errorf("dev did not say what the spool holds:\n%s", p.stdout.String())
	}
}

// stateNames is every name directly under a state directory, in name order.
func stateNames(t *testing.T, state string) []string {
	t.Helper()
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// stateFiles is the content of every file under a state directory, by path.
// Fewer than the four files dev writes at its start is a walk that examined
// too little, and fails the test.
func stateFiles(t *testing.T, state string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(state, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path) //nolint:gosec // G122: the state directory this test's dev laid out
		files[path] = raw
		return err
	})
	if err != nil || len(files) < 4 {
		t.Fatalf("the walk of %s read %d files: %v", state, len(files), err)
	}
	return files
}

// TestTheTokenStaysOnDevsStdout: the page's token is on dev's standard
// output and nowhere else dev reaches: not in the page's arguments, not in
// either process's environment, in no file under the state directory and
// not in dev's log. The system shows a process's environment as it started,
// and the page draws its token after it starts, so the process checks catch
// only a token handed to the page, or to dev, at its start; dev starts no
// process after the page. The state directory holds the names dev.md lists
// and no file under it but the dev operator's key, readable by this account
// alone, holds a private key as PEM or PKCS#8, raw or base64; a key written
// in another form is caught only by a name the list lacks.
func TestTheTokenStaysOnDevsStdout(t *testing.T) {
	t.Parallel()
	p, values, state := devDemo(t, "5ms")
	_, token, ok := strings.Cut(values["page"], "/#t=")
	if !ok || len(token) != 43 || !strings.Contains(p.stdout.String(), token) {
		t.Fatalf("no token on dev's stdout: %q", values["page"])
	}
	for _, pid := range []int{p.pagePID(t), p.cmd.Process.Pid} {
		if strings.Contains(processText(t, pid), token) {
			t.Errorf("the arguments or the environment of %d carry the token", pid)
		}
	}
	if names, want := stateNames(t, state), []string{"approvals", "floors", "holds", "inbox", "operator", "pause", "pausefloor", "policy.bundle", "policy.statement", "settings.txt", "spool", "trail", "trust"}; !slices.Equal(names, want) {
		t.Errorf("the state directory holds %q, want %q", names, want)
	}
	prefix := []byte(policykey.PKCS8Prefix)
	unwritten := map[string][]byte{
		"the page's token":                 []byte(token),
		"a PEM private key block":          []byte("PRIVATE" + " KEY"),
		"the PKCS#8 prefix of a key":       prefix,
		"the base64 of a key body's start": []byte(base64.StdEncoding.EncodeToString(prefix[:len(prefix)/3*3])),
	}
	operatorKey := ownerOnly(t, filepath.Join(state, "operator", "signing.key"))
	for path, raw := range stateFiles(t, state) {
		if path == operatorKey {
			continue
		}
		for what, text := range unwritten {
			if bytes.Contains(raw, text) {
				t.Errorf("%s holds %s", path, what)
			}
		}
	}
	if strings.Contains(p.stderr.String(), token) {
		t.Error("dev's log carries the token")
	}
}

// ownerOnly fails unless path is a file only this account may read, and
// returns it.
func ownerOnly(t *testing.T, path string) string {
	t.Helper()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("%s: %v %v, want a file only this account reads", path, info, err)
	}
	return path
}
