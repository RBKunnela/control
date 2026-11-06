//go:build unix

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
)

// lockedBuffer is a buffer two goroutines may use.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// interactiveDev is one run of dev with no scenario.
type interactiveDev struct {
	cmd            *exec.Cmd
	stdout, stderr *lockedBuffer
	exited         chan struct{}
}

// startInteractiveDev starts dev over the demo with no scenario, as the
// tutorial does, and returns its `name: value` lines once it is ready.
func startInteractiveDev(t *testing.T) (*interactiveDev, map[string]string) {
	t.Helper()
	gateway, config := builtDemo(t)
	policy, err := filepath.Abs("policy.json")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gateway, "dev", "--config", config, "--policy", policy, "--decision-point=silent", "--state", filepath.Join(t.TempDir(), "state")) //nolint:gosec // G204: the binary this test built
	cmd.Env = environ()
	stdout, stderr := &lockedBuffer{}, &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	d := &interactiveDev{cmd: cmd, stdout: stdout, stderr: stderr, exited: exited}
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
	})
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(stdout.String(), "\nscenario_command: ") {
		select {
		case <-exited:
			t.Fatalf("dev exited before it was ready:\n%s\n%s", stdout.String(), stderr.String())
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("dev was not ready within 30s:\n%s\n%s", stdout.String(), stderr.String())
		}
	}
	values := map[string]string{}
	s := bufio.NewScanner(strings.NewReader(stdout.String()))
	for s.Scan() {
		if name, value, ok := strings.Cut(s.Text(), ": "); ok {
			values[name] = value
		}
	}
	return d, values
}

// answer is what call.sh printed, read as the JSON-RPC answer it is.
type answer struct {
	Result struct {
		Meta    map[string]any `json:"_meta"`
		IsError bool           `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	} `json:"result"`
}

func (a answer) meta(name string) string {
	s, _ := a.Result.Meta[brand.OTelNamespace+"/"+name].(string)
	return s
}

// callScript runs call.sh the way the tutorial does.
func callScript(t *testing.T, mcp, tool, args string) answer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "./call.sh", mcp, tool, args).Output() //nolint:gosec // G204: this package's own script
	if err != nil {
		t.Fatalf("call.sh %s: %v\n%s", tool, err, out)
	}
	var a answer
	if err := json.Unmarshal(out, &a); err != nil {
		t.Fatalf("call.sh %s printed %q, which is not one JSON-RPC answer: %v", tool, out, err)
	}
	return a
}

// TestTheTutorialsCallsBehaveAsItSays: on one interactive plane, the read
// runs, the update is held, an approval lets the same update resume on the
// held request, the trail command finds both requests whole, and the
// counters show two executions and one hold. The page is not driven here: the
// approval is signed with the approvals command the page names.
func TestTheTutorialsCallsBehaveAsItSays(t *testing.T) {
	d, v := startInteractiveDev(t)
	read := callScript(t, v["mcp"], "read_order", `{"id":"ord-1"}`)
	if read.Result.IsError || len(read.Result.Content) != 1 || !strings.HasPrefix(read.Result.Content[0].Text, "order ord-1: ") {
		t.Fatalf("the read answered %+v", read)
	}
	update := `{"id":"ord-1","status":"cancelled"}`
	held := callScript(t, v["mcp"], "update_order", update)
	if held.meta("answer") != "pending" || held.meta("approval_id") == "" || held.meta("request_id") == "" {
		t.Fatalf("the update answered %+v, want pending with an approval id", held)
	}
	gateway, _ := builtDemo(t)
	approve(t, filepath.Join(filepath.Dir(gateway), brand.CLI), v, held.meta("approval_id"))
	resumed := callScript(t, v["mcp"], "update_order", update)
	if resumed.Result.IsError || resumed.meta("answer") != "" || resumed.meta("request_id") != held.meta("request_id") {
		t.Fatalf("the retry answered %+v, want a result on request %s", resumed, held.meta("request_id"))
	}
	requireRecorded(t, gateway, v, read.meta("request_id"), held.meta("request_id"))
	d.interrupt(t)
}

// requireRecorded requires the trail command to name every request and the
// counters to show two executions and one hold.
func requireRecorded(t *testing.T, gateway string, v map[string]string, requests ...string) {
	t.Helper()
	trailOut := waitForTrail(t, gateway, v["trail"])
	for _, id := range requests {
		if !strings.Contains(trailOut, "request="+id+" ") {
			t.Errorf("the trail command does not name request %s:\n%s", id, trailOut)
		}
	}
	metrics := get(t, v["metrics"])
	for _, want := range []string{"_pipeline_executed_total 2\n", "_pipeline_pending_total 1\n"} {
		if !strings.Contains(metrics, want) {
			t.Errorf("/metrics lacks %q:\n%s", want, metrics)
		}
	}
}

// approve signs an approval with the approvals command and the dev
// operator's key, which is what the page names for a dev plane's hold.
func approve(t *testing.T, control string, v map[string]string, id string) {
	t.Helper()
	cmd := exec.Command(control, "approvals", "approve", "--key", v["operator_key"], "--inbox", v["inbox"], v["approvals"], id) //nolint:gosec // G204: the binary this test built
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("approving: %v\n%s", err, out)
	}
}

// interrupt interrupts dev and requires it to exit 0 within twenty seconds.
func (d *interactiveDev) interrupt(t *testing.T) {
	t.Helper()
	if err := d.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.exited:
	case <-time.After(20 * time.Second):
		t.Fatalf("dev did not exit within 20s of an interrupt:\n%s\n%s", d.stdout.String(), d.stderr.String())
	}
	if code := d.cmd.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("dev exited %d after an interrupt, want 0:\n%s\n%s", code, d.stdout.String(), d.stderr.String())
	}
}

// waitForTrail runs the trail command until it finds two whole trails, the
// spool having shipped them, within ten seconds.
func waitForTrail(t *testing.T, gateway, trail string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, err := exec.Command(gateway, "trail", trail).CombinedOutput() //nolint:gosec // G204: the binary this test built
		if err == nil && strings.Contains(string(out), "trails 2: ok 2,") {
			return string(out)
		}
		if time.Now().After(deadline) {
			t.Fatalf("the trail command did not find two whole trails within 10s: %v\n%s", err, out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func get(t *testing.T, url string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d, %v", url, resp.StatusCode, err)
	}
	return string(body)
}
