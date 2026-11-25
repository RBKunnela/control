//go:build unix

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	adaptermcp "github.com/guardana/control/adapters/mcp"
)

// stdioPlane is the built gateway serving one run over its standard streams,
// with what it wrote to standard output that is not a protocol message kept
// apart, so the protocol reaches the agent either way.
type stdioPlane struct {
	cmd    *exec.Cmd
	cs     *sdk.ClientSession
	stray  *syncBuffer
	stderr *syncBuffer
	// drained is closed once split has read the plane's standard output to its
	// end, which Wait may not close before: a line written at shutdown would
	// otherwise be lost.
	drained chan struct{}
	done    chan error
	once    sync.Once
}

// stdioAgent starts a stdio plane serving the run whose token tokenFile holds
// and connects an agent to it.
func (rp *runsPlane) stdioAgent(tokenFile string) *stdioPlane {
	rp.t.Helper()
	cmd := exec.Command(rp.gateway, "run", "--config", rp.config, "--run-token-file", tokenFile) //nolint:gosec // G204: the binary this test built
	cmd.Env = environ()
	sp := &stdioPlane{cmd: cmd, stray: &syncBuffer{}, stderr: &syncBuffer{}, drained: make(chan struct{}), done: make(chan error, 1)}
	cmd.Stderr = sp.stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		rp.t.Fatalf("the plane's stdin: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		rp.t.Fatalf("the plane's stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		rp.t.Fatalf("starting the stdio plane: %v", err)
	}
	protocol, toAgent := io.Pipe()
	go sp.split(stdout, toAgent)
	go func() {
		<-sp.drained
		sp.done <- cmd.Wait()
	}()
	rp.t.Cleanup(func() { sp.stop(rp.t) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sp.cs, err = sdk.NewClient(&sdk.Implementation{Name: "stdio-agent", Version: "0"}, nil).Connect(ctx,
		&sdk.IOTransport{Reader: protocol, Writer: stdin}, &sdk.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		rp.t.Fatalf("connecting to the stdio plane: %v\nits stderr:\n%s", err, sp.stderr.String())
	}
	return sp
}

// split hands the agent every line that is a JSON value and keeps the rest,
// reading to the end even after the agent has gone, so every stray line the
// plane writes is kept.
func (sp *stdioPlane) split(stdout io.Reader, toAgent *io.PipeWriter) {
	defer close(sp.drained)
	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 64<<10), 4<<20)
	agentGone := false
	for s.Scan() {
		line := s.Bytes()
		if json.Valid(line) {
			if !agentGone {
				_, err := toAgent.Write(append(line, '\n'))
				agentGone = err != nil
			}
			continue
		}
		_, _ = sp.stray.Write(append(line, '\n'))
	}
	_ = toAgent.CloseWithError(s.Err())
}

// stop ends the agent's session, which closes the plane's stdin, and waits
// for the plane to exit; past the bound it is killed. A second stop has
// nothing left to do.
func (sp *stdioPlane) stop(t *testing.T) {
	t.Helper()
	sp.once.Do(func() {
		if sp.cs != nil {
			_ = sp.cs.Close()
		}
		select {
		case <-sp.done:
		case <-time.After(15 * time.Second):
			_ = sp.cmd.Process.Kill()
			<-sp.done
			t.Errorf("the stdio plane did not stop within its bound:\n%s", sp.stderr.String())
		}
	})
}

// TestAStdioPlaneWritesOnlyTheProtocolToStandardOutput: a stdio plane's
// standard output is the agent's protocol stream, so a line that is not a
// JSON-RPC message ends the agent's session at its first read.
func TestAStdioPlaneWritesOnlyTheProtocolToStandardOutput(t *testing.T) {
	rp := newRunsPlane(t, "stdio")
	run := rp.open()
	sp := rp.stdioAgent(writeToken(t, t.TempDir(), "run.token", run.token, 0o600))
	expectRan(t, "a call", callTool(t, sp.cs, toolSendMail))
	sp.stop(t)
	if stray := strings.TrimSpace(sp.stray.String()); stray != "" {
		t.Errorf("the plane wrote to its protocol stream lines that are not JSON-RPC:\n%s", stray)
	}
}

// TestAStdioPlaneStoppedBySIGTERMExitsZero: a stop by signal, the agent
// still connected, is a clean stop: the listener answering it with the
// context's error is not a failure of the run.
func TestAStdioPlaneStoppedBySIGTERMExitsZero(t *testing.T) {
	rp := newRunsPlane(t, "stdio")
	run := rp.open()
	sp := rp.stdioAgent(writeToken(t, t.TempDir(), "run.token", run.token, 0o600))
	expectRan(t, "a call", callTool(t, sp.cs, toolSendMail))
	sp.once.Do(func() {
		if err := sp.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-sp.done:
			if err != nil {
				t.Errorf("the plane stopped by SIGTERM: %v, want exit 0:\n%s", err, sp.stderr.String())
			}
		case <-time.After(15 * time.Second):
			_ = sp.cmd.Process.Kill()
			<-sp.done
			t.Errorf("the stdio plane did not stop within 15s of SIGTERM:\n%s", sp.stderr.String())
		}
	})
}

// TestARunClosedUnderAStdioPlaneIsRefusedAtTheNextMessage: a stdio plane
// judges its one token again at every message, so once the operator closes
// the run the next call is answered with the run refusal and never sent.
func TestARunClosedUnderAStdioPlaneIsRefusedAtTheNextMessage(t *testing.T) {
	rp := newRunsPlane(t, "stdio")
	run := rp.open()
	sp := rp.stdioAgent(writeToken(t, t.TempDir(), "run.token", run.token, 0o600))
	expectRan(t, "the call before the close", callTool(t, sp.cs, toolSendMail))

	rp.closeRun(run.id)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := sp.cs.CallTool(ctx, &sdk.CallToolParams{Name: toolSendMail, Arguments: map[string]any{"to": "orders-backup@example.net"}})
	var refusal *jsonrpc.Error
	if !errors.As(err, &refusal) || refusal.Code != adaptermcp.CodeRunRefused {
		t.Errorf("the call after the close was answered %+v, %v; want the JSON-RPC error %d", res, err, adaptermcp.CodeRunRefused)
	}
	if ran := rp.up.count(toolSendMail); ran != 1 {
		t.Errorf("the upstream ran send_mail %d time(s), want the one before the close", ran)
	}
}
