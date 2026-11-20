//go:build unix

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/attempts"
)

// attemptTree is the demo laid out beside the binaries every live test
// shares, which TestMain removes: the victims in attempts/bin and the demo's
// files in attempts/examples/vulnerable-mcp-agent, where its command path
// reaches them.
var attemptTree struct {
	once sync.Once
	root string
	err  error
}

// demoDir is the demo's directory in the tree, built once for every test.
func demoDir(t *testing.T) string {
	t.Helper()
	gatewayBin, _ := builtBinaries(t)
	attemptTree.once.Do(func() {
		attemptTree.root = filepath.Join(filepath.Dir(gatewayBin), "attempts")
		attemptTree.err = buildAttemptTree(attemptTree.root)
	})
	if attemptTree.err != nil {
		t.Fatalf("building the demo: %v", attemptTree.err)
	}
	return filepath.Join(attemptTree.root, "examples", "vulnerable-mcp-agent")
}

func buildAttemptTree(root string) error {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("cannot resolve this file's own path")
	}
	repo := filepath.Dir(filepath.Dir(filepath.Dir(self)))
	cmd := exec.Command("go", "build", "-o", filepath.Join(root, "bin")+string(filepath.Separator), "./examples/vulnerable-mcp-agent") //nolint:gosec // G204: the go tool on this tree
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build: %w\n%s", err, out)
	}
	src := filepath.Join(repo, "examples", "vulnerable-mcp-agent")
	dst := filepath.Join(root, "examples", "vulnerable-mcp-agent")
	for _, sub := range []string{"scenarios", "attempts"} {
		if err := os.MkdirAll(filepath.Join(dst, sub), 0o750); err != nil {
			return err
		}
	}
	names, err := filepath.Glob(filepath.Join(src, "scenarios", "*.json"))
	if err != nil {
		return err
	}
	for _, name := range append(names, filepath.Join(src, "demo.yaml"), filepath.Join(src, "policy.json"), filepath.Join(src, "attempts", "manifest.json")) {
		raw, err := os.ReadFile(name) //nolint:gosec // G304: the demo's own files
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, rel), raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// attemptRun is one run of the built gateway's attempts command.
type attemptRun struct {
	code           int
	stdout, stderr string
	took           time.Duration
}

// runAttemptsCommand runs attempts run over manifest, writing report, with
// every plane's state under state, bounded by limit.
func runAttemptsCommand(t *testing.T, limit time.Duration, manifest, report, state string) attemptRun {
	t.Helper()
	demoDir(t)
	gateway, _ := builtBinaries(t)
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, gateway, "attempts", "run", "--manifest", manifest, "--report", report, "--state", state) //nolint:gosec // G204: the binary this test built
	cmd.Env = environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	started := time.Now()
	err := cmd.Run()
	r := attemptRun{stdout: stdout.String(), stderr: stderr.String(), took: time.Since(started)}
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		t.Fatalf("attempts run did not end within %v:\n%s\n%s", limit, r.stdout, r.stderr)
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	case err != nil:
		t.Fatalf("attempts run did not run: %v", err)
	}
	return r
}

// writeManifest writes body as a manifest in the demo's attempts directory
// under a name of its own, and returns its path.
func writeManifest(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(demoDir(t), "attempts", name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

// readBack is a report read back: the header, each attempt-run and the
// summary, which must be the last line.
type readBack struct {
	header  attempts.Header
	runs    []attempts.AttemptLine
	summary attempts.Summary
}

func readReport(t *testing.T, path string) readBack {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own report
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		lines = append(lines, append([]byte(nil), s.Bytes()...))
	}
	if len(lines) < 2 || !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatalf("the report holds %d lines:\n%s", len(lines), raw)
	}
	var r readBack
	decode := func(line []byte, into any) {
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(into); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
	decode(lines[0], &r.header)
	for _, line := range lines[1 : len(lines)-1] {
		var a attempts.AttemptLine
		decode(line, &a)
		r.runs = append(r.runs, a)
	}
	decode(lines[len(lines)-1], &r.summary)
	if r.header.Kind != attempts.ReportKind || r.header.Line != "header" || r.summary.Line != "summary" {
		t.Fatalf("the report opens with %q %q and closes with %q", r.header.Kind, r.header.Line, r.summary.Line)
	}
	return r
}

// run is the line of one attempt-run.
func (r readBack) run(t *testing.T, attempt, plane string) attempts.AttemptLine {
	t.Helper()
	for _, a := range r.runs {
		if a.Attempt == attempt && a.Plane == plane {
			return a
		}
	}
	t.Fatalf("the report has no run of %s on %s", attempt, plane)
	return attempts.AttemptLine{}
}

// journal is the lines a victim journalled in the run dir names, call and
// arguments as written.
func journal(t *testing.T, state, dir, server string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(state, dir, "journal", server+".jsonl")) //nolint:gosec // G304: the test's own state
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}
