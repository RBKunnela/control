package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func otlpFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "otlp", filepath.Base(name)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestCollectListensOnTheLoopbackOnly: every address that is not a loopback
// IP literal is refused before the file is opened, and the loopback one beside
// them is taken.
func TestCollectListensOnTheLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "[::]:0", ":0", "192.0.2.1:0", "localhost:0", "127.0.0.1", "[::1]", "127.0.0.1:x"} {
		out := filepath.Join(t.TempDir(), "trail")
		var stdout, stderr bytes.Buffer
		status := run(context.Background(), collectArgs(t, addr, out), &stdout, &stderr)
		if status != exitFail || !strings.Contains(stderr.String(), "loopback") {
			t.Errorf("--listen %s answered %d with %q, want %d naming the loopback", addr, status, stderr.String(), exitFail)
		}
		if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("--listen %s left a trail directory behind: %v", addr, err)
		}
	}
	c := startCollect(t, filepath.Join(t.TempDir(), "trail"))
	c.stop(t)
	// A host may have no IPv6 loopback to bind, so the address alone is judged.
	for _, addr := range []string{"[::1]:4318", "127.0.0.2:4318", "127.0.0.1:65535"} {
		if err := loopbackOnly(addr); err != nil {
			t.Errorf("loopbackOnly(%s) = %v", addr, err)
		}
	}
	if err := loopbackOnly("127.0.0.1:65536"); err == nil {
		t.Error("a port past 16 bits was taken")
	}
}

// TestCollectNeedsEveryFlagAndNothingElse: each required flag left out, an
// argument after them and a flag collect does not take are refused before
// anything is opened.
func TestCollectNeedsEveryFlagAndNothingElse(t *testing.T) {
	full := collectArgs(t, "127.0.0.1:0", filepath.Join(t.TempDir(), "trail"))
	for i := 1; i < len(full); i += 2 {
		args := slices.Concat(full[:i], full[i+2:])
		var stdout, stderr bytes.Buffer
		if status := run(context.Background(), args, &stdout, &stderr); status != exitUsage || !strings.Contains(stderr.String(), full[i]) {
			t.Errorf("without %s: answered %d with %q, want %d naming it", full[i], status, stderr.String(), exitUsage)
		}
	}
	for _, args := range [][]string{append(slices.Clone(full), "extra"), {"collect", "--config", "x"}} {
		var stdout, stderr bytes.Buffer
		if status := run(context.Background(), args, &stdout, &stderr); status != exitUsage {
			t.Errorf("%q answered %d, want %d", args, status, exitUsage)
		}
	}
}

// TestCollectRefusesADirectoryItCannotHold: a trail directory the group may
// write is refused, and so is one another collect holds.
func TestCollectRefusesADirectoryItCannotHold(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil { //nolint:gosec // G302: the group-writable directory collect must refuse
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), collectArgs(t, "127.0.0.1:0", dir), &stdout, &stderr)
	if status != exitFail || !strings.Contains(stderr.String(), "only this account writes") {
		t.Errorf("a group-writable directory answered %d with %q", status, stderr.String())
	}

	out := filepath.Join(t.TempDir(), "trail")
	c := startCollect(t, out)
	stdout.Reset()
	stderr.Reset()
	status = run(context.Background(), collectArgs(t, "127.0.0.1:0", out), &stdout, &stderr)
	if status != exitFail || !strings.Contains(stderr.String(), "held by another writer") {
		t.Errorf("a second collect on one directory answered %d with %q", status, stderr.String())
	}
	c.stop(t)
}

// TestCollectWritesWhatArrivesUntilTheSignal: collect prints where it listens
// and what it writes, answers the exporter's golden request with 200 once the
// file holds its events, and stops when its context ends.
func TestCollectWritesWhatArrivesUntilTheSignal(t *testing.T) {
	out := filepath.Join(t.TempDir(), "trail")
	c := startCollect(t, out)
	if !strings.Contains(c.stdout.String(), out) || !strings.Contains(c.stdout.String(), "allow_plaintext") ||
		!strings.Contains(c.stdout.String(), "export.headers.Authorization: Bearer <the credential>") ||
		strings.Contains(c.stdout.String(), collectToken) {
		t.Errorf("collect printed %q, which does not name the directory, the plaintext setting and the header, or prints the credential", c.stdout.String())
	}
	if status := c.post(t, otlpFixture(t, "export_logs_request.json")); status != http.StatusOK {
		t.Fatalf("the golden request answered %d", status)
	}
	if got, want := liveSegment(t, out), otlpFixture(t, "events.jsonl"); !bytes.Equal(got, want) {
		t.Errorf("the trail holds\n%s\nwant\n%s", got, want)
	}
	c.stop(t)
	if _, err := http.Post(c.url, "application/json", strings.NewReader("{}")); err == nil {
		t.Error("the collector still answers after its context ended")
	}
}

// liveSegment is what the live segment of the trail in dir holds.
func liveSegment(t *testing.T, dir string) []byte {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dir, "live.jsonl")) //nolint:gosec // G304: the test's own temp directory
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return got
}

// TestCollectLeavesADirectoryThatIsNotATrail: --dir naming a directory of
// notes, or one whose live segment holds notes, is refused and left byte for
// byte as it was. A collect that took it would serve until its deadline and
// end 0, which fails here rather than hanging the suite.
func TestCollectLeavesADirectoryThatIsNotATrail(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"notes":                   {"notes.txt": "a note\nanother note"},
		"a live segment of notes": {"live.jsonl": "a note\n{half a record"},
	} {
		out := filepath.Join(t.TempDir(), "trail")
		if err := os.Mkdir(out, 0o700); err != nil {
			t.Fatal(err)
		}
		for file, body := range files {
			if err := os.WriteFile(filepath.Join(out, file), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		stdout, stderr := &syncBuffer{}, &syncBuffer{}
		done := make(chan int, 1)
		go func() { done <- run(ctx, collectArgs(t, "127.0.0.1:0", out), stdout, stderr) }()
		var status int
		select {
		case status = <-done:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatalf("%s: collect did not end within five seconds", name)
		}
		cancel()
		if status != exitFail {
			t.Errorf("%s: collect answered %d with %q, want %d", name, status, stderr.String(), exitFail)
		}
		for file, body := range files {
			if got, err := os.ReadFile(filepath.Join(out, file)); err != nil || string(got) != body { //nolint:gosec // G304: the test's own temp file
				t.Errorf("%s: the refused file holds %q (%v)", name, got, err)
			}
		}
	}
}

// TestCollectAnswersARequestInFlightAtTheSignal: a request whose body is
// still arriving when the context ends is read to its end, answered 200 once
// the file holds its events, and only then does collect stop.
func TestCollectAnswersARequestInFlightAtTheSignal(t *testing.T) {
	out := filepath.Join(t.TempDir(), "trail")
	c := startCollect(t, out)
	addr := strings.TrimSuffix(strings.TrimPrefix(c.url, "http://"), logsPath)
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	body := otlpFixture(t, "export_logs_request.json")
	head := "POST " + logsPath + " HTTP/1.1\r\nHost: " + addr + "\r\nAuthorization: Bearer " + collectToken +
		"\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n"
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatal(err)
	}
	// The server sends 100 Continue once its handler first reads the body, so
	// the request is in flight when the signal comes; the listener closing
	// says the shutdown has started.
	answers := bufio.NewReader(conn)
	interim, err := http.ReadResponse(answers, nil)
	if err != nil || interim.StatusCode != http.StatusContinue {
		t.Fatalf("the server did not ask for the body: %v %v", interim, err)
	}
	if _, err := conn.Write(body[:len(body)/2]); err != nil {
		t.Fatal(err)
	}
	c.cancel()
	waitClosed(t, addr)
	if _, err := conn.Write(body[len(body)/2:]); err != nil {
		t.Fatalf("the rest of the body could not be sent: %v", err)
	}
	resp, err := http.ReadResponse(answers, nil)
	if err != nil {
		t.Fatalf("no answer to the request in flight: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the request in flight answered %d, want 200", resp.StatusCode)
	}
	c.stop(t)
	if got, want := liveSegment(t, out), otlpFixture(t, "events.jsonl"); !bytes.Equal(got, want) {
		t.Errorf("the trail holds\n%s\nwant\n%s", got, want)
	}
}

// waitClosed waits until addr refuses a connection, for five seconds at most.
func waitClosed(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		probe, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return
		}
		_ = probe.Close()
		if time.Now().After(deadline) {
			t.Fatal("the listener still takes connections five seconds after the signal")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// collecting is a collect command a test started.
type collecting struct {
	url    string
	stdout *syncBuffer
	stderr *syncBuffer
	cancel context.CancelFunc
	done   chan int
}

// TestCollectPrintsTheDirectoryOnOneLine: a --dir holding a bidirectional
// control or a line or paragraph separator passes the argument check, since
// none is a control character, and the line naming it quotes it.
func TestCollectPrintsTheDirectoryOnOneLine(t *testing.T) {
	for _, r := range []rune{0x202e, 0x2028, 0x2029} {
		out := filepath.Join(t.TempDir(), "a"+string(r)+"txt.lmth")
		c := startCollect(t, out)
		c.stop(t)
		stdout := c.stdout.String()
		if strings.Contains(stdout, out) || !strings.Contains(stdout, "collect: appending to "+strconv.Quote(out)+" for tenant") {
			t.Errorf("U+%04X: collect printed %q, want --dir quoted", r, stdout)
		}
	}
}

// collectToken is the credential the collectors under test require.
var collectToken = strings.Repeat("q", 40)

// credentialFile writes token to a file only this account can read.
func credentialFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "collector.credential")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// collectArgs is a collect of the trail in dir on listen, bound to the
// fixture's tenant and project, requiring collectToken.
func collectArgs(t *testing.T, listen, dir string) []string {
	t.Helper()
	return []string{"collect", "--listen", listen, "--dir", dir, "--tenant", "tenant-1", "--project", "proj-1",
		"--credential-file", credentialFile(t, collectToken)}
}

func startCollect(t *testing.T, out string, extra ...string) *collecting {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &collecting{stdout: &syncBuffer{}, stderr: &syncBuffer{}, cancel: cancel, done: make(chan int, 1)}
	args := append(collectArgs(t, "127.0.0.1:0", out), extra...)
	go func() {
		c.done <- run(ctx, args, c.stdout, c.stderr)
	}()
	t.Cleanup(cancel)
	line := waitFor(t, c.stdout, "listening on ")
	_, url, _ := strings.Cut(line, "listening on ")
	c.url = strings.TrimSpace(url)
	return c
}

// post sends body to the collector with its credential and returns the
// status.
func (c *collecting) post(t *testing.T, body []byte) int {
	t.Helper()
	return c.postAs(t, body, "Bearer "+collectToken)
}

// postAs sends body with authorization as its Authorization header, none
// when it is empty.
func (c *collecting) postAs(t *testing.T, body []byte, authorization string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func (c *collecting) stop(t *testing.T) {
	t.Helper()
	c.cancel()
	select {
	case status := <-c.done:
		if status != exitOK {
			t.Errorf("collect ended with %d: %s", status, c.stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("collect did not stop within ten seconds of its context ending")
	}
}
