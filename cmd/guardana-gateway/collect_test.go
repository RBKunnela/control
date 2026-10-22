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
		out := filepath.Join(t.TempDir(), "trail.jsonl")
		var stdout, stderr bytes.Buffer
		status := run(context.Background(), []string{"collect", "--listen", addr, "--out", out}, &stdout, &stderr)
		if status != exitFail || !strings.Contains(stderr.String(), "loopback") {
			t.Errorf("--listen %s answered %d with %q, want %d naming the loopback", addr, status, stderr.String(), exitFail)
		}
		if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("--listen %s left a trail file behind: %v", addr, err)
		}
	}
	c := startCollect(t, filepath.Join(t.TempDir(), "trail.jsonl"))
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

func TestCollectNeedsBothFlagsAndNothingElse(t *testing.T) {
	out := filepath.Join(t.TempDir(), "trail.jsonl")
	for _, args := range [][]string{
		{"collect", "--out", out},
		{"collect", "--listen", "127.0.0.1:0"},
		{"collect", "--listen", "127.0.0.1:0", "--out", out, "extra"},
		{"collect", "--config", out},
	} {
		var stdout, stderr bytes.Buffer
		if status := run(context.Background(), args, &stdout, &stderr); status != exitUsage {
			t.Errorf("%q answered %d, want %d", args, status, exitUsage)
		}
	}
}

// TestCollectRefusesAFileItCannotHold: a trail file in a directory the group
// may write is refused, and so is one another collect holds.
func TestCollectRefusesAFileItCannotHold(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil { //nolint:gosec // G302: the group-writable directory collect must refuse
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"collect", "--listen", "127.0.0.1:0", "--out", filepath.Join(dir, "t.jsonl")}, &stdout, &stderr)
	if status != exitFail || !strings.Contains(stderr.String(), "writable") {
		t.Errorf("a group-writable directory answered %d with %q", status, stderr.String())
	}

	out := filepath.Join(t.TempDir(), "trail.jsonl")
	c := startCollect(t, out)
	stdout.Reset()
	stderr.Reset()
	status = run(context.Background(), []string{"collect", "--listen", "127.0.0.1:0", "--out", out}, &stdout, &stderr)
	if status != exitFail || !strings.Contains(stderr.String(), "held by another writer") {
		t.Errorf("a second collect on one file answered %d with %q", status, stderr.String())
	}
	c.stop(t)
}

// TestCollectWritesWhatArrivesUntilTheSignal: collect prints where it listens
// and what it writes, answers the exporter's golden request with 200 once the
// file holds its events, and stops when its context ends.
func TestCollectWritesWhatArrivesUntilTheSignal(t *testing.T) {
	out := filepath.Join(t.TempDir(), "trail.jsonl")
	c := startCollect(t, out)
	if !strings.Contains(c.stdout.String(), out) || !strings.Contains(c.stdout.String(), "allow_plaintext") {
		t.Errorf("collect printed %q, which does not name the file and the plaintext setting", c.stdout.String())
	}
	resp, err := http.Post(c.url, "application/json", bytes.NewReader(otlpFixture(t, "export_logs_request.json")))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the golden request answered %d", resp.StatusCode)
	}
	got, err := os.ReadFile(out) //nolint:gosec // G304: the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	if want := otlpFixture(t, "events.jsonl"); !bytes.Equal(got, want) {
		t.Errorf("the trail file holds\n%s\nwant\n%s", got, want)
	}
	c.stop(t)
	if _, err := http.Post(c.url, "application/json", strings.NewReader("{}")); err == nil {
		t.Error("the collector still answers after its context ended")
	}
}

// TestCollectLeavesAFileThatIsNotATrail: --out naming a file of notes, or a
// settings file of one line, is refused as damaged, and the file is left byte
// for byte as it was. A collect that took the file would serve until its
// deadline and end 0, which fails here rather than hanging the suite.
func TestCollectLeavesAFileThatIsNotATrail(t *testing.T) {
	for _, notes := range []string{
		"a note\nanother note", "a note\n{half a record", `{"k":1}`,
		`{"kind":"production"} // settings, keep`, `{"eventId":1}x`,
	} {
		out := filepath.Join(t.TempDir(), "notes.txt")
		if err := os.WriteFile(out, []byte(notes), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		stdout, stderr := &syncBuffer{}, &syncBuffer{}
		done := make(chan int, 1)
		go func() { done <- run(ctx, []string{"collect", "--listen", "127.0.0.1:0", "--out", out}, stdout, stderr) }()
		var status int
		select {
		case status = <-done:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatalf("%q: collect did not end within five seconds", notes)
		}
		cancel()
		if status != exitFail || !strings.Contains(stderr.String(), "damaged") {
			t.Errorf("%q: collect answered %d with %q, want %d naming the damage", notes, status, stderr.String(), exitFail)
		}
		if got, err := os.ReadFile(out); err != nil || string(got) != notes { //nolint:gosec // G304: the test's own temp file
			t.Errorf("%q: the refused file holds %q (%v)", notes, got, err)
		}
	}
}

// TestCollectAnswersARequestInFlightAtTheSignal: a request whose body is
// still arriving when the context ends is read to its end, answered 200 once
// the file holds its events, and only then does collect stop.
func TestCollectAnswersARequestInFlightAtTheSignal(t *testing.T) {
	out := filepath.Join(t.TempDir(), "trail.jsonl")
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
	head := "POST " + logsPath + " HTTP/1.1\r\nHost: " + addr + "\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n"
	if _, err := conn.Write(append([]byte(head), body[:len(body)/2]...)); err != nil {
		t.Fatal(err)
	}
	// The server has read the head and waits on the body when the signal
	// comes; the listener closing says the shutdown has started.
	time.Sleep(200 * time.Millisecond)
	c.cancel()
	waitClosed(t, addr)
	if _, err := conn.Write(body[len(body)/2:]); err != nil {
		t.Fatalf("the rest of the body could not be sent: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer to the request in flight: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the request in flight answered %d, want 200", resp.StatusCode)
	}
	c.stop(t)
	got, err := os.ReadFile(out) //nolint:gosec // G304: the test's own temp file
	if want := otlpFixture(t, "events.jsonl"); err != nil || !bytes.Equal(got, want) {
		t.Errorf("the trail file holds\n%s\n(%v), want\n%s", got, err, want)
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

// TestCollectPrintsOutOnOneLine: an --out holding a bidirectional control or
// a line or paragraph separator passes the argument check, since none is a
// control character, and the line naming the file quotes it.
func TestCollectPrintsOutOnOneLine(t *testing.T) {
	for _, r := range []rune{0x202e, 0x2028, 0x2029} {
		out := filepath.Join(t.TempDir(), "a"+string(r)+"txt.lmth")
		c := startCollect(t, out)
		c.stop(t)
		stdout := c.stdout.String()
		if strings.Contains(stdout, out) || !strings.Contains(stdout, "collect: appending to "+strconv.Quote(out)+"\n") {
			t.Errorf("U+%04X: collect printed %q, want --out quoted", r, stdout)
		}
	}
}

func startCollect(t *testing.T, out string) *collecting {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &collecting{stdout: &syncBuffer{}, stderr: &syncBuffer{}, cancel: cancel, done: make(chan int, 1)}
	go func() {
		c.done <- run(ctx, []string{"collect", "--listen", "127.0.0.1:0", "--out", out}, c.stdout, c.stderr)
	}()
	t.Cleanup(cancel)
	line := waitFor(t, c.stdout, "listening on ")
	_, url, _ := strings.Cut(line, "listening on ")
	c.url = strings.TrimSpace(url)
	return c
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
