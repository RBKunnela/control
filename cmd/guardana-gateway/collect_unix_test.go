//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startUnixCollect runs collect of the trail out on a unix socket at socket,
// bound to the fixture's tenant and project unless boundTo names others.
func startUnixCollect(t *testing.T, socket, out string, boundTo ...string) *collecting {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &collecting{stdout: &syncBuffer{}, stderr: &syncBuffer{}, cancel: cancel, done: make(chan int, 1)}
	args := collectArgs(t, "unix://"+socket, out)
	if len(boundTo) == 2 {
		args[6], args[8] = boundTo[0], boundTo[1]
	}
	go func() {
		c.done <- run(ctx, args, c.stdout, c.stderr)
	}()
	t.Cleanup(cancel)
	line := waitFor(t, c.stdout, "listening on ")
	_, url, _ := strings.Cut(line, "listening on ")
	c.url = strings.TrimSpace(url)
	return c
}

// TestCollectListensOnAUnixSocket: collect on unix:///path says so and names
// the account a plane checks for, keeps what arrives over the socket with the
// credential, refuses what arrives without it, and removes the socket when
// it stops.
func TestCollectListensOnAUnixSocket(t *testing.T) {
	socket := shortSocketPath(t)
	out := filepath.Join(t.TempDir(), "trail")
	c := startUnixCollect(t, socket, out)
	if c.url != "unix://"+socket {
		t.Errorf("collect listens on %q, want unix://%s", c.url, socket)
	}
	if want := "export.collector_uid: " + strconv.Itoa(os.Geteuid()); !strings.Contains(c.stdout.String(), want) ||
		strings.Contains(c.stdout.String(), "allow_plaintext") {
		t.Errorf("collect printed %q, which does not say %q or names the plaintext setting", c.stdout.String(), want)
	}
	if info, err := os.Lstat(socket); err != nil || info.Mode().Type() != fs.ModeSocket {
		t.Fatalf("the socket is %v, %v", info, err)
	}
	post := func(authorization string) int { return postOverSocket(t, socket, authorization) }
	if status := post(""); status != http.StatusUnauthorized {
		t.Errorf("a request without the credential answered %d", status)
	}
	if status := post("Bearer " + collectToken); status != http.StatusOK {
		t.Fatalf("the golden request answered %d", status)
	}
	if got, want := liveSegment(t, out), otlpFixture(t, "events.jsonl"); !bytes.Equal(got, want) {
		t.Errorf("the trail holds\n%s\nwant\n%s", got, want)
	}
	c.stop(t)
	if _, err := os.Lstat(socket); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the socket outlived collect: %v", err)
	}
}

// TestCollectBindsNoSocketOverAFile: a file at the path, and a path that is
// not absolute and clean though it could be bound, are refused before the
// trail is opened, and the file is left as it was.
func TestCollectBindsNoSocketOverAFile(t *testing.T) {
	taken := shortSocketPath(t)
	if err := os.WriteFile(taken, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	here := filepath.Dir(taken)
	if err := os.Mkdir(filepath.Join(here, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(here)
	for _, listen := range []string{"unix://" + taken, "unix://c.sock", "unix://" + here + "/x/../c.sock", "unix://"} {
		out := filepath.Join(t.TempDir(), "trail")
		var stdout, stderr bytes.Buffer
		// A collect that took the path serves until the context ends, and
		// then exits 0, which is not the refusal wanted.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		status := run(ctx, collectArgs(t, listen, out), &stdout, &stderr)
		cancel()
		if status != exitFail {
			t.Errorf("--listen %s answered %d with %q", listen, status, stderr.String())
		}
		if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("--listen %s left a trail directory behind: %v", listen, err)
		}
	}
	if raw, err := os.ReadFile(taken); err != nil || string(raw) != "keep" { //nolint:gosec // G304: the test's own file
		t.Errorf("the file is now %q, %v", raw, err)
	}
}

// postOverSocket sends the golden request to the collector on socket with
// authorization as its Authorization header, none when it is empty, and
// returns the status.
func postOverSocket(t *testing.T, socket, authorization string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://collector"+logsPath,
		bytes.NewReader(otlpFixture(t, "export_logs_request.json")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := socketClient(socket).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
