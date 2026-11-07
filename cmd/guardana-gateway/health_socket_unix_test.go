//go:build unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// shortSocketPath is a socket path short enough for the platform's bound
// on a socket's name, which a test's own directory can pass on darwin.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// stoppedRuns is a serving plane whose stop list stops a run of its own
// project and one of another, and whose pause file pauses each of them,
// with its health socket at socket answering also the account allow names.
// It returns the plane and both run ids.
func stoppedRuns(t *testing.T, socket, allow string) (*plane, string, string) {
	t.Helper()
	tr := newTree(t)
	route := tr.withReaction(t)
	own := openRunOf(t, filepath.Join(tr.dir, "runs"), "orders")
	other := openRunOf(t, filepath.Join(tr.dir, "runs"), "billing")
	for i, id := range []string{own, other} {
		finding := fmt.Sprintf("finding-%d", i+1)
		stopAt := func(now time.Time) (reaction.Stop, error) { return stopOf(id, finding, now), nil }
		if _, _, covered, err := stopwrite.AppendFinding(context.Background(), filepath.Join(tr.dir, "stops"), route, time.Now, stopAt); err != nil || covered {
			t.Fatalf("appending the stop of %s: covered %v, %v", id, covered, err)
		}
	}
	tr.withPauseFile(t, pauseDocument(
		pauseEntry("pause-own", `{"kind":"run","id":"`+own+`"}`),
		pauseEntry("pause-other", `{"kind":"run","id":"`+other+`"}`)), time.Second)
	if socket != "" {
		setEnv(t, "health.socket", socket)
	}
	if allow != "" {
		setEnv(t, "health.socket_uid", allow)
	}
	p, err := buildServing(t, tr)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	p.stops.poller.Poll()
	p.poller.Poll()
	return p, own, other
}

// TestHealthzNamesNoRun: a plane whose stops and pause entries name two
// runs answers /healthz with their counts and neither id, under schema 2.
func TestHealthzNamesNoRun(t *testing.T) {
	p, own, other := stoppedRuns(t, "", "")
	rec := httptest.NewRecorder()
	p.healthMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	raw := rec.Body.String()
	for _, id := range []string{own, other} {
		if strings.Contains(raw, id) {
			t.Errorf("/healthz names run %s:\n%s", id, raw)
		}
	}
	var body struct {
		Schema string                     `json:"schema"`
		Stops  map[string]json.RawMessage `json:"stops"`
		Pause  map[string]json.RawMessage `json:"pause"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Schema != "2" {
		t.Errorf("schema = %q, want 2", body.Schema)
	}
	for member, want := range map[string]string{"active": "2", "unheld": "1", "unread": "0"} {
		if got := string(body.Stops[member]); got != want {
			t.Errorf("stops.%s = %s, want %s", member, got, want)
		}
	}
	for _, member := range []string{"entries", "unheld_runs", "unread_runs"} {
		if _, ok := body.Stops[member]; ok {
			t.Errorf("/healthz carries stops.%s", member)
		}
	}
	if got := string(body.Pause["entries"]); got != "2" {
		t.Errorf("pause.entries = %s, want 2", got)
	}
}

// socketClient asks over the Unix socket at path.
func socketClient(path string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
}

// serveSocket binds the plane's health socket and serves it until the test
// ends, its peers read through uid.
func serveSocket(t *testing.T, p *plane, uid func(net.Conn) (uint32, error)) {
	t.Helper()
	bound, err := p.bindHealthSocket(io.Discard, nil)
	if err != nil {
		t.Fatalf("binding the health socket: %v", err)
	}
	if len(bound) != 1 {
		t.Fatalf("bound %d listeners, want the socket", len(bound))
	}
	ln, ok := bound[0].listener.(*peerListener)
	if !ok {
		t.Fatalf("the socket's listener is %T, which checks no peer", bound[0].listener)
	}
	ln.uid = uid
	go func() { _ = bound[0].server.Serve(ln) }()
	t.Cleanup(func() { _ = bound[0].server.Close() })
}

// TestTheHealthSocketAnswersThisAccountWhole: over a real socket the peer is
// this account, which reads the whole answer: both runs and which is
// unheld. The socket is 0600, and it is gone once the server closes.
func TestTheHealthSocketAnswersThisAccountWhole(t *testing.T) {
	path := shortSocketPath(t)
	p, own, other := stoppedRuns(t, path, "")
	bound, err := p.bindHealthSocket(io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Type() != os.ModeSocket || info.Mode().Perm() != 0o600 {
		t.Fatalf("the socket is %v, %v; want a socket of mode 0600", info, err)
	}
	served := make(chan error, 1)
	go func() { served <- bound[0].server.Serve(bound[0].listener) }()
	schema, stops := wholeOverSocket(t, path)
	runs := stopRuns(stops)
	want := []string{own, other}
	slices.Sort(want)
	if schema != "2" || !slices.Equal(runs, want) || !slices.Equal(stops.UnheldRuns, []string{other}) || stops.Unheld != 1 {
		t.Errorf("the socket answered schema %q, runs %v, unheld %v (%d); want 2, %v, [%s]", schema, runs, stops.UnheldRuns, stops.Unheld, want, other)
	}
	if err := bound[0].server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Serve = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket outlived its server: %v", err)
	}
}

// wholeOverSocket reads the whole answer on the socket at path and returns
// its schema and its stops.
func wholeOverSocket(t *testing.T, path string) (string, stopsAnswer) {
	t.Helper()
	resp, err := socketClient(path).Get("http://plane/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Schema string      `json:"schema"`
		Stops  stopsAnswer `json:"stops"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Schema, body.Stops
}

// stopRuns is the runs of s's entries, sorted.
func stopRuns(s stopsAnswer) []string {
	var runs []string
	for _, e := range s.Entries {
		runs = append(runs, e.RunID)
	}
	slices.Sort(runs)
	return runs
}

// askRaw writes one request on the socket and returns every byte that came
// back before the connection ended.
func askRaw(t *testing.T, path string) []byte {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // a test's connection
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: plane\r\nConnection: close\r\n\r\n"))
	got, _ := io.ReadAll(conn)
	return got
}

// TestTheHealthSocketClosesAnotherAccountUnanswered: a peer of an account
// the socket does not answer, or one whose account cannot be named, gets
// not a byte; the configured other account is answered. With
// health.socket_uid the socket is 0666, so that account may connect where
// connecting takes write permission, and the peer check alone admits;
// without it the socket stays 0600.
func TestTheHealthSocketClosesAnotherAccountUnanswered(t *testing.T) {
	for name, tc := range map[string]struct {
		uid      func(net.Conn) (uint32, error)
		allow    string
		mode     os.FileMode
		answered bool
	}{
		"another account":                  {func(net.Conn) (uint32, error) { return 4242, nil }, "", 0o600, false},
		"another account than the allowed": {func(net.Conn) (uint32, error) { return 4242, nil }, "4243", 0o666, false},
		"no account named":                 {func(net.Conn) (uint32, error) { return 0, errors.New("fixture: no answer") }, "", 0o600, false},
		"no account named, beside uid 0":   {func(net.Conn) (uint32, error) { return 0, errors.New("fixture: no answer") }, "0", 0o666, false},
		"the allowed account":              {func(net.Conn) (uint32, error) { return 4242, nil }, "4242", 0o666, true},
	} {
		t.Run(name, func(t *testing.T) {
			path := shortSocketPath(t)
			p, _, _ := stoppedRuns(t, path, tc.allow)
			serveSocket(t, p, tc.uid)
			if info, err := os.Lstat(path); err != nil || info.Mode().Type() != os.ModeSocket || info.Mode().Perm() != tc.mode {
				t.Fatalf("the socket is %v, %v; want a socket of mode %04o", info, err, tc.mode)
			}
			got := askRaw(t, path)
			if answered := len(got) > 0; answered != tc.answered {
				t.Errorf("answered %v (%q), want %v", answered, got, tc.answered)
			}
			if tc.answered && !strings.HasPrefix(string(got), "HTTP/1.1 200 ") {
				t.Errorf("the allowed account got %q", got)
			}
		})
	}
}

// TestTheHealthSocketBindsOverNoFile: a file at the path is refused and left
// as it was.
func TestTheHealthSocketBindsOverNoFile(t *testing.T) {
	path := shortSocketPath(t)
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenHealthSocket(path, false); err == nil || !strings.Contains(err.Error(), "is not a socket of this account") {
		t.Errorf("over a file: %v", err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "keep" { //nolint:gosec // G304: the test's own file
		t.Errorf("the file is now %q, %v", raw, err)
	}
}

// TestTheHealthSocketReplacesOnlyItsOwnStaleSocket: a live socket at the
// path is refused; a socket of this account that refuses connections is
// replaced.
func TestTheHealthSocketReplacesOnlyItsOwnStaleSocket(t *testing.T) {
	path := shortSocketPath(t)
	live, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := listenHealthSocket(path, false); err == nil || !strings.Contains(err.Error(), "something answers") {
		t.Errorf("over a live socket: %v", err)
	}
	live.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the stale socket is not there: %v", err)
	}
	ln, err := listenHealthSocket(path, false)
	if err != nil {
		t.Fatalf("over a stale socket of this account: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestTheHealthSocketLeavesAFileThatReplacedIt: closing removes the path
// only while it is still the socket the plane bound.
func TestTheHealthSocketLeavesAFileThatReplacedIt(t *testing.T) {
	path := shortSocketPath(t)
	ln, err := listenHealthSocket(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("someone else's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "someone else's" { //nolint:gosec // G304: the test's own file
		t.Errorf("closing removed a file the plane did not bind: %q, %v", raw, err)
	}
}
