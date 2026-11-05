package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/console"
)

// pageLine is the one line the page prints, spelled out here rather than
// built from the code that prints it.
var pageLine = regexp.MustCompile(`^page: http://127\.0\.0\.1:([0-9]{1,5})/#t=([A-Za-z0-9_-]{43})\n$`)

// lockedBuffer is a buffer two goroutines can share.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
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

// runningPage is one console command running in this process.
type runningPage struct {
	base, token    string
	session        string
	stdin          *io.PipeWriter
	done           chan int
	stdout, stderr *lockedBuffer
}

// startPage runs the command with args over pipes and reads its first line.
func startPage(ctx context.Context, t *testing.T, args ...string) *runningPage {
	t.Helper()
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	p := &runningPage{stdin: stdinW, done: make(chan int, 1), stdout: &lockedBuffer{}, stderr: &lockedBuffer{}}
	go func() {
		code := serveConsole(ctx, args, stdinR, stdoutW, p.stderr)
		_ = stdoutW.Close()
		p.done <- code
	}()
	lines := make(chan string, 1)
	br := bufio.NewReader(stdoutR)
	go func() {
		line, _ := br.ReadString('\n')
		lines <- line
		_, _ = io.Copy(p.stdout, br)
	}()
	var line string
	select {
	case line = <-lines:
	case <-time.After(5 * time.Second):
		t.Fatalf("the page printed no line; stderr %q", p.stderr.String())
	}
	m := pageLine.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("the first line %q is not the page's; stderr %q", line, p.stderr.String())
	}
	p.base, p.token = "http://127.0.0.1:"+m[1], m[2]
	t.Cleanup(func() {
		_ = stdinW.Close()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
		}
	})
	code, out := p.send(t, console.SessionPath, p.token, `{}`)
	var traded struct {
		Session string `json:"session"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(out), &traded) != nil || traded.Session == "" {
		t.Fatalf("trading the printed token answered %d %q", code, out)
	}
	p.session = traded.Session
	return p
}

// exited waits up to limit for the command's exit status.
func (p *runningPage) exited(t *testing.T, limit time.Duration) int {
	t.Helper()
	select {
	case code := <-p.done:
		return code
	case <-time.After(limit):
		t.Fatalf("the page is still serving %s later", limit)
		return -1
	}
}

// post sends one write as the page's script sends it, under the session the
// printed token was traded for.
func (p *runningPage) post(t *testing.T, path, body string) (int, string) {
	t.Helper()
	return p.send(t, path, p.session, body)
}

// send posts body to path carrying token.
func (p *runningPage) send(t *testing.T, path, token, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, p.base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(console.TokenHeader, token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", p.base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(out)
}

// answerBody is the body of one answer to approvalID, carrying the action digest
// the kernel computes for its request, as the script carries the one it showed.
func answerBody(t *testing.T, approvalID, reason string) string {
	t.Helper()
	raw, err := json.Marshal(struct {
		ID           string `json:"id"`
		Reason       string `json:"reason"`
		ActionDigest string `json:"action_digest"`
	}{approvalID, reason, string(digestOf(t, approvalID))})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestConsoleTradesThePrintedTokenOnce: the printed token is good for one
// trade, and after it neither a second trade nor an answer takes it.
func TestConsoleTradesThePrintedTokenOnce(t *testing.T) {
	dir, plane := newStore(t)
	hold(t, plane, "HELD1", clockNow().Add(15*time.Minute))
	p := startPage(context.Background(), t, "--approvals", dir, "--approver-id", "page-approver")
	if code, body := p.send(t, console.SessionPath, p.token, `{}`); code != http.StatusUnauthorized {
		t.Errorf("a second trade of the printed token answered %d %q, want 401", code, body)
	}
	if code, body := p.send(t, "/api/approve", p.token, answerBody(t, "HELD1", "")); code != http.StatusUnauthorized {
		t.Errorf("an answer under the printed token answered %d %q, want 401", code, body)
	}
	if code, listing, stderr := invoke(t, "approvals", "list", dir); code != exitOK || fieldOf(t, blockOf(t, listing, "HELD1"), "state") != "APPROVAL_STATE_PENDING" {
		t.Errorf("after the refusals approvals list answered %d %q %q", code, listing, stderr)
	}
}

// TestConsolePrintsOneLineAndStopsWhenStdinCloses: stdout is the one line
// and nothing else, neither the printed nor the session token is in any
// other output or in a file the page wrote, and the command exits 0 within
// two seconds of its stdin ending.
func TestConsolePrintsOneLineAndStopsWhenStdinCloses(t *testing.T) {
	dir, plane := newStore(t)
	hold(t, plane, "HELD1", clockNow().Add(15*time.Minute))
	file := initialized(t)
	p := startPage(context.Background(), t, "--approvals", dir, "--pause", file, "--approver-id", "page-approver", "--until-stdin-closes")
	if code, body := p.post(t, "/api/approve", answerBody(t, "HELD1", "looked fine")); code != http.StatusOK {
		t.Fatalf("approve answered %d %q", code, body)
	}
	if code, body := p.post(t, "/api/pause", `{"scope":{"kind":"global","provider":"","action":"","name":""},"reason":""}`); code != http.StatusOK {
		t.Fatalf("pause answered %d %q", code, body)
	}
	if err := p.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if code := p.exited(t, 2*time.Second); code != exitOK {
		t.Errorf("exit %d after stdin closed, want 0; stderr %q", code, p.stderr.String())
	}
	if rest := p.stdout.String(); rest != "" {
		t.Errorf("stdout carried more than the one line: %q", rest)
	}
	for _, token := range []string{p.token, p.session} {
		if strings.Contains(p.stderr.String(), token) {
			t.Error("stderr carries a token")
		}
		if strings.Contains(dirText(t, dir)+fileBytes(t, file), token) {
			t.Error("a file the page wrote carries a token")
		}
	}
}

// TestConsoleOutlivesStdinWithoutTheFlag: without --until-stdin-closes the
// page does not read its stdin, and only its context stops it.
func TestConsoleOutlivesStdinWithoutTheFlag(t *testing.T) {
	dir, _ := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := startPage(ctx, t, "--approvals", dir, "--approver-id", "page-approver")
	if err := p.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-p.done:
		t.Fatalf("the page stopped with %d when stdin closed without the flag", code)
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	if code := p.exited(t, 2*time.Second); code != exitOK {
		t.Errorf("exit %d after an interrupt, want 0; stderr %q", code, p.stderr.String())
	}
}

// mustPost sends one write and fails unless it was filed.
func (p *runningPage) mustPost(t *testing.T, path, body string) string {
	t.Helper()
	code, out := p.post(t, path, body)
	if code != http.StatusOK {
		t.Fatalf("%s answered %d %q", path, code, out)
	}
	return out
}

// TestConsoleAnswersAsTheCommandsDo: an approval answered through the page
// lists as one answered through approvals approve does, and a rejection as a
// rejection under the starter's approver id.
func TestConsoleAnswersAsTheCommandsDo(t *testing.T) {
	dir, plane := newStore(t)
	expires := clockNow().Add(15 * time.Minute)
	for _, id := range []string{"BYPAGE", "BYCLI", "REFUSED"} {
		hold(t, plane, id, expires)
	}
	p := startPage(context.Background(), t, "--approvals", dir, "--approver-id", "duty-officer")
	p.mustPost(t, "/api/approve", answerBody(t, "BYPAGE", ""))
	p.mustPost(t, "/api/reject", answerBody(t, "REFUSED", "wrong account"))
	mustApprove(t, dir, "BYCLI", "duty-officer")
	code, listing, stderr := invoke(t, "approvals", "list", dir)
	if code != exitOK {
		t.Fatalf("approvals list answered %d: %s", code, stderr)
	}
	page, cli, refused := blockOf(t, listing, "BYPAGE"), blockOf(t, listing, "BYCLI"), blockOf(t, listing, "REFUSED")
	for _, label := range []string{"state", "answered by", "expires", "bundle digest"} {
		if fieldOf(t, page, label) != fieldOf(t, cli, label) {
			t.Errorf("%s: the page wrote %q, the command %q", label, fieldOf(t, page, label), fieldOf(t, cli, label))
		}
	}
	if got := fieldOf(t, page, "state"); got != "APPROVAL_STATE_APPROVED" {
		t.Errorf("the page's answer lists as %q", got)
	}
	if got, by := fieldOf(t, refused, "state"), fieldOf(t, refused, "answered by"); got != "APPROVAL_STATE_REJECTED" || by != "duty-officer" {
		t.Errorf("the page's rejection lists as %q by %q", got, by)
	}
}

// TestConsolePausesAsTheCommandsDo: a pause added through the page is the
// line pause list prints under the id the page answered with, and lifting it
// leaves the file pause list reads as empty.
func TestConsolePausesAsTheCommandsDo(t *testing.T) {
	dir, _ := newStore(t)
	file := initialized(t)
	p := startPage(context.Background(), t, "--approvals", dir, "--pause", file, "--approver-id", "duty-officer")
	body := p.mustPost(t, "/api/pause", `{"scope":{"kind":"provider","provider":"payments","action":"","name":""},"reason":"card fraud"}`)
	id := regexp.MustCompile(`"id":"([A-Z2-7]+)"`).FindStringSubmatch(body)
	if id == nil {
		t.Fatalf("pause answered %q, with no id", body)
	}
	code, listed, stderr := invoke(t, "pause", "list", file)
	if want := regexp.MustCompile(`^` + id[1] + ` provider payments created [0-9TZ:-]+ reason "card fraud"\n$`); code != exitOK || !want.MatchString(listed) {
		t.Errorf("pause list answered %d %q %q", code, listed, stderr)
	}
	p.mustPost(t, "/api/unpause", `{"id":"`+id[1]+`"}`)
	if code, listed, _ := invoke(t, "pause", "list", file); code != exitOK || listed != "no entries\n" {
		t.Errorf("after the lift pause list answered %d %q", code, listed)
	}
}

// TestConsoleRefusesItsOwnArguments: each call lacks one thing the page
// needs, or carries an approver id the store refuses, and exits 2 before
// anything binds, with nothing on stdout.
func TestConsoleRefusesItsOwnArguments(t *testing.T) {
	dir, _ := newStore(t)
	for name, c := range map[string]struct {
		args []string
		says string
	}{
		"no directory":       {[]string{"--approver-id", "a"}, "--approvals names"},
		"no approver":        {[]string{"--approvals", dir}, "--approver-id names"},
		"a trailing space":   {[]string{"--approvals", dir, "--approver-id", "duty "}, "the approver id"},
		"an id of 129 bytes": {[]string{"--approvals", dir, "--approver-id", strings.Repeat("a", 129)}, "the approver id"},
		"a bare argument":    {[]string{"--approvals", dir, "--approver-id", "a", "extra"}, "takes flags only"},
		"an unknown flag":    {[]string{"--approvals", dir, "--approver-id", "a", "--listen", "0.0.0.0:80"}, "flag provided but not defined"},
	} {
		var stdout, stderr bytes.Buffer
		code := serveConsole(context.Background(), c.args, strings.NewReader(""), &stdout, &stderr)
		if code != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), c.says) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d saying %q", name, code, stdout.String(), stderr.String(), exitUsage, c.says)
		}
	}
}
