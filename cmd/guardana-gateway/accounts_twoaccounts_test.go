//go:build twoaccounts && unix

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
)

// The variables the "Two accounts" job sets: the uids of two accounts it
// made beside root, which runs these tests (ADR-0081).
const (
	otherUIDVar = "GUARDANA_TEST_OTHER_UID"
	thirdUIDVar = "GUARDANA_TEST_THIRD_UID"
)

// helperRole names what this binary does when a test starts it as another
// account; helperArg is what that role reads.
const (
	helperRole = "TWOACCOUNTS_ROLE"
	helperArg  = "TWOACCOUNTS_ARG"
)

// account is one account of the machine: its uid, its primary group and
// the supplementary groups a test hands it.
type account struct {
	uid, gid uint32
	groups   []uint32
}

// twoAccounts is the job's two accounts, other and third. Without the
// variables the test skips, which the job's checker refuses; with them, a
// process that is not root, or accounts that are root or the same, fail.
func twoAccounts(t *testing.T) (other, third account) {
	t.Helper()
	if os.Getenv(otherUIDVar) == "" || os.Getenv(thirdUIDVar) == "" {
		t.Skip(otherUIDVar + " and " + thirdUIDVar + " are not set; the Two accounts job runs this test as root beside two accounts")
	}
	if os.Geteuid() != 0 {
		t.Fatalf("this test runs as root, which hands each account its part; euid is %d", os.Geteuid())
	}
	other, third = accountOf(t, otherUIDVar), accountOf(t, thirdUIDVar)
	if other.uid == third.uid {
		t.Fatalf("%s and %s name one account, %d", otherUIDVar, thirdUIDVar, other.uid)
	}
	return other, third
}

func accountOf(t *testing.T, name string) account {
	t.Helper()
	uid, err := strconv.ParseUint(os.Getenv(name), 10, 32)
	if err != nil || uid == 0 {
		t.Fatalf("%s=%q names no account other than root: %v", name, os.Getenv(name), err)
	}
	u, err := user.LookupId(strconv.FormatUint(uid, 10))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		t.Fatalf("%s: the group %q: %v", name, u.Gid, err)
	}
	return account{uid: uint32(uid), gid: uint32(gid)}
}

// as runs this test binary as a under role, reading arg, and returns its
// standard output, its standard error and its exit status. The binary has
// to be one every account may execute.
func (a account) as(t *testing.T, role, arg string) (string, string, int) {
	t.Helper()
	cmd := a.command(t, role, arg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("running %s as uid %d: %v", role, a.uid, err)
		}
		code = exit.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func (a account) command(t *testing.T, role, arg string) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestHelperActsAsAnotherAccount$", "-test.count=1") //nolint:gosec // G204: this test binary and its own flags
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", helperRole + "=" + role, helperArg + "=" + arg}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: a.uid, Gid: a.gid, Groups: a.groups}}
	return cmd
}

// TestHelperActsAsAnotherAccount is this binary as another account, started
// by a two-account test; it never runs on its own.
func TestHelperActsAsAnotherAccount(t *testing.T) {
	role := os.Getenv(helperRole)
	if role == "" {
		t.Skip("it runs as another account in the child process of a two-account test alone")
	}
	arg := os.Getenv(helperArg)
	switch role {
	case "ask":
		os.Exit(askSocket(arg))
	case "signed-start":
		os.Exit(judgeSignedStart(arg))
	case "collector":
		os.Exit(serveCollector(arg))
	}
	fmt.Fprintf(os.Stderr, "no role %q\n", role)
	os.Exit(2)
}

// askSocket writes one GET /healthz on the socket at path and copies every
// byte that came back to standard output. It exits 3 when the connect
// itself is refused.
func askSocket(path string) int {
	conn, err := net.DialTimeout("unix", path, 5*time.Second) //nolint:gosec // G704: the socket the starting test names
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		return 3
	}
	defer conn.Close() //nolint:errcheck // a test's connection
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if _, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: plane\r\nConnection: close\r\n\r\n")); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
	}
	if _, err := io.Copy(os.Stdout, conn); err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
	}
	return 0
}

// judgeSignedStart loads the configuration at path as this account and
// prints what checkSignedStart answers: "ok", or its refusal.
func judgeSignedStart(path string) int {
	cfg, err := gatewayconfig.Load(path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		return 2
	}
	if err := checkSignedStart(cfg); err != nil {
		return tellParent(err.Error())
	}
	return tellParent("ok")
}

// tellParent writes line to standard output, which the starting test reads,
// and returns the helper's exit status: 2 when the line could not be written.
func tellParent(line string) int {
	if _, err := fmt.Fprintln(os.Stdout, line); err != nil {
		return 2
	}
	return 0
}

// serveCollector listens on the unix socket at path and prints "listening",
// then "connection" for each connection and "request <path> <Authorization>"
// for each request, answering every request 200, until it is killed.
func serveCollector(path string) int {
	ln, err := net.Listen("unix", path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		return 2
	}
	if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // G302: the exporter's peer check of the collector, not the socket's mode, is under test
		fmt.Fprintf(os.Stderr, "chmod: %v\n", err)
		return 2
	}
	var mu sync.Mutex
	say := func(line string) {
		mu.Lock()
		defer mu.Unlock()
		if tellParent(line) != 0 {
			os.Exit(2)
		}
	}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				say("connection")
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			say("request " + r.URL.Path + " " + r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		}),
	}
	say("listening")
	_ = srv.Serve(ln)
	return 0
}

// lockedBuffer is a buffer a child process writes while a test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startAs starts role as a in the background and waits until its output
// holds ready; the process is killed when the test ends.
func (a account) startAs(t *testing.T, role, arg, ready string) *lockedBuffer {
	t.Helper()
	cmd := a.command(t, role, arg)
	out := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s as uid %d: %v", role, a.uid, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	waitForLine(t, out, ready)
	return out
}

// waitForLine waits up to ten seconds for out to hold want.
func waitForLine(t *testing.T, out *lockedBuffer, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for !strings.Contains(out.String(), want) {
		select {
		case <-ctx.Done():
			t.Fatalf("no %q within 10s; the output is %q", want, out.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// openToEveryAccount makes every directory from dir up to the temporary
// directory's root searchable by every account and writable by none but its
// owner, as root's t.TempDir makes them 0700.
func openToEveryAccount(t *testing.T, dir string) {
	t.Helper()
	top := filepath.Clean(os.TempDir())
	for p := filepath.Clean(dir); p != top && strings.HasPrefix(p, top+string(filepath.Separator)); p = filepath.Dir(p) {
		if err := os.Chmod(p, 0o755); err != nil { //nolint:gosec // G302: a directory every account may search
			t.Fatal(err)
		}
	}
}

// giveTree hands every entry under dir, dir included, to a, files 0644 and
// directories 0755, so a owns it and nobody else may write it.
func giveTree(t *testing.T, dir string, a account) {
	t.Helper()
	if rel, err := filepath.Rel(os.TempDir(), dir); err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		t.Fatalf("%s is not a test's own directory under %s", dir, os.TempDir())
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o644)
		if d.IsDir() {
			mode = 0o755
		}
		if err := os.Lchown(path, int(a.uid), int(a.gid)); err != nil { //nolint:gosec // G122: a test's own directory, which no other account may write
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		return os.Chmod(path, mode) //nolint:gosec // G122: a test's own directory, which no other account may write
	})
	if err != nil {
		t.Fatalf("handing %s to uid %d: %v", dir, a.uid, err)
	}
}
