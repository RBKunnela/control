//go:build twoaccounts && unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/runs/signedruns"
	"github.com/guardana/control/internal/trust"
)

// The variables the "Two accounts" job sets: the uids of two accounts it
// made beside root, which runs these tests (ADR-0081).
const (
	otherUIDVar = "GUARDANA_TEST_OTHER_UID"
	thirdUIDVar = "GUARDANA_TEST_THIRD_UID"
)

// helperRole names what this binary does when a test starts it as another
// account; helperArg is the JSON that role reads.
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
	if other.uid == third.uid || other.gid == third.gid {
		t.Fatalf("%s and %s share an account or a group: %+v, %+v", otherUIDVar, thirdUIDVar, other, third)
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

// as runs this test binary as a under role, handing it arg as JSON, and
// returns its standard output, its standard error and its exit status.
func (a account) as(t *testing.T, role string, arg any) (string, string, int) {
	t.Helper()
	raw, err := json.Marshal(arg)
	if err != nil {
		t.Fatal(err)
	}
	cmd := a.command(t, role, raw)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("running %s as uid %d: %v", role, a.uid, err)
		}
		code = exit.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func (a account) command(t *testing.T, role string, raw []byte) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestHelperActsAsAnotherAccount$", "-test.count=1") //nolint:gosec // G204: this test binary and its own flags
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", helperRole + "=" + role, helperArg + "=" + string(raw)}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: a.uid, Gid: a.gid, Groups: a.groups}}
	return cmd
}

// holding starts a plane's hold of the approvals directory dir as a and
// waits until it holds the lock; the hold ends with the test.
func (a account) holding(t *testing.T, dir string) {
	t.Helper()
	raw, err := json.Marshal(dir)
	if err != nil {
		t.Fatal(err)
	}
	cmd := a.command(t, "hold-approvals", raw)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	line := make([]byte, len("held\n"))
	if _, err := io.ReadFull(stdout, line); err != nil || string(line) != "held\n" {
		_ = cmd.Wait()
		t.Fatalf("the plane as uid %d did not hold %s: %q, %v, %q", a.uid, dir, line, err, stderr.String())
	}
}

// resolveArg is what the resolve role reads: a signed runs directory, the
// roster and root key a plane of tenant and project judges with, and a
// token.
type resolveArg struct {
	Dir, Roster, Root, Token string
}

// TestHelperActsAsAnotherAccount is this binary as another account, started
// by a two-account test; it never runs on its own.
func TestHelperActsAsAnotherAccount(t *testing.T) {
	role := os.Getenv(helperRole)
	if role == "" {
		t.Skip("it runs as another account in the child process of a two-account test alone")
	}
	raw := []byte(os.Getenv(helperArg))
	switch role {
	case "cli":
		var args []string
		if err := json.Unmarshal(raw, &args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(run(args, os.Stdout, os.Stderr))
	case "resolve":
		var a resolveArg
		if err := json.Unmarshal(raw, &a); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(resolveAsPlane(a))
	case "hold-approvals":
		var dir string
		if err := json.Unmarshal(raw, &dir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(holdApprovals(dir))
	}
	fmt.Fprintf(os.Stderr, "no role %q\n", role)
	os.Exit(2)
}

// resolveAsPlane opens the signed layout as a plane of t1/p1 on its own
// account, judging with the roster, and prints "ok" or why the token is
// refused.
func resolveAsPlane(a resolveArg) int {
	doc, err := verifiedRoster(a.Roster, a.Root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "roster: %v\n", err)
		return 2
	}
	p, err := runs.OpenSignedPlane(a.Dir, runs.SignedOptions{Judge: signedruns.Roster{Document: doc, Tenant: "t1", Project: "p1"}})
	if err != nil {
		return tellParent("open: " + err.Error())
	}
	defer func() { _ = p.Close() }()
	if _, err := p.Resolve(context.Background(), a.Token, tenantP1, time.Now()); err != nil {
		return tellParent("resolve: " + err.Error())
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

// holdApprovals opens dir as a signed plane's approvals directory, which
// holds its lock, prints "held", and keeps it until standard input closes.
func holdApprovals(dir string) int {
	p, err := approvals.OpenPlane(dir, approvals.WithAuthority(approvals.HeldUnderSigned))
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		return 2
	}
	if tellParent("held") != 0 {
		return 2
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	if err := p.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close: %v\n", err)
		return 2
	}
	return 0
}

func verifiedRoster(rosterPath, rootPath string) (trust.Document, error) {
	raw, err := os.ReadFile(rosterPath) //nolint:gosec // G304: the roster the parent test wrote
	if err != nil {
		return trust.Document{}, err
	}
	env, err := trust.ParseFile(raw)
	if err != nil {
		return trust.Document{}, err
	}
	line, err := os.ReadFile(rootPath) //nolint:gosec // G304: the root key the parent test wrote
	if err != nil {
		return trust.Document{}, err
	}
	root, err := policykey.ParsePublic(strings.TrimSpace(string(line)))
	if err != nil {
		return trust.Document{}, err
	}
	return trust.VerifyDocument(env, root)
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

// giveTree hands every entry under dir, dir included, to a, keeping each
// mode.
func giveTree(t *testing.T, dir string, a account) {
	t.Helper()
	if rel, err := filepath.Rel(os.TempDir(), dir); err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		t.Fatalf("%s is not a test's own directory under %s", dir, os.TempDir())
	}
	err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, int(a.uid), int(a.gid)) //nolint:gosec // G122: a test's own directory, which no other account may write
	})
	if err != nil {
		t.Fatalf("handing %s to uid %d: %v", dir, a.uid, err)
	}
}
