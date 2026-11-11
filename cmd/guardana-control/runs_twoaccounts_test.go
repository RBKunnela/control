//go:build twoaccounts && unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/guardana/control/internal/runs"
)

// TestAnOperatorsSignedRunIsTakenByAPlaneInItsGroup: an operator's account
// opens a signed run over a runs directory it owns; records/ is the
// operator's, 0750, and the record 0640. A plane of another account in the
// operator's group, owning state/, resolves the token; the same plane
// outside that group cannot read the record, and a records/ handed to the
// plane's own account is refused.
func TestAnOperatorsSignedRunIsTakenByAPlaneInItsGroup(t *testing.T) {
	plane, operator := twoAccounts(t)
	s := newSignedRuns(t)
	handToOperator(t, s, operator)
	token := openAsOperator(t, s, operator)
	records := filepath.Join(s.dir, runs.RecordsDir)

	state := filepath.Join(s.dir, runs.StateDir)
	if err := os.Lchown(state, int(plane.uid), int(plane.gid)); err != nil {
		t.Fatal(err)
	}
	arg := resolveArg{Dir: s.dir, Roster: s.roster, Root: s.root, Token: token}
	inGroup := plane
	inGroup.groups = []uint32{operator.gid}
	if out := resolveAs(t, inGroup, arg); out != "ok" {
		t.Errorf("a plane in the operator's group: %q; want the token resolved", out)
	}
	if out := resolveAs(t, plane, arg); out == "ok" || !strings.Contains(out, "permission denied") {
		t.Errorf("a plane outside the operator's group: %q; want the record unreadable", out)
	}
	if err := os.Lchown(records, int(plane.uid), int(operator.gid)); err != nil {
		t.Fatal(err)
	}
	if out := resolveAs(t, inGroup, arg); out == "ok" {
		t.Errorf("a records/ the plane's account owns: %q; want it refused", out)
	}
}

// handToOperator gives the signed layout's tree to the operator, the runs
// directory 0750 and the trust files 0644 in directories every account may
// search.
func handToOperator(t *testing.T, s signedRuns, operator account) {
	t.Helper()
	giveTree(t, filepath.Dir(filepath.Dir(s.dir)), operator)
	openToEveryAccount(t, filepath.Dir(s.dir))
	if err := os.Chmod(s.dir, 0o750); err != nil { //nolint:gosec // G302: the operator's group reads the runs directory
		t.Fatal(err)
	}
	for _, f := range []string{s.roster, s.root} {
		openToEveryAccount(t, filepath.Dir(f))
		if err := os.Chmod(f, 0o644); err != nil { //nolint:gosec // G302: public trust files every account reads
			t.Fatal(err)
		}
	}
}

// openAsOperator runs "runs open --key" as the operator, checks that
// records/ and the record are the operator's at 0750 and 0640, and returns
// the run's token.
func openAsOperator(t *testing.T, s signedRuns, operator account) string {
	t.Helper()
	stdout, stderr, code := operator.as(t, "cli", openArgs(s.dir, tenantP1, "1h", s.flags()...))
	if code != exitOK {
		t.Fatalf("runs open --key as the operator answered %d: %q %q", code, stdout, stderr)
	}
	records := filepath.Join(s.dir, runs.RecordsDir)
	expectOwned(t, records, operator.uid, 0o750)
	record, err := filepath.Glob(filepath.Join(records, "*.run.json"))
	if err != nil || len(record) != 1 {
		t.Fatalf("records/ holds %v, %v; want the one record", record, err)
	}
	expectOwned(t, record[0], operator.uid, 0o640)
	return fieldAfter(t, stdout, "token: ")
}

func resolveAs(t *testing.T, a account, arg resolveArg) string {
	t.Helper()
	out, stderr, code := a.as(t, "resolve", arg)
	if code != 0 {
		t.Fatalf("the plane as uid %d exited %d: %q %q", a.uid, code, out, stderr)
	}
	return strings.TrimSpace(out)
}

// expectOwned fails unless path is uid's with mode perm.
func expectOwned(t *testing.T, path string, uid uint32, perm os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || info.Mode().Perm() != perm {
		t.Errorf("%s is %v; want uid %d's with mode %04o", path, info.Mode(), uid, perm)
	}
}
