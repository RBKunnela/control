//go:build twoaccounts && unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/findinglog"
)

// TestReactUnderASignedRouteRunsAsTheOperatorBesideThePlane: with the
// approvals directory the plane's account owns and holds, 2750 in the
// operator's group, react run as the operator's account passes its guard and
// reads every input, and the same react run as the plane's account is
// refused before it reads a finding.
func TestReactUnderASignedRouteRunsAsTheOperatorBesideThePlane(t *testing.T) {
	plane, operator := twoAccounts(t)
	tr := newSignedTree(t)
	if code, _, stderr := tr.run(t, "stops init", "--key", tr.keys["alice"], tr.stops); code != exitOK {
		t.Fatalf("stops init: %d, %q", code, stderr)
	}
	findings := ownerDir(t, filepath.Join(tr.dir, "findings"))
	if err := os.WriteFile(filepath.Join(findings, findinglog.FileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runsAt := runsDir(t)
	openRun(t, runsAt, who, "1h")
	giveTree(t, filepath.Dir(tr.dir), operator)
	openToEveryAccount(t, tr.dir)
	for _, f := range []string{tr.route, tr.judge[1], tr.judge[3]} {
		if err := os.Chmod(f, 0o644); err != nil { //nolint:gosec // G302: files the operator's react reads
			t.Fatal(err)
		}
	}
	approvalsDir := filepath.Join(tr.dir, "approvals")
	if err := os.Mkdir(approvalsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(approvalsDir, int(plane.uid), int(operator.gid)); err != nil {
		t.Fatal(err)
	}
	// setgid, so what the plane writes there is in the operator's group too.
	if err := os.Chmod(approvalsDir, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	plane.holding(t, approvalsDir)

	args := []string{"react", "--findings", findings, "--runs", runsAt, "--route", tr.route,
		"--roster", tr.judge[1], "--root-key", tr.judge[3], "--approvals", approvalsDir, "--stops", tr.stops}
	stdout, stderr, code := operator.as(t, "cli", args)
	if code != exitOK || !strings.Contains(stdout, "stops 0, covered 0") {
		t.Errorf("react as the operator answered %d: %q %q; want a pass that stopped nothing", code, stdout, stderr)
	}
	stdout, stderr, code = plane.as(t, "cli", args)
	if code == exitOK || !strings.Contains(stderr, errPlaneAccount.Error()) {
		t.Errorf("react as the plane's account answered %d: %q %q; want it refused as the plane's account", code, stdout, stderr)
	}
}
