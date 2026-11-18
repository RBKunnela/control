//go:build twoaccounts && unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
)

// TestAnOperatorListsTheApprovalsThePlaneHolds: the approvals directory is
// the plane's, 2750 in the operator's group, holding one record the plane
// held under the signed authority; approvals list run as the operator's
// account shows it and that the plane holds the directory, and refuses the
// same directory once its group may write it.
func TestAnOperatorListsTheApprovalsThePlaneHolds(t *testing.T) {
	plane, operator := twoAccounts(t)
	dir, p := signedStore(t)
	hold(t, p, waitingID, clockNow().Add(time.Hour))
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	giveTree(t, dir, account{uid: plane.uid, gid: operator.gid})
	openToEveryAccount(t, filepath.Dir(dir))
	if err := os.Chmod(dir, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	plane.holding(t, dir)

	stdout, stderr, code := operator.as(t, "cli", []string{"approvals", "list", dir})
	if code != exitOK || !strings.Contains(stdout, "1 record in "+dir) || !strings.Contains(stdout, "a plane holds this directory") ||
		!strings.Contains(stdout, waitingID) {
		t.Errorf("approvals list as the operator answered %d: %q %q; want the held record", code, stdout, stderr)
	}
	if err := os.Chmod(dir, 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = operator.as(t, "cli", []string{"approvals", "list", dir})
	if code == exitOK || !strings.Contains(stderr, string(approvals.ErrPermissions)) {
		t.Errorf("approvals list over a group-writable directory answered %d: %q %q; want it refused", code, stdout, stderr)
	}
}
