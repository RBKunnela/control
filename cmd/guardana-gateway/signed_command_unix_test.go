//go:build unix

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policykey"
)

// approvalsCommand runs the built approver's binary with args and returns
// its exit status and its two streams.
func approvalsCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	_, controlBin := builtBinaries(t)
	cmd := exec.Command(controlBin, append([]string{"approvals"}, args...)...) //nolint:gosec // G204: the binary this test built
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exited *exec.ExitError
	if err != nil && !errors.As(err, &exited) {
		t.Fatalf("running the approvals command: %v", err)
	}
	return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
}

// TestTheApproversCommandAnswersASignedPlane: on a signed plane holding a
// call, a claim through the approvals command is refused naming the signing
// form and the retry stays held; alice's answer signed by the command, from
// the plane's own record of the hold, runs the retry.
func TestTheApproversCommandAnswersASignedPlane(t *testing.T) {
	tr, p := signedHoldingPlane(t)
	held := admitTransfer(t, p, "req-hold-1")
	if held.Action != core.AwaitApproval {
		t.Fatalf("the first call is %v, want a hold", held.Action)
	}
	dir := filepath.Join(tr.dir, recordsDir)
	code, _, stderr := approvalsCommand(t, "approve", "--approver-id", "alice", dir, held.Pending.ApprovalID)
	if code != 1 || !strings.Contains(stderr, "--key") {
		t.Fatalf("a claim on a signed plane: exit %d, %q; want a refusal naming --key", code, stderr)
	}
	if again := admitTransfer(t, p, "req-hold-2"); again.Action == core.Execute {
		t.Fatal("the retry ran after a refused claim")
	}
	keys := filepath.Join(t.TempDir(), "alice")
	if err := policykey.WriteKeyPair(keys, signedTestKey("alice")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := approvalsCommand(t, "approve", "--key", filepath.Join(keys, policykey.PrivateFile),
		"--inbox", filepath.Join(tr.dir, "inbox"), dir, held.Pending.ApprovalID)
	if code != 0 || !strings.Contains(stdout, held.Pending.ActionDigest) {
		t.Fatalf("signing: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	retry := admitTransfer(t, p, "req-hold-3")
	if retry.Action != core.Execute {
		t.Fatalf("the retry after a signed answer is %v: %v", retry.Action, retry.Decision.GetReasonCodes())
	}
	closeExecution(t, p, retry)
	entries, err := os.ReadDir(filepath.Join(tr.dir, "inbox"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("the inbox holds %d entries (%v), want the one answer", len(entries), err)
	}
}
