package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/internal/recovery"
)

// TestASpentApprovalStaysSpentAcrossARestore is the recovery guide's check.
// The backup is taken while a hold pends, before any approval is spent; the
// approver's answer to that hold comes after it. The call is then approved
// and spent, the floors and the spool are lost, and the state is restored
// from that backup, which alone can build the floors again. The same call
// retried runs nowhere: where the hold journal survived, its ledger answers
// that the approval was spent, which a restore bringing back the backup's
// journal would undo; where the journal was lost too, the call is held anew.
func TestASpentApprovalStaysSpentAcrossARestore(t *testing.T) {
	for _, c := range []struct {
		name        string
		journalLost bool
		want        func(*testing.T, *sdk.CallToolResult)
	}{
		{"the journal kept", false, func(t *testing.T, again *sdk.CallToolResult) {
			body := planeFields(again.Meta)
			codes, _ := body["reason_codes"].([]any)
			if !again.IsError || body["answer"] != "blocked" || !slices.Contains(codes, any("APPROVAL_ALREADY_USED")) {
				t.Fatalf("the retry after the restore answered %v, want APPROVAL_ALREADY_USED from the ledger", body)
			}
		}},
		{"the journal lost", true, func(t *testing.T, again *sdk.CallToolResult) { pendingApproval(t, again) }},
	} {
		t.Run(c.name, func(t *testing.T) { c.want(t, retryAfterARestore(t, c.journalLost)) })
	}
}

// retryAfterARestore is one case of TestASpentApprovalStaysSpentAcrossARestore
// up to the retry after the restore, which it returns; the hold journal is
// lost with the floors and the spool when journalLost is set.
func retryAfterARestore(t *testing.T, journalLost bool) *sdk.CallToolResult {
	tr := newTree(t)
	records, holds := tr.fileProvider(t)
	collector := newAcceptingCollector(t)
	upstream := tr.approveConfiguration(t, collector.url)

	first := tr.startPlane(t)
	held := pendingApproval(t, callTransfer(t, connectAgent(t, first.address(t)), "a"))
	first.kill(t)
	cfg := tr.load(t)
	backup := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(t.Context(), cfg, backup, time.Now()); err != nil {
		t.Fatalf("state backup: %v", err)
	}
	answerFrom(t, records, held, false)

	second := tr.startPlane(t)
	agent := connectAgent(t, second.address(t))
	answerFrom(t, records, pendingApproval(t, callTransfer(t, agent, "a")), true)
	if granted := callTransfer(t, agent, "a"); granted.IsError {
		t.Fatalf("the approved retry was refused: %+v", granted.StructuredContent)
	}
	second.stop(t)
	if ran := upstream.count(); ran != 1 {
		t.Fatalf("the upstream ran %d times before the restore, want 1", ran)
	}

	lost := []string{filepath.Join(tr.dir, "floors"), filepath.Join(tr.dir, "spool")}
	if journalLost {
		lost = append(lost, holds)
	}
	for _, dir := range lost {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range lost[1:] {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	restoredAt := time.Now()
	if _, err := recovery.Restore(t.Context(), cfg, backup, restoredAt); err != nil {
		t.Fatalf("state restore: %v", err)
	}
	// The restored floor is stamped at the restore, rounded up to the
	// second, and only a statement issued since confirms the bundle.
	time.Sleep(time.Until(restoredAt.Truncate(time.Second).Add(2 * time.Second)))
	writeStatement(t, filepath.Join(tr.dir, "policy.statement"), tr.dir+"/approve.bundle", time.Now().Truncate(time.Second))

	third := tr.startPlane(t)
	again := callTransfer(t, connectAgent(t, third.address(t)), "a")
	third.stop(t)
	if ran := upstream.count(); ran != 1 {
		t.Fatalf("the upstream ran %d times; the retry after the restore ran on a spent approval: %+v", ran, again.StructuredContent)
	}
	return again
}
