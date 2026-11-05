package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/brand"
)

// recordOf reads one record back through the store, which is the plane's own
// view of it and not the listing's rendering of it.
func recordOf(t *testing.T, dir, approvalID string) approvals.Record {
	t.Helper()
	store, err := approvals.OpenApprover(dir)
	if err != nil {
		t.Fatalf("opening an approver over %s: %v", dir, err)
	}
	defer func() { _ = store.Close() }()
	l, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("listing %s: %v", dir, err)
	}
	for _, e := range l.Entries {
		if e.Record.ApprovalID == approvalID {
			return e.Record
		}
	}
	t.Fatalf("no record %q under %s", approvalID, dir)
	return approvals.Record{}
}

// TestAnswerFilesTheApproverAndNothingElse: an answer changes the state, the
// approver, the reason and the decided time, and leaves the binding, the
// digest and the expiry the plane minted exactly as they were.
func TestAnswerFilesTheApproverAndNothingElse(t *testing.T) {
	for command, want := range map[string]controlv1.ApprovalState{
		"approve": controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
		"reject":  controlv1.ApprovalState_APPROVAL_STATE_REJECTED,
	} {
		t.Run(command, func(t *testing.T) {
			dir, plane := newStore(t)
			expires := clockNow().Add(15 * time.Minute)
			hold(t, plane, waitingID, expires)

			code, stdout, stderr := invoke(t, "approvals", command, "--approver-id", "duty-officer", "--reason", approverReason, dir, waitingID)
			if code != exitOK || stderr != "" {
				t.Fatalf("exit %d with %q, want 0 and nothing on stderr", code, stderr)
			}
			if !strings.Contains(stdout, waitingID) || !strings.Contains(stdout, "duty-officer") {
				t.Errorf("stdout = %q, want the approval and the approver it was filed under", stdout)
			}
			assertFiled(t, dir, want, expires)
		})
	}
}

// assertFiled reads the record back through the store and holds it to what an
// answer may change and to what it may not.
func assertFiled(t *testing.T, dir string, want controlv1.ApprovalState, expires time.Time) {
	t.Helper()
	rec := recordOf(t, dir, waitingID)
	if got := rec.Approval.GetState(); got != want {
		t.Errorf("state = %s, want %s", got, want)
	}
	if got := rec.Approval.GetApproverId(); got != "duty-officer" {
		t.Errorf("approver = %q, want %q", got, "duty-officer")
	}
	if got := rec.Approval.GetReason(); got != approverReason {
		t.Errorf("reason = %q, want %q", got, approverReason)
	}
	if rec.Approval.GetDecidedAt() == nil {
		t.Error("the record carries no decided time")
	}
	if got := rec.Approval.GetActionDigest(); got != string(digestOf(t, waitingID)) {
		t.Errorf("action digest = %q, want the one the plane minted", got)
	}
	if got := rec.Approval.GetExpiresAt().AsTime(); !got.Equal(expires) {
		t.Errorf("expiry = %s, want %s", got, expires)
	}
}

// TestAnswerWithoutAnApproverIDIsRefused: an approval nobody claims is not an
// approval, so both commands refuse the call before it reaches the directory.
func TestAnswerWithoutAnApproverIDIsRefused(t *testing.T) {
	for _, command := range []string{"approve", "reject"} {
		t.Run(command, func(t *testing.T) {
			dir, plane := newStore(t)
			hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
			before := files(t, dir)

			code, stdout, stderr := invoke(t, "approvals", command, dir, waitingID)
			if code != exitUsage {
				t.Errorf("exit %d, want %d", code, exitUsage)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
			if line := oneStderrLine(t, stderr); !strings.Contains(line, "--approver-id") {
				t.Errorf("stderr = %q, want a line naming the flag", line)
			}
			if after := files(t, dir); !maps.Equal(before, after) {
				t.Error("the directory changed under a call that was refused")
			}
		})
	}
}

// TestAnswerRefusalsAreDistinguishable: every state an answer can meet is its
// own line an operator can act on, and none of them changes the directory.
func TestAnswerRefusalsAreDistinguishable(t *testing.T) {
	dir, _ := everyState(t)
	before := files(t, dir)

	lines := map[string]string{}
	for name, tc := range map[string]struct{ id, want string }{
		"no such approval": {"NOSUCH", "no record under that approval id"},
		"answered already": {answeredID, "answered this approval already"},
		"expired":          {staleID, "past its expiry"},
	} {
		line := refusalLine(t, dir, tc.id)
		if !strings.HasPrefix(line, brand.CLI+": "+approveName+": ") || !strings.Contains(line, tc.want) {
			t.Errorf("%s: stderr = %q, want a line containing %q", name, line, tc.want)
		}
		if !strings.Contains(line, "nothing was written") {
			t.Errorf("%s: stderr = %q, does not say the directory was left alone", name, line)
		}
		for other, seen := range lines {
			if seen == line {
				t.Errorf("%s and %s are refused with the same line %q", name, other, line)
			}
		}
		lines[name] = line
	}
	if after := files(t, dir); !maps.Equal(before, after) {
		t.Error("a refused answer changed the directory")
	}
}

// refusalLine answers one approval, holds the call to a refusal that printed
// nothing on stdout, and returns the one line it wrote on stderr.
func refusalLine(t *testing.T, dir, approvalID string) string {
	t.Helper()
	code, stdout, stderr := invoke(t, "approvals", "approve", "--approver-id", "duty-officer", dir, approvalID)
	if code != exitFail || stdout != "" {
		t.Errorf("%s: exit %d with %q on stdout, want %d and nothing", approvalID, code, stdout, exitFail)
	}
	return oneStderrLine(t, stderr)
}

// TestBoundedFieldsAreRefusedBeforeTheyReachARecord: the approver id and the
// reason are held to their bounds and to no control character, and the input
// one byte past each bound is the input at which the bound bites. The command
// is reached past the dispatcher, which would refuse a control character
// first.
func TestBoundedFieldsAreRefusedBeforeTheyReachARecord(t *testing.T) {
	for name, tc := range map[string]struct {
		approverID, reason string
		want               string
	}{
		"a control character in the approver id": {"duty\x01officer", "", "approver id"},
		"a newline in the approver id":           {"duty\nofficer", "", "approver id"},
		"an approver id past its bound":          {strings.Repeat("a", approvals.MaxApproverIDBytes+1), "", "approver id"},
		"a control character in the reason":      {"duty-officer", "checked\x07with the desk", "reason"},
		"a newline in the reason":                {"duty-officer", "checked\nwith the desk", "reason"},
		"a reason past its bound":                {"duty-officer", strings.Repeat("r", approvals.MaxReasonBytes+1), "reason"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, plane := newStore(t)
			hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
			before := files(t, dir)

			code, stdout, stderr := invokeCommand(t, approveCommand, "--approver-id", tc.approverID, "--reason", tc.reason, dir, waitingID)
			if code != exitFail || stdout != "" {
				t.Errorf("exit %d with %q on stdout, want %d and nothing", code, stdout, exitFail)
			}
			if line := oneStderrLine(t, stderr); !strings.Contains(line, tc.want) {
				t.Errorf("stderr = %q, want a line naming the %s", line, tc.want)
			}
			if after := files(t, dir); !maps.Equal(before, after) {
				t.Error("a refused answer reached the directory")
			}
		})
	}
}

// TestAtTheBoundTheAnswerIsFiled is the other side of the bounds above:
// exactly at the limit the answer is filed, so the refusals there are the
// bound biting and not the command refusing everything long.
func TestAtTheBoundTheAnswerIsFiled(t *testing.T) {
	dir, plane := newStore(t)
	hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
	id := strings.Repeat("a", approvals.MaxApproverIDBytes)
	reason := strings.Repeat("r", approvals.MaxReasonBytes)

	code, _, stderr := invoke(t, "approvals", "approve", "--approver-id", id, "--reason", reason, dir, waitingID)
	if code != exitOK {
		t.Fatalf("exit %d with %q, want 0", code, stderr)
	}
	rec := recordOf(t, dir, waitingID)
	if got := rec.Approval.GetApproverId(); got != id {
		t.Errorf("the record carries an approver id of %d bytes, want %d", len(got), len(id))
	}
	if got := rec.Approval.GetReason(); got != reason {
		t.Errorf("the record carries a reason of %d bytes, want %d", len(got), len(reason))
	}
}

// TestAnswerWithNoPlaneHoldingTheDirectory: the answer is written, because
// the alternative closes that call's trail as one nobody answered, which is
// false about a person who did decide. The call still does not run, so the
// operator is told all four of the things that are now true.
func TestAnswerWithNoPlaneHoldingTheDirectory(t *testing.T) {
	dir, plane := newStore(t)
	hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
	if err := plane.Close(); err != nil {
		t.Fatalf("closing the plane: %v", err)
	}

	code, stdout, stderr := invoke(t, "approvals", "approve", "--approver-id", "duty-officer", "--reason", approverReason, dir, waitingID)
	if code != exitOK {
		t.Fatalf("exit %d with %q, want 0: the answer was written", code, stderr)
	}
	if !strings.Contains(stdout, waitingID) {
		t.Errorf("stdout = %q, want the approval it filed", stdout)
	}
	rec := recordOf(t, dir, waitingID)
	if got := rec.Approval.GetState(); got != controlv1.ApprovalState_APPROVAL_STATE_APPROVED {
		t.Errorf("state = %s, want approved: the answer is not on disk", got)
	}
	if got := rec.Approval.GetApproverId(); got != "duty-officer" {
		t.Errorf("approver = %q, want %q", got, "duty-officer")
	}
	if rec.Approval.GetDecidedAt() == nil {
		t.Error("the record carries no decided time")
	}
	// Each fact changes what the operator does next, so each is asserted on
	// its own: a notice that lost one of them still passes a test that only
	// looked for a warning.
	for name, want := range map[string]string{
		"that no plane holds the directory":     "no plane holds this directory",
		"that the call will not run":            "will not run",
		"that the answer was written":           "is written to the directory",
		"what a journalling plane does with it": "plane that keeps a hold journal",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not say %s (%q):\n%s", name, want, stderr)
		}
	}
}

// TestAnswerWithAPlaneRunningSaysNothingExtra: the notice above is for the
// case it names, and an answer a plane is waiting for is one line on stdout.
func TestAnswerWithAPlaneRunningSaysNothingExtra(t *testing.T) {
	dir, plane := newStore(t)
	hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
	code, _, stderr := invoke(t, "approvals", "approve", "--approver-id", "duty-officer", dir, waitingID)
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d with %q, want 0 and nothing on stderr", code, stderr)
	}
}

// TestAnswerRefusesADirectoryThatIsNotAStore: the answering commands refuse
// the wrong path the way the listing does, rather than making a store of it.
func TestAnswerRefusesADirectoryThatIsNotAStore(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := invoke(t, "approvals", "approve", "--approver-id", "duty-officer", dir, waitingID)
	if code != exitFail || stdout != "" {
		t.Errorf("exit %d with %q on stdout, want %d and nothing", code, stdout, exitFail)
	}
	if line := oneStderrLine(t, stderr); !strings.HasPrefix(line, brand.CLI+": "+approveName+": ") {
		t.Errorf("stderr = %q, want a refusal under the command's own name", line)
	}
	if len(files(t, dir)) != 0 {
		t.Error("a refused answer wrote into a directory that is not a store")
	}
}

// TestAnAnswerOfUnknownOutcomeSaysToLookFirst: a write that failed after the
// plane may have read it tells the operator to list before answering again,
// even beside the error that made the write fail.
func TestAnAnswerOfUnknownOutcomeSaysToLookFirst(t *testing.T) {
	err := errors.Join(fs.ErrPermission, fmt.Errorf("%w: %q", approvals.ErrOutcomeUnknown, "APPROVAL1.1-answered.rec"))
	if hint := answerHint(err); !strings.Contains(hint, "may have read") || !strings.Contains(hint, "approvals list") {
		t.Errorf("hint = %q", hint)
	}
}
