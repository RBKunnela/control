package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
)

// The approval id, the request and the approver a writer of the directory
// files a refused record under.
const (
	forgedApproval = "apr-forged-1"
	forgedRequest  = "req-forged-1"
	forgedApprover = "authn:okta:mallory"
)

// fileProviderOf is the directory provider among the ones the wiring takes.
func fileProviderOf(t *testing.T) provider {
	t.Helper()
	for _, p := range providers() {
		if p.name == "file" {
			return p
		}
	}
	t.Fatal("no file provider")
	return provider{}
}

// forgeRefused copies the framed record from under approvalID and requestID,
// naming an approver the claim rule refuses, as a writer of the directory
// with no use for the approvers' command would.
func forgeRefused(t *testing.T, dir, from, approvalID, requestID string) {
	t.Helper()
	framed, err := os.ReadFile(filepath.Join(dir, from)) //nolint:gosec // G304: the test's own temporary directory
	if err != nil || len(framed) <= recordHeader {
		t.Fatalf("reading %s: %v", from, err)
	}
	fields := map[string]json.RawMessage{}
	inner := map[string]json.RawMessage{}
	if err := json.Unmarshal(framed[recordHeader:], &fields); err != nil {
		t.Fatalf("the record body: %v", err)
	}
	if err := json.Unmarshal(fields["approval"], &inner); err != nil {
		t.Fatalf("the approval: %v", err)
	}
	quoted := func(s string) json.RawMessage { return json.RawMessage(`"` + s + `"`) }
	fields["approval_id"], inner["approvalId"] = quoted(approvalID), quoted(approvalID)
	fields["request_id"], inner["requestId"] = quoted(requestID), quoted(requestID)
	inner["approverId"] = quoted(forgedApprover)
	raw, err := json.Marshal(inner)
	if err != nil {
		t.Fatalf("marshalling the approval: %v", err)
	}
	fields["approval"] = raw
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshalling the record: %v", err)
	}
	writeFramed(t, filepath.Join(dir, approvalID+".0-held.rec"), body)
}

// TestARefusedRecordOfAnotherRequestStallsNoCall: a writer files a record for
// another request of the same action under an approver id the claim rule
// refuses. A retry of the held call still finds its own hold pending, resumes
// once it is approved and runs once, and the call after it reads the
// approval as spent.
func TestARefusedRecordOfAnotherRequestStallsNoCall(t *testing.T) {
	tr, plane := holdingPlane(t, fileProviderOf(t), 15*time.Minute)
	records := filepath.Join(tr.dir, recordsDir)

	held := admitTransfer(t, plane, "req-hold-1")
	if held.Action != core.AwaitApproval {
		t.Fatalf("the first call is %v, want a hold: %v", held.Action, held.Decision.GetReasonCodes())
	}
	forgeRefused(t, records, held.Pending.ApprovalID+".0-held.rec", forgedApproval, forgedRequest)
	waiting := admitTransfer(t, plane, "req-hold-2")
	if waiting.Action != core.AwaitApproval {
		t.Fatalf("the retry before any answer is %v, want the hold pending: %v", waiting.Action, waiting.Decision.GetReasonCodes())
	}
	if waiting.Pending.ApprovalID != held.Pending.ApprovalID {
		t.Fatalf("the retry is pending on %q, want the held approval %q", waiting.Pending.ApprovalID, held.Pending.ApprovalID)
	}

	answerFrom(t, records, held.Pending.ApprovalID, true)
	resumed := admitTransfer(t, plane, "req-hold-3")
	if resumed.Action != core.Execute {
		t.Fatalf("the approved retry is %v, want an execution: %v", resumed.Action, resumed.Decision.GetReasonCodes())
	}
	closeExecution(t, plane, resumed)
	spent := admitTransfer(t, plane, "req-hold-4")
	if codes := spent.Decision.GetReasonCodes(); spent.Action != core.Block || !slices.Contains(codes, "APPROVAL_ALREADY_USED") {
		t.Errorf("the call after the approved one is %v with %v, want a block with APPROVAL_ALREADY_USED", spent.Action, codes)
	}
	if s := plane.pipeline.Stats(); s.Executed != 1 {
		t.Errorf("%d execution(s); one approval is consumed once", s.Executed)
	}
	if !slices.Contains(namesUnder(t, records), forgedApproval+".0-held.rec") {
		t.Errorf("the refused record was touched: %v", namesUnder(t, records))
	}
}

// TestARefusedRecordUnderTheHeldRequestHidesNoRejection: a writer files a
// refused record under the held request's own id and another approval id.
// Once the approver rejects the held approval, the retry is refused with the
// rejection, never told to wait on a record the plane did not mint.
func TestARefusedRecordUnderTheHeldRequestHidesNoRejection(t *testing.T) {
	tr, plane := holdingPlane(t, fileProviderOf(t), 15*time.Minute)
	records := filepath.Join(tr.dir, recordsDir)

	held := admitTransfer(t, plane, "req-hold-1")
	if held.Action != core.AwaitApproval {
		t.Fatalf("the first call is %v, want a hold: %v", held.Action, held.Decision.GetReasonCodes())
	}
	forgeRefused(t, records, held.Pending.ApprovalID+".0-held.rec", forgedApproval, "req-hold-1")
	approver, err := approvals.OpenApprover(records)
	if err != nil {
		t.Fatalf("OpenApprover: %v", err)
	}
	_, err = approver.Answer(context.Background(), held.Pending.ApprovalID,
		controlv1.ApprovalState_APPROVAL_STATE_REJECTED, "approver-1", "no", time.Now())
	if closeErr := approver.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("rejecting %s: %v", held.Pending.ApprovalID, err)
	}

	refused := admitTransfer(t, plane, "req-hold-2")
	if codes := refused.Decision.GetReasonCodes(); refused.Action != core.Block || !slices.Contains(codes, "APPROVAL_REJECTED") {
		t.Errorf("the retry after the rejection is %v with %v, want a block with APPROVAL_REJECTED", refused.Action, codes)
	}
	if s := plane.pipeline.Stats(); s.Executed != 0 || s.Pending != 1 {
		t.Errorf("%d execution(s) and %d pending answer(s), want 0 and the first call's 1", s.Executed, s.Pending)
	}
}

// TestARefusedRecordThePlaneNeverHeldIsHeldAnew: the only record under the
// binding is one the claim rule refuses, filed as answered for a request this
// plane never held. The store cannot speak for it and the ledger holds no mark
// of it, so it proves no execution: the call is held anew and the record
// counted, never told that the approval was used.
func TestARefusedRecordThePlaneNeverHeldIsHeldAnew(t *testing.T) {
	tr, plane := holdingPlane(t, fileProviderOf(t), 15*time.Minute)
	records := filepath.Join(tr.dir, recordsDir)
	bundle := approval.BundleDigest(plane.holder.Current().Ref().GetDigest())
	digest, binding, err := approval.Bind(transferEnvelope(t, forgedRequest), transferArgs, bundle)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	now := time.Now()
	writeRecord(t, filepath.Join(records, forgedApproval+".1-answered.rec"), &controlv1.Approval{
		SchemaVersion: "1.0", ApprovalId: forgedApproval, RequestId: forgedRequest,
		ActionDigest: string(digest), PolicyBundleDigest: string(bundle),
		State: controlv1.ApprovalState_APPROVAL_STATE_APPROVED, ApproverId: forgedApprover,
		RequestedAt: timestamppb.New(now.Add(-time.Minute)), DecidedAt: timestamppb.New(now.Add(-time.Second)),
		ExpiresAt: timestamppb.New(now.Add(10 * time.Minute)),
	}, binding)

	call := admitTransfer(t, plane, "req-new-1")
	if call.Action != core.AwaitApproval {
		t.Fatalf("the call is %v with %v, want a hold of its own", call.Action, call.Decision.GetReasonCodes())
	}
	if s := plane.pipeline.Stats(); s.UnheldRecords != 1 || s.Executed != 0 {
		t.Errorf("%d unheld record(s) counted and %d execution(s), want 1 and 0", s.UnheldRecords, s.Executed)
	}
}
