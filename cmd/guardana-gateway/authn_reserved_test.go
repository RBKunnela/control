package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
)

// The record frame as the store's format states it, written out here so the
// rewrite below does not borrow the store's own encoder.
const (
	recordMagic  = "APPRVREC"
	recordHeader = len(recordMagic) + 8
)

// rewriteApprover replaces the approver id inside one framed record and
// frames the body again, as a writer of the directory with no use for the
// approvers' command would.
func rewriteApprover(t *testing.T, path, from, to string) {
	t.Helper()
	framed, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	old := []byte(`"approverId":"` + from + `"`)
	body := framed[recordHeader:]
	if len(framed) <= recordHeader || string(framed[:len(recordMagic)]) != recordMagic || !bytes.Contains(body, old) {
		t.Fatalf("%s is not a framed record naming approver %q", path, from)
	}
	body = bytes.Replace(body, old, []byte(`"approverId":"`+to+`"`), 1)
	out := make([]byte, recordHeader, recordHeader+len(body))
	copy(out, recordMagic)
	binary.BigEndian.PutUint32(out[len(recordMagic):], uint32(len(body))) //nolint:gosec // G115: a test record is a few hundred bytes
	binary.BigEndian.PutUint32(out[len(recordMagic)+4:], crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
	if err := os.WriteFile(path, append(out, body...), 0o600); err != nil { //nolint:gosec // G703: the test's own temporary directory
		t.Fatalf("writing %s: %v", path, err)
	}
}

// TestAHandWrittenAuthnApproverResumesNothingAndClosesUnknown: a plane lost a
// hold, and the record was answered by hand under the reserved prefix. The
// seam refuses to spend it, and the reconciliation closes the trail
// APPROVAL_STATE_UNKNOWN, never as an approval that came too late. The same
// rewrite to a plain claim closes APPROVAL_NOT_RESUMED, so the prefix is what
// changes the outcome.
func TestAHandWrittenAuthnApproverResumesNothingAndClosesUnknown(t *testing.T) {
	for _, c := range []struct{ approver, closes string }{
		{"night-officer", "APPROVAL_NOT_RESUMED"},
		{"authn:okta:alice", "APPROVAL_STATE_UNKNOWN"},
		{"AUTHN:okta:alice", "APPROVAL_STATE_UNKNOWN"},
		{"\u0430uthn:okta:alice", "APPROVAL_STATE_UNKNOWN"},
	} {
		t.Run(c.approver, func(t *testing.T) {
			tr := newTree(t)
			records, holds := tr.fileProvider(t)
			binding := lostHold(t, records, holds, time.Now().Add(50*time.Second))
			answerLost(t, records)
			rewriteApprover(t, filepath.Join(records, lostApproval+".1-answered.rec"), "duty-officer", c.approver)

			if c.closes == "APPROVAL_STATE_UNKNOWN" {
				consumeReserved(t, records, binding)
			}

			p := tr.plane(t)
			if r := p.pipeline.Reconcile(context.Background()); r.Closed != 1 {
				t.Fatalf("the reconciliation settled %+v, want the one lost hold closed", r)
			}
			blocks := p.pipeline.Stats().Blocks
			if blocks[c.closes] != 1 || len(blocks) != 1 {
				t.Errorf("the lost hold closed as %v, want one %s", blocks, c.closes)
			}
			if slices.Contains(namesUnder(t, records), lostApproval+".3-consumed.rec") {
				t.Error("the record was spent")
			}
		})
	}
}

// consumeReserved asks the seam to spend the lost hold's record and holds it
// to refusing with the reservation's sentinel.
func consumeReserved(t *testing.T, records string, binding approval.Binding) {
	t.Helper()
	store, err := approvals.OpenPlane(records)
	if err != nil {
		t.Fatalf("OpenPlane: %v", err)
	}
	got, err := (&approvalStore{plane: store}).Consume(context.Background(), binding, lostRequest, lostApproval, time.Now())
	if closeErr := store.Close(); closeErr != nil {
		t.Fatalf("closing the store: %v", closeErr)
	}
	if got != nil || !errors.Is(err, approval.ErrReservedApproverID) {
		t.Errorf("consuming through the seam = %v, %v; want nothing and ErrReservedApproverID", got, err)
	}
}

// answerLost approves the fixture's lost hold as an approver does.
func answerLost(t *testing.T, records string) {
	t.Helper()
	a, err := approvals.OpenApprover(records)
	if err != nil {
		t.Fatalf("OpenApprover: %v", err)
	}
	_, err = a.Answer(context.Background(), lostApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "duty-officer", "", time.Now())
	if closeErr := a.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("answering the lost hold: %v", err)
	}
}
