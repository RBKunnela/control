package gateway_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// TestARejectionTheChecksRefuseIsNeverRecordedAsDecided: a store that hands
// back a rejection that is not the held approval, rejected, of this contract's
// major and decided by the plane's clock has it checked as an approval is. Its
// record is never written as APPROVAL_DECIDED: the held trail closes with the
// approval the plane minted, expired, or the hold waits for an answer it can
// read, and nothing runs. The genuine rejection is the record APPROVAL_DECIDED
// carries.
func TestARejectionTheChecksRefuseIsNeverRecordedAsDecided(t *testing.T) {
	cases := []struct {
		name    string
		lie     func(*controlv1.Approval) *controlv1.Approval
		outcome int
		verdict controlv1.Verdict
		code    string
	}{
		{"the genuine rejection", func(a *controlv1.Approval) *controlv1.Approval { return a }, closesRejected, verdictDeny, codeApprovalRejected},
		{"no record", func(*controlv1.Approval) *controlv1.Approval { return nil }, holdsAnew, 0, ""},
		{"another approval", func(a *controlv1.Approval) *controlv1.Approval { a.ApprovalId = "a-other"; return a }, waits, 0, ""},
		{"another request", func(a *controlv1.Approval) *controlv1.Approval { a.RequestId = "req-other"; return a }, holdsAnew, 0, ""},
		{"multi-use", func(a *controlv1.Approval) *controlv1.Approval { a.MultiUse = true; return a }, waits, 0, ""},
		{"another digest", func(a *controlv1.Approval) *controlv1.Approval { a.ActionDigest = "sha256:" + digits; return a }, closesExpired, verdictDeny, codeApprovalDigestMismatch},
		{"another bundle", func(a *controlv1.Approval) *controlv1.Approval { a.PolicyBundleDigest = "sha256:" + digits; return a }, closesExpired, verdictDeny, codeApprovalBundleMismatch},
		{"an expiry past the minted one", func(a *controlv1.Approval) *controlv1.Approval {
			a.ExpiresAt = timestamppb.New(base().Add(time.Hour))
			return a
		}, closesExpired, verdictIndeterminate, codeEvidenceUnavailable},
		{"another major", func(a *controlv1.Approval) *controlv1.Approval { a.SchemaVersion = "9.0"; return a }, closesExpired, verdictIndeterminate, codeEvidenceUnavailable},
		{"decided after the reading", func(a *controlv1.Approval) *controlv1.Approval {
			a.DecidedAt = timestamppb.New(base().Add(time.Nanosecond))
			return a
		}, waits, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeStore()
			h := withStore(t, f)
			first := hold(t, h)
			if err := f.Answer(first.Pending.ApprovalID, rejected, "bob", "not today", base()); err != nil {
				t.Fatalf("Answer: %v", err)
			}
			lieAbout(f, tc.lie)
			d := h.admit(retry(t, "req-2"), refundArgs())
			expectLiedTo(t, h, d, first, tc.outcome, tc.verdict, tc.code)
			if s := h.p.Stats(); s.Executed != 0 {
				t.Errorf("Stats: %d executed; want nothing run", s.Executed)
			}
			if tc.outcome == closesRejected {
				if a := h.trailOf("req-1")[3].GetApproval(); a.GetApproverId() != "bob" || a.GetReason() != "not today" {
					t.Errorf("APPROVAL_DECIDED carries %+v; want the rejection", a)
				}
			}
		})
	}
}

// TestAnApprovalOfAnotherMajorOrDecidedLaterNeverRuns: an approval of a major
// this build does not read, or with none, closes the held trail; one with no
// decision time, or decided after the plane's clock reading or before its
// request, is no answer yet and the hold waits. The call never runs; a later
// minor, and an answer decided at that very reading, run.
func TestAnApprovalOfAnotherMajorOrDecidedLaterNeverRuns(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*controlv1.Approval)
		runs  bool
		waits bool
	}{
		{"major 1", func(*controlv1.Approval) {}, true, false},
		{"a later minor", func(a *controlv1.Approval) { a.SchemaVersion = "1.7" }, true, false},
		{"decided at the reading", func(a *controlv1.Approval) { a.DecidedAt = timestamppb.New(base()) }, true, false},
		{"another major", func(a *controlv1.Approval) { a.SchemaVersion = "9.0" }, false, false},
		{"major 10", func(a *controlv1.Approval) { a.SchemaVersion = "10.0" }, false, false},
		{"no version", func(a *controlv1.Approval) { a.SchemaVersion = "" }, false, false},
		{"a major alone", func(a *controlv1.Approval) { a.SchemaVersion = "1" }, false, false},
		{"a major and a dot", func(a *controlv1.Approval) { a.SchemaVersion = "1." }, false, false},
		{"a minor that is no number", func(a *controlv1.Approval) { a.SchemaVersion = "1.x" }, false, false},
		{"a third part", func(a *controlv1.Approval) { a.SchemaVersion = "1.0.0" }, false, false},
		{"a signed minor", func(a *controlv1.Approval) { a.SchemaVersion = "1.-3" }, false, false},
		{"a minor past 32 bits", func(a *controlv1.Approval) { a.SchemaVersion = "1.4294967296" }, false, false},
		{"a major with a leading zero", func(a *controlv1.Approval) { a.SchemaVersion = "01.0" }, false, false},
		{"decided after the reading", func(a *controlv1.Approval) { a.DecidedAt = timestamppb.New(base().Add(time.Nanosecond)) }, false, true},
		{"no decision time", func(a *controlv1.Approval) { a.DecidedAt = nil }, false, true},
		{"decided before the request", func(a *controlv1.Approval) {
			a.DecidedAt = timestamppb.New(a.GetRequestedAt().AsTime().Add(-time.Nanosecond))
		}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeStore()
			h := withStore(t, f)
			holdApproved(t, h, f)
			f.found = tc.edit
			d := h.admit(retry(t, "req-2"), refundArgs())
			switch {
			case tc.runs:
				if d.Action != core.Execute {
					t.Errorf("%s %v, want the approved call handed out", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
				}
				return
			case tc.waits:
				if d.Action != core.AwaitApproval {
					t.Errorf("Action = %d, want the hold waiting", d.Action)
				}
			default:
				expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			}
			if s := h.p.Stats(); s.Executed != 0 || s.Open != 0 {
				t.Errorf("Stats: %d executed, %d open; want nothing run", s.Executed, s.Open)
			}
		})
	}
}

// TestAMultiUseApprovalIsLeftPending: a store that holds the approval as
// multi-use is refused without anything being spent or written: the retry is
// answered pending with the held approval, nothing is handed out, and the
// refusal is counted once.
func TestAMultiUseApprovalIsLeftPending(t *testing.T) {
	f := newFakeStore()
	h := withStore(t, f)
	first := hold(t, h)
	f.found = func(a *controlv1.Approval) { a.MultiUse = true }
	d := h.admit(retry(t, "req-2"), refundArgs())
	if d.Action != core.AwaitApproval || pendingID(d) != first.Pending.ApprovalID {
		t.Errorf("the retry: Action = %d, pending %q; want pending on %q", d.Action, pendingID(d), first.Pending.ApprovalID)
	}
	if d.AuthorizedArgs != nil || d.ExecutionID != "" {
		t.Errorf("the retry handed out %q under execution %q", d.AuthorizedArgs, d.ExecutionID)
	}
	expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if s := h.p.Stats(); s.MultiUseRefused != 1 || s.Pending != 2 || s.Executed != 0 || s.Held != 1 || len(s.Blocks) != 0 {
		t.Errorf("Stats: %d multi-use refused, %d pending, %d executed, %d held, blocks %v; want 1, 2, 0, 1 and none",
			s.MultiUseRefused, s.Pending, s.Executed, s.Held, s.Blocks)
	}
}
