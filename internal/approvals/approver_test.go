package approvals_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
)

// answerer is the method the two handles are kept apart by.
type answerer interface {
	Answer(context.Context, string, controlv1.ApprovalState, string, string, time.Time) (approvals.Answered, error)
}

// TestOnlyTheApproverCanAnswer holds the rule the compiler is meant to carry:
// the plane's handle has no way to grant an approval to itself. The second
// half is what makes the first half able to fail.
func TestOnlyTheApproverCanAnswer(t *testing.T) {
	var plane any = &approvals.Plane{}
	if _, ok := plane.(answerer); ok {
		t.Error("the plane's handle answers approvals; the two handles are meant to be kept apart")
	}
	var approver any = &approvals.Approver{}
	if _, ok := approver.(answerer); !ok {
		t.Error("the approver's handle has no Answer of this shape, so the check above proves nothing")
	}
}

// heldOne holds one request and returns the plane, the directory and the hold.
func heldOne(t *testing.T) (*approvals.Plane, string, approvals.Hold) {
	t.Helper()
	p, dir := openPlane(t)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	return p, dir, h
}

// TestAnAnswerThatIsNotAnAnswerIsRefusedAndNotFiled. An approval with nobody
// claiming it is a grant nobody made.
func TestAnAnswerThatIsNotAnAnswerIsRefusedAndNotFiled(t *testing.T) {
	_, dir, _ := heldOne(t)
	a := openApprover(t, dir)
	cases := []struct {
		name       string
		state      controlv1.ApprovalState
		approverID string
		reason     string
		decidedAt  time.Time
		want       approvals.Error
	}{
		{"approved with no approver", controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "", "", minted, approvals.ErrApproverID},
		{"pending", controlv1.ApprovalState_APPROVAL_STATE_PENDING, "approver-1", "", minted, approvals.ErrApprovalAnswer},
		{"unspecified", controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED, "approver-1", "", minted, approvals.ErrApprovalAnswer},
		{"a state outside the enumeration", controlv1.ApprovalState(99), "approver-1", "", minted, approvals.ErrApprovalAnswer},
		{"at a zero clock", controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", time.Time{}, approvals.ErrZeroTime},
	}
	for _, c := range cases {
		_, err := a.Answer(t.Context(), firstApproval, c.state, c.approverID, c.reason, c.decidedAt)
		if !errors.Is(err, c.want) {
			t.Errorf("%s = %v, want %v", c.name, err, c.want)
		}
	}
	if names := recordNames(t, dir); len(names) != 1 || names[0] != "APPROVAL1.0-held.rec" {
		t.Fatalf("a refused answer files nothing; the directory holds %v", names)
	}
}

// TestTheApproverIDAndTheReasonAreBoundedBeforeTheyReachAnApproval names the
// length at which each refusal starts and the character that is refused.
func TestTheApproverIDAndTheReasonAreBoundedBeforeTheyReachAnApproval(t *testing.T) {
	cases := []struct {
		name       string
		approverID string
		reason     string
		want       approvals.Error
	}{
		{"an approver id at the bound", strings.Repeat("a", approvals.MaxApproverIDBytes), "", ""},
		{"an approver id one byte over", strings.Repeat("a", approvals.MaxApproverIDBytes+1), "", approvals.ErrApproverID},
		{"an approver id holding a control character", "approver\x07one", "", approvals.ErrApproverID},
		{"an approver id ending in white space", "approver ", "", approvals.ErrApproverID},
		{"an approver id that is not UTF-8", "approver\xff", "", approvals.ErrApproverID},
		{"a reason at the bound", "approver-1", strings.Repeat("r", approvals.MaxReasonBytes), ""},
		{"a reason one byte over", "approver-1", strings.Repeat("r", approvals.MaxReasonBytes+1), approvals.ErrReason},
		{"a reason holding a line feed", "approver-1", "first\nsecond", approvals.ErrReason},
		{"a reason holding a tab", "approver-1", "first\tsecond", approvals.ErrReason},
		{"a reason that is not UTF-8", "approver-1", "why\xff", approvals.ErrReason},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, dir, _ := heldOne(t)
			a := openApprover(t, dir)
			_, err := a.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, c.approverID, c.reason, minted)
			if c.want == "" {
				if err != nil {
					t.Fatalf("the answer at the bound was refused: %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("= %v, want %v", err, c.want)
			}
			if names := recordNames(t, dir); len(names) != 1 || names[0] != "APPROVAL1.0-held.rec" {
				t.Fatalf("a refused answer files nothing; the directory holds %v", names)
			}
		})
	}
}

// TestAnAnswerMovesNothingButTheAnswer. Every other field is the plane's, and
// the expected values here are the ones the fixture minted, written out.
func TestAnAnswerMovesNothingButTheAnswer(t *testing.T) {
	p, dir, h := heldOne(t)
	a := openApprover(t, dir)
	if _, err := a.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "signed off", minted.Add(time.Minute)); err != nil {
		t.Fatalf("answering: %v", err)
	}
	found, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	got := found[0].Approval
	if want := expires; !got.GetExpiresAt().AsTime().Equal(want) {
		t.Errorf("expires_at = %v, the plane minted %v", got.GetExpiresAt().AsTime(), want)
	}
	if want := minted; !got.GetRequestedAt().AsTime().Equal(want) {
		t.Errorf("requested_at = %v, the plane minted %v", got.GetRequestedAt().AsTime(), want)
	}
	if got.GetRequestId() != "req-1" || got.GetApprovalId() != firstApproval {
		t.Errorf("the answer moved an identifier: %v", got)
	}
	if got.GetPolicyBundleDigest() != string(bundle) {
		t.Errorf("policy_bundle_digest = %q, the fixture bound under %q", got.GetPolicyBundleDigest(), bundle)
	}
	if got.GetMultiUse() {
		t.Error("the answer turned the record multi-use")
	}
	if got.GetReason() != "signed off" || !got.GetDecidedAt().AsTime().Equal(minted.Add(time.Minute)) {
		t.Errorf("the answer itself did not land: %v", got)
	}
}

// answerRefused answers APPROVAL1 over dir and holds the refusal to want.
func answerRefused(t *testing.T, dir string, at time.Time, want approvals.Error) {
	t.Helper()
	a := openApprover(t, dir)
	_, err := a.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", at)
	if !errors.Is(err, want) {
		t.Fatalf("= %v, want %v", err, want)
	}
}

// TestASecondAnswerIsRefused.
func TestASecondAnswerIsRefused(t *testing.T) {
	_, dir, _ := heldOne(t)
	a := openApprover(t, dir)
	if _, err := a.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", minted.Add(time.Minute)); err != nil {
		t.Fatalf("the first answer: %v", err)
	}
	answerRefused(t, dir, minted.Add(2*time.Minute), approvals.ErrApprovalAnswered)
}

// TestAnAnswerAfterTheRecordExpiredIsRefused.
func TestAnAnswerAfterTheRecordExpiredIsRefused(t *testing.T) {
	_, dir, _ := heldOne(t)
	answerRefused(t, dir, expires, approvals.ErrApprovalExpired)
	if _, err := openApprover(t, dir).Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
		"approver-1", "", expires.Add(-time.Nanosecond)); err != nil {
		t.Errorf("an answer one nanosecond before the expiry = %v, want it filed", err)
	}
}

// TestAnAnswerToAnApprovalNobodyHeldIsRefused.
func TestAnAnswerToAnApprovalNobodyHeldIsRefused(t *testing.T) {
	_, dir, _ := heldOne(t)
	a := openApprover(t, dir)
	_, err := a.Answer(t.Context(), "APPROVAL9", controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", minted)
	if !errors.Is(err, approvals.ErrNoApproval) {
		t.Fatalf("= %v, want ErrNoApproval", err)
	}
	for _, id := range []string{"", "../escape", firstApproval + "/../" + firstApproval, ".hidden", strings.Repeat("a", 129)} {
		_, err := a.Answer(t.Context(), id, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", minted)
		if !errors.Is(err, approvals.ErrRecordName) {
			t.Errorf("answering %q = %v, want ErrRecordName", id, err)
		}
	}
}

// TestAnAnswerIsFiledWhetherOrNotAPlaneIsRunning. The held call does not run
// either way, because a hold does not survive a restart; what differs is what
// the evidence says afterwards, and an answer that was never written would
// close the trail as one nobody answered.
func TestAnAnswerIsFiledWhetherOrNotAPlaneIsRunning(t *testing.T) {
	t.Run("a plane holds the directory", func(t *testing.T) {
		p, dir, h := heldOne(t)
		a := openApprover(t, dir)
		result, err := a.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "signed off", minted.Add(time.Minute))
		if err != nil {
			t.Fatalf("answering: %v", err)
		}
		if !result.PlaneRunning {
			t.Fatal("a plane holds the directory and the answer says none does")
		}
		assertAnswerOnDisk(t, dir)
		if _, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute)); err != nil {
			t.Fatalf("the plane reads its own answer back: %v", err)
		}
	})

	t.Run("no plane holds the directory", func(t *testing.T) {
		p, dir, h := heldOne(t)
		a := openApprover(t, dir)
		if err := p.Close(); err != nil {
			t.Fatalf("closing the plane: %v", err)
		}
		result, err := a.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "signed off", minted.Add(time.Minute))
		if err != nil {
			t.Fatalf("answering with no plane running = %v; the answer is worth keeping", err)
		}
		if result.PlaneRunning {
			t.Fatal("no plane holds the directory and the answer says one does")
		}
		assertAnswerOnDisk(t, dir)

		// What the plane finds when it comes back is the person's decision,
		// which is what lets the trail close as answered rather than as one
		// nobody answered.
		restarted, err := approvals.OpenPlane(dir)
		if err != nil {
			t.Fatalf("restarting the plane: %v", err)
		}
		t.Cleanup(func() { _ = restarted.Close() })
		found, err := restarted.Find(t.Context(), h.Binding, minted.Add(2*time.Minute))
		if err != nil {
			t.Fatalf("finding after the restart: %v", err)
		}
		if len(found) != 1 || found[0].Approval.GetApproverId() != "approver-1" {
			t.Fatalf("the restarted plane reads %v", found)
		}
	})
}

// TestAListingSaysWhetherAPlaneIsRunning.
func TestAListingSaysWhetherAPlaneIsRunning(t *testing.T) {
	p, dir, _ := heldOne(t)
	a := openApprover(t, dir)
	listing, err := a.List(t.Context())
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if !listing.PlaneRunning {
		t.Fatal("a plane holds the directory and the listing says it does not")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("closing the plane: %v", err)
	}
	listing, err = a.List(t.Context())
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if listing.PlaneRunning {
		t.Fatal("the plane closed and the listing still says it holds the directory")
	}
}

// assertAnswerOnDisk reads the answered record through an approver's listing,
// which is the only reader that does not need the plane's lock.
func assertAnswerOnDisk(t *testing.T, dir string) {
	t.Helper()
	if names := recordNames(t, dir); !slices.Equal(names, []string{firstApproval + ".1-answered.rec"}) {
		t.Fatalf("the answered name alone stands, got %v", names)
	}
	a := openApprover(t, dir)
	listing, err := a.List(t.Context())
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(listing.Entries) != 1 {
		t.Fatalf("one record, got %d", len(listing.Entries))
	}
	got := listing.Entries[0].Record.Approval
	if got.GetState() != controlv1.ApprovalState_APPROVAL_STATE_APPROVED {
		t.Errorf("the record reads %s", got.GetState())
	}
	if got.GetApproverId() != "approver-1" || got.GetReason() != "signed off" {
		t.Errorf("the record names %q for %q", got.GetApproverId(), got.GetReason())
	}
	if !got.GetDecidedAt().AsTime().Equal(minted.Add(time.Minute)) {
		t.Errorf("decided_at = %v", got.GetDecidedAt().AsTime())
	}
}

// TestNothingOnDiskCarriesFreeText. Invariant 9 and ADR-0004 are not widened
// by a second human-readable copy of a held request.
func TestNothingOnDiskCarriesFreeText(t *testing.T) {
	_, dir, _ := heldOne(t)
	names := append(recordNames(t, dir), firstApproval+".view.json")
	for _, name := range names {
		body := readFile(t, dir, name)
		for _, secret := range []string{freeTextReason, freeTextPreview} {
			if bytes.Contains(body, []byte(secret)) {
				t.Errorf("%s carries free text: %q", name, secret)
			}
		}
	}
	if len(names) != 2 {
		t.Fatalf("the case reads the record and its projection, got %v", names)
	}
}

// TestTheProjectionCarriesWhatAnApproverNeeds.
func TestTheProjectionCarriesWhatAnApproverNeeds(t *testing.T) {
	_, dir, _ := heldOne(t)
	a := openApprover(t, dir)
	listing, err := a.List(t.Context())
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(listing.Entries) != 1 || listing.Entries[0].View == nil {
		t.Fatalf("one held record with its projection, got %+v", listing)
	}
	view := *listing.Entries[0].View
	for _, c := range []struct{ name, got, want string }{
		{"principal", view.Principal, "user-1"},
		{"agent", view.Agent, "agent-1"},
		{"action", view.Action, "refund"},
		{"upstream", view.Provider, "payments"},
		{"resource type", view.ResourceType, "payment"},
		{"resource id", view.ResourceID, "pay-9"},
		{"effect class", view.EffectClass, "EFFECT_CLASS_TRANSACT"},
		{"request id", view.RequestID, "req-1"},
		{"approval id", view.ApprovalID, firstApproval},
		{"bundle digest", view.PolicyBundleDigest, string(bundle)},
		{"rule ids", strings.Join(view.RuleIDs, ","), "rule-a,rule-b"},
	} {
		if c.got != c.want {
			t.Errorf("the projection's %s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if !view.ExpiresAt.Equal(expires) || !view.RequestedAt.Equal(minted) {
		t.Errorf("the projection's times = %v, %v", view.RequestedAt, view.ExpiresAt)
	}
}

// TestARecordWorksWithoutItsProjection, and the listing says which one lost it.
func TestARecordWorksWithoutItsProjection(t *testing.T) {
	p, dir, h := heldOne(t)
	if err := os.Remove(filepath.Join(dir, "APPROVAL1.view.json")); err != nil {
		t.Fatalf("removing the projection: %v", err)
	}
	if _, err := p.Find(t.Context(), h.Binding, minted); err != nil {
		t.Fatalf("a record without its projection has to answer: %v", err)
	}
	a := openApprover(t, dir)
	listing, err := a.List(t.Context())
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(listing.Entries) != 1 || listing.Entries[0].View != nil {
		t.Fatalf("the record is listed without a projection, got %+v", listing.Entries)
	}
	if len(listing.Problems) != 1 || listing.Problems[0].Name != "APPROVAL1.view.json" {
		t.Fatalf("the missing projection is named, got %+v", listing.Problems)
	}
}

// TestAListingThatCouldNotReadEverythingSaysSo. An incomplete listing is
// unmeasured, never a short one and never an empty one.
func TestAListingThatCouldNotReadEverythingSaysSo(t *testing.T) {
	p, dir := openPlane(t)
	for _, id := range []string{firstApproval, "APPROVAL2"} {
		if err := p.Hold(t.Context(), held(t, id, "req-"+id), minted); err != nil {
			t.Fatalf("holding %s: %v", id, err)
		}
	}
	t.Run("a bound that bites", func(t *testing.T) {
		a := openApprover(t, dir, approvals.WithMaxRecords(1))
		listing, err := a.List(t.Context())
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if listing.Complete {
			t.Fatal("a listing stopped by its bound says it is complete")
		}
		if len(listing.Entries) != 1 {
			t.Fatalf("the bound holds the listing to one entry, got %d", len(listing.Entries))
		}
	})
	t.Run("a record that will not decode", func(t *testing.T) {
		writeFile(t, dir, "APPROVAL2.0-held.rec", []byte("not a record"))
		a := openApprover(t, dir)
		listing, err := a.List(t.Context())
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if listing.Complete {
			t.Fatal("a listing that could not read a record says it is complete")
		}
		if len(listing.Entries) != 1 || listing.Entries[0].Record.ApprovalID != firstApproval {
			t.Fatalf("the readable record is still listed, got %+v", listing.Entries)
		}
		if len(listing.Problems) != 1 || !errors.Is(listing.Problems[0].Err, approvals.ErrTruncated) {
			t.Fatalf("the unreadable record is named with why, got %+v", listing.Problems)
		}
	})
}
