package approvals_test

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
)

// answerAt is what a test does to a held record when it is not testing the
// answer itself.
func answerAt(t *testing.T, dir string, at time.Time) {
	t.Helper()
	a := openApprover(t, dir)
	result, err := a.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "signed off", at)
	if err != nil {
		t.Fatalf("answering %s: %v", firstApproval, err)
	}
	if !result.PlaneRunning {
		t.Fatalf("a plane holds the directory and the answer says it does not")
	}
}

// TestAHeldRequestIsFoundBeforeAnybodyAnswersIt. A retry is recognised as the
// same request from the record; what nobody has answered reads as pending,
// not hidden from Find.
func TestAHeldRequestIsFoundBeforeAnybodyAnswersIt(t *testing.T) {
	p, _ := openPlane(t)
	ctx := t.Context()
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(ctx, h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	rec := findOne(t, p, h.Binding, minted)
	if rec.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Fatalf("the held record reads %s", rec.Approval.GetState())
	}
	if rec.Approval.GetApproverId() != "" || rec.Approval.GetDecidedAt() != nil {
		t.Fatalf("the held record carries an answer: %v", rec.Approval)
	}
}

// TestAnApprovalGivenBesideThePlaneResumesTheHeldRequest is the whole point of
// the package: the plane holds, another handle answers, and the plane reads
// the answer back as often as it asks, writing nothing: spending it is the
// plane's ledger's to record.
func TestAnApprovalGivenBesideThePlaneResumesTheHeldRequest(t *testing.T) {
	p, dir := openPlane(t)
	ctx := t.Context()
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(ctx, h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	answerAt(t, dir, minted.Add(time.Minute))

	rec := findOne(t, p, h.Binding, minted.Add(2*time.Minute))
	if rec.ApprovalID != firstApproval || rec.RequestID != "req-1" {
		t.Fatalf("the record names %q for request %q", rec.ApprovalID, rec.RequestID)
	}
	if got := rec.Approval.GetApproverId(); got != "approver-1" {
		t.Fatalf("approver_id = %q, the answer named approver-1", got)
	}

	if again := findOne(t, p, h.Binding, minted.Add(3*time.Minute)); again.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_APPROVED {
		t.Fatalf("a second read returned state %s", again.Approval.GetState())
	}
	if names := recordNames(t, dir); !slices.Equal(names, []string{firstApproval + ".1-answered.rec"}) {
		t.Fatalf("after the answer the answered name alone stands, got %v", names)
	}
}

// findOne fails unless exactly one record stands under binding.
func findOne(t *testing.T, p *approvals.Plane, binding approval.Binding, now time.Time) approvals.Record {
	t.Helper()
	found, err := p.Find(t.Context(), binding, now)
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("one record was filed, found %d", len(found))
	}
	return found[0]
}

// TestTheZeroHandlesApproveNothing holds the rule that a composite literal of
// either handle from another package is useless.
func TestTheZeroHandlesApproveNothing(t *testing.T) {
	var p approvals.Plane
	var a approvals.Approver
	ctx := t.Context()
	binding := bindingOf(t, "req-1")
	calls := map[string]error{
		"plane hold":      p.Hold(ctx, held(t, firstApproval, "req-1"), minted),
		"plane find":      second(p.Find(ctx, binding, minted)),
		"plane prune":     secondInt(p.Prune(ctx, minted)),
		"plane close":     p.Close(),
		"approver list":   secondListing(a.List(ctx)),
		"approver answer": secondAnswered(a.Answer(ctx, firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", minted)),
		"approver close":  a.Close(),
	}
	for name, err := range calls {
		if !errors.Is(err, approvals.ErrClosed) {
			t.Errorf("%s on a zero handle = %v, want ErrClosed", name, err)
		}
	}
}

func second(_ []approvals.Record, err error) error         { return err }
func secondInt(_ int, err error) error                     { return err }
func secondListing(_ approvals.Listing, err error) error   { return err }
func secondAnswered(_ approvals.Answered, err error) error { return err }

// TestASecondPlaneIsRefusedByThePlaneLock asserts the refusal is the lock and
// not the directory: the same directory opens for an approver while the plane
// holds it, and opens for a plane again once the first one has closed.
func TestASecondPlaneIsRefusedByThePlaneLock(t *testing.T) {
	dir := t.TempDir()
	first, err := approvals.OpenPlane(dir)
	if err != nil {
		t.Fatalf("opening the first plane: %v", err)
	}
	if _, err := approvals.OpenPlane(dir); !errors.Is(err, approvals.ErrLocked) {
		t.Fatalf("the second plane = %v, want ErrLocked", err)
	}
	if a, err := approvals.OpenApprover(dir); err != nil {
		t.Fatalf("an approver has to open beside the plane: %v", err)
	} else if err := a.Close(); err != nil {
		t.Fatalf("closing the approver: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("closing the first plane: %v", err)
	}
	again, err := approvals.OpenPlane(dir)
	if err != nil {
		t.Fatalf("the directory has to open once the lock is free: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
}

// TestADirectoryOthersMayWriteIsRefused names the mode at which the refusal
// starts: a directory a group may write is one whose approvals are theirs.
func TestADirectoryOthersMayWriteIsRefused(t *testing.T) {
	for _, c := range []struct {
		mode    os.FileMode
		refused bool
	}{
		{0o700, false},
		{0o750, false},
		{0o770, true},
		{0o707, true},
		{0o777, true},
	} {
		dir := t.TempDir()
		if err := os.Chmod(dir, c.mode); err != nil {
			t.Fatalf("chmod %04o: %v", c.mode, err)
		}
		p, err := approvals.OpenPlane(dir)
		switch {
		case c.refused && !errors.Is(err, approvals.ErrPermissions):
			t.Errorf("mode %04o = %v, want ErrPermissions", c.mode, err)
		case !c.refused && err != nil:
			t.Errorf("mode %04o = %v, want an open store", c.mode, err)
		}
		if err == nil {
			_ = p.Close()
		}
	}
}

// TestADirectoryThatIsNotAStoreIsRefused: a plane pointed at the wrong path
// holds every call rather than approving from an empty listing.
func TestADirectoryThatIsNotAStoreIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "notes.txt", []byte("someone else's directory\n"))
	if _, err := approvals.OpenPlane(dir); !errors.Is(err, approvals.ErrNotAStore) {
		t.Fatalf("a directory with a stranger's file = %v, want ErrNotAStore", err)
	}
	if _, err := approvals.OpenApprover(dir); !errors.Is(err, approvals.ErrNotAStore) {
		t.Fatalf("the approver over the same directory = %v, want ErrNotAStore", err)
	}
	empty := t.TempDir()
	if _, err := approvals.OpenApprover(empty); !errors.Is(err, approvals.ErrNotAStore) {
		t.Fatalf("an empty directory no plane made = %v, want ErrNotAStore", err)
	}
}

// TestAForeignFileUnderTheStoreRefusesTheScan: the store owns its directory,
// so a name it did not write is refused rather than skipped.
func TestAForeignFileUnderTheStoreRefusesTheScan(t *testing.T) {
	p, dir := openPlane(t)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	writeFile(t, dir, "APPROVAL1.9-whatever.rec", []byte("forged"))
	if _, err := p.Find(t.Context(), h.Binding, minted); !errors.Is(err, approvals.ErrForeignFile) {
		t.Fatalf("a foreign name = %v, want ErrForeignFile", err)
	}
}

// TestAFileNameThatDisagreesWithTheRecordIsRefused: the name is how the store
// finds a record and the content is what it answers from, so the two have to
// agree.
func TestAFileNameThatDisagreesWithTheRecordIsRefused(t *testing.T) {
	p, dir := openPlane(t)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	body := readFile(t, dir, "APPROVAL1.0-held.rec")
	if err := os.Remove(filepath.Join(dir, "APPROVAL1.0-held.rec")); err != nil {
		t.Fatalf("removing: %v", err)
	}
	writeFile(t, dir, "APPROVAL2.0-held.rec", body)
	_, err := p.Find(t.Context(), h.Binding, minted)
	if !errors.Is(err, approvals.ErrNameMismatch) {
		t.Fatalf("a record under another name = %v, want ErrNameMismatch", err)
	}
}

// TestARecordFiledUnderAnotherBindingIsRefused: a record whose binding is not
// the one its own digests make is refused, and one whose digests were changed
// with it answers about nothing the plane asked for.
func TestARecordFiledUnderAnotherBindingIsRefused(t *testing.T) {
	p, dir := openPlane(t)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	body := readFile(t, dir, "APPROVAL1.0-held.rec")
	other := otherBinding(t)
	if other == h.Binding {
		t.Fatal("the two fixtures share a binding; the case tests nothing")
	}
	writeFile(t, dir, "APPROVAL1.0-held.rec", reframe(t, replaceInBody(t, body, string(h.Binding), string(other))))
	if _, err := p.Find(t.Context(), h.Binding, minted); !errors.Is(err, approvals.ErrRecordMismatch) {
		t.Fatalf("a record filed under another binding = %v, want ErrRecordMismatch", err)
	}
}

// TestAnExpiredApprovalResumesNothing names the instant the bound bites: at
// the expiry itself, not a moment after it.
func TestAnExpiredApprovalResumesNothing(t *testing.T) {
	p, dir := openPlane(t)
	ctx := t.Context()
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(ctx, h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	answerAt(t, dir, minted.Add(time.Minute))

	if _, err := p.Find(ctx, h.Binding, expires.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("one nanosecond before the expiry the record still stands: %v", err)
	}
	if _, err := p.Find(ctx, h.Binding, expires); !errors.Is(err, approvals.ErrNoApproval) {
		t.Fatalf("at the expiry = %v, want ErrNoApproval", err)
	}
	if names := recordNames(t, dir); len(names) != 1 {
		t.Fatalf("a read drops nothing, %v is left", names)
	}
	if n, err := p.Prune(ctx, expires); n != 1 || err != nil {
		t.Fatalf("pruning at the expiry = %d, %v; want the record", n, err)
	}
	if names := recordNames(t, dir); len(names) != 0 {
		t.Fatalf("a pruned record leaves %v", names)
	}
}

// TestARejectedApprovalIsReadAsItStands: Find hands back the rejection with
// its reason, and nothing is dropped: the record goes when it expires.
func TestARejectedApprovalIsReadAsItStands(t *testing.T) {
	p, dir := openPlane(t)
	ctx := t.Context()
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(ctx, h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	a := openApprover(t, dir)
	if _, err := a.Answer(ctx, firstApproval, controlv1.ApprovalState_APPROVAL_STATE_REJECTED, "approver-1", "no", minted.Add(time.Minute)); err != nil {
		t.Fatalf("rejecting: %v", err)
	}
	rec := findOne(t, p, h.Binding, minted.Add(2*time.Minute))
	if rec.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_REJECTED || rec.Approval.GetReason() != "no" {
		t.Fatalf("the rejection reads %s for %q", rec.Approval.GetState(), rec.Approval.GetReason())
	}
	if names := recordNames(t, dir); !slices.Equal(names, []string{firstApproval + ".1-answered.rec"}) {
		t.Fatalf("a read of a rejection drops nothing, got %v", names)
	}
}

// TestAMultiUseRecordIsNotHonoured. The plane will hold one, because the field
// is the producer's; what it judges an answer by never lets it be spent.
func TestAMultiUseRecordIsNotHonoured(t *testing.T) {
	p, dir := openPlane(t)
	ctx := t.Context()
	h := held(t, firstApproval, "req-1")
	h.Approval.MultiUse = true
	if err := p.Hold(ctx, h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	answerAt(t, dir, minted.Add(time.Minute))
	rec := findOne(t, p, h.Binding, minted.Add(2*time.Minute))
	if got := approval.Consumable(rec.Approval, minted.Add(2*time.Minute)); got != approval.StandingMultiUse {
		t.Fatalf("a multi-use record stands %v, want multi-use", got)
	}
}

// TestACrashBetweenTheLinkAndTheUnlinkIsResolvedByTheOrder: two names for one
// record, and the reader takes the furthest along.
func TestACrashBetweenTheLinkAndTheUnlinkIsResolvedByTheOrder(t *testing.T) {
	p, dir := openPlane(t)
	ctx := t.Context()
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(ctx, h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	// The answer unlinks the held name; putting it back is what an unlink
	// interrupted by a crash leaves behind.
	pending := readFile(t, dir, "APPROVAL1.0-held.rec")
	answerAt(t, dir, minted.Add(time.Minute))
	writeFile(t, dir, "APPROVAL1.0-held.rec", pending)
	if names := recordNames(t, dir); len(names) != 2 {
		t.Fatalf("the case needs both names present, got %v", names)
	}
	found, err := p.Find(ctx, h.Binding, minted.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("finding with two names: %v", err)
	}
	if len(found) != 1 || found[0].Approval.GetApproverId() != "approver-1" {
		t.Fatalf("the furthest-along name has to win, got %v", found)
	}
}

// TestTheRecordCountBoundBites names the hold that is refused: the one past
// the bound, and not the one at it.
func TestTheRecordCountBoundBites(t *testing.T) {
	p, _ := openPlane(t, approvals.WithMaxRecords(2))
	ctx := t.Context()
	for i, id := range []string{firstApproval, "APPROVAL2"} {
		if err := p.Hold(ctx, held(t, id, "req-"+id), minted); err != nil {
			t.Fatalf("hold %d: %v", i+1, err)
		}
	}
	err := p.Hold(ctx, held(t, "APPROVAL3", "req-APPROVAL3"), minted)
	if !errors.Is(err, approvals.ErrTooManyRecords) {
		t.Fatalf("the third hold under a bound of two = %v, want ErrTooManyRecords", err)
	}
}

// TestTheRecordByteBoundBites derives the input from the record the plane
// writes, then asserts the behaviour changes on either side of it.
func TestTheRecordByteBoundBites(t *testing.T) {
	p, dir := openPlane(t)
	if err := p.Hold(t.Context(), held(t, firstApproval, "req-1"), minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	body := len(readFile(t, dir, "APPROVAL1.0-held.rec")) - frameHeaderBytes
	if body <= 0 {
		t.Fatalf("the record is %d bytes of body", body)
	}
	tight, _ := openPlane(t, approvals.WithMaxRecordBytes(body))
	if err := tight.Hold(t.Context(), held(t, firstApproval, "req-1"), minted); err != nil {
		t.Fatalf("a bound of exactly the body has to hold it: %v", err)
	}
	narrow, _ := openPlane(t, approvals.WithMaxRecordBytes(body-1))
	err := narrow.Hold(t.Context(), held(t, firstApproval, "req-1"), minted)
	if !errors.Is(err, approvals.ErrRecordTooLarge) {
		t.Fatalf("one byte under the body = %v, want ErrRecordTooLarge", err)
	}
}

// TestAZeroClockIsRefused: a zero reading would pass every expiry.
func TestAZeroClockIsRefused(t *testing.T) {
	p, _ := openPlane(t)
	ctx := t.Context()
	binding := bindingOf(t, "req-1")
	var zero time.Time
	calls := map[string]error{
		"hold":  p.Hold(ctx, held(t, firstApproval, "req-1"), zero),
		"find":  second(p.Find(ctx, binding, zero)),
		"prune": secondInt(p.Prune(ctx, zero)),
	}
	for name, err := range calls {
		if !errors.Is(err, approvals.ErrZeroTime) {
			t.Errorf("%s at a zero clock = %v, want ErrZeroTime", name, err)
		}
	}
}

// TestAHoldIsRefusedTwice under one binding and under one approval id.
func TestAHoldIsRefusedTwice(t *testing.T) {
	p, _ := openPlane(t)
	ctx := t.Context()
	if err := p.Hold(ctx, held(t, firstApproval, "req-1"), minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	if err := p.Hold(ctx, held(t, "APPROVAL2", "req-1"), minted); !errors.Is(err, approvals.ErrAlreadyHeld) {
		t.Fatalf("the same request under the same binding = %v, want ErrAlreadyHeld", err)
	}
	if err := p.Hold(ctx, held(t, firstApproval, "req-2"), minted); !errors.Is(err, approvals.ErrAlreadyHeld) {
		t.Fatalf("the same approval id = %v, want ErrAlreadyHeld", err)
	}
	if err := p.Hold(ctx, held(t, "APPROVAL2", "req-2"), minted); err != nil {
		t.Fatalf("another request under the same binding: %v", err)
	}
}

// TestThePlaneRefusesToHoldAnApprovalThatCarriesAnAnswer: a plane that could
// file its own grant would make the directory decoration.
func TestThePlaneRefusesToHoldAnApprovalThatCarriesAnAnswer(t *testing.T) {
	p, dir := openPlane(t)
	ctx := t.Context()
	cases := map[string]func(h *approvals.Hold){
		"approved":         func(h *approvals.Hold) { h.Approval.State = controlv1.ApprovalState_APPROVAL_STATE_APPROVED },
		"with an approver": func(h *approvals.Hold) { h.Approval.ApproverId = "approver-1" },
		"with no expiry":   func(h *approvals.Hold) { h.Approval.ExpiresAt = nil },
		"with no envelope": func(h *approvals.Hold) { h.Envelope = nil },
	}
	for name, spoil := range cases {
		h := held(t, firstApproval, "req-1")
		spoil(&h)
		if err := p.Hold(ctx, h, minted); !errors.Is(err, approvals.ErrInvalidHold) {
			t.Errorf("a hold %s = %v, want ErrInvalidHold", name, err)
		}
	}
	if names := recordNames(t, dir); len(names) != 0 {
		t.Fatalf("a refused hold writes nothing, %v is there", names)
	}
}

// TestPruneForgetsWhatExpired, and nothing else.
func TestPruneForgetsWhatExpired(t *testing.T) {
	p, dir := openPlane(t)
	ctx := t.Context()
	if err := p.Hold(ctx, held(t, firstApproval, "req-1"), minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	n, err := p.Prune(ctx, expires.Add(-time.Nanosecond))
	if err != nil || n != 0 {
		t.Fatalf("pruning before the expiry = %d, %v", n, err)
	}
	n, err = p.Prune(ctx, expires)
	if err != nil || n != 1 {
		t.Fatalf("pruning at the expiry = %d, %v; want one record", n, err)
	}
	if names := recordNames(t, dir); len(names) != 0 {
		t.Fatalf("%v is left after the prune", names)
	}
	if _, err := os.Stat(filepath.Join(dir, "APPROVAL1.view.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the projection goes with the record, stat = %v", err)
	}
}

// TestACutScanAnswersNothing: a directory past the bound is read only as far
// as the bound, so Find refuses rather than answer from the records the scan
// happened to reach.
func TestACutScanAnswersNothing(t *testing.T) {
	p, dir := openPlane(t)
	ctx := t.Context()
	for _, id := range []string{firstApproval, "APPROVAL2"} {
		if err := p.Hold(ctx, held(t, id, "req-"+id), minted); err != nil {
			t.Fatalf("holding %s: %v", id, err)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	bounded, err := approvals.OpenPlane(dir, approvals.WithMaxRecords(1))
	if err != nil {
		t.Fatalf("reopening under a bound of one: %v", err)
	}
	t.Cleanup(func() { _ = bounded.Close() })
	binding := bindingOf(t, "req-APPROVAL2")
	if found, err := bounded.Find(ctx, binding, minted); !errors.Is(err, approvals.ErrTooManyRecords) {
		t.Errorf("Find over a cut scan = %d record(s), %v; want ErrTooManyRecords", len(found), err)
	}
}

// TestAPruneOverACutScanSaysSo: a directory past the bound is read only as
// far as the bound, so the count a prune reports is of what it read and not
// of what expired. It forgets what it read, and says the sweep was cut.
func TestAPruneOverACutScanSaysSo(t *testing.T) {
	p, dir := openPlane(t)
	ctx := t.Context()
	for _, id := range []string{firstApproval, "APPROVAL2"} {
		if err := p.Hold(ctx, held(t, id, "req-"+id), minted); err != nil {
			t.Fatalf("holding %s: %v", id, err)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	bounded, err := approvals.OpenPlane(dir, approvals.WithMaxRecords(1))
	if err != nil {
		t.Fatalf("reopening under a bound of one: %v", err)
	}
	t.Cleanup(func() { _ = bounded.Close() })
	n, err := bounded.Prune(ctx, expires)
	if !errors.Is(err, approvals.ErrTooManyRecords) || n != 1 {
		t.Fatalf("pruning two expired records under a bound of one = %d, %v; want 1 and ErrTooManyRecords", n, err)
	}
	if names := recordNames(t, dir); !slices.Equal(names, []string{"APPROVAL2.0-held.rec"}) {
		t.Fatalf("after the cut prune the directory holds %v", names)
	}
	n, err = bounded.Prune(ctx, expires)
	if err != nil || n != 1 {
		t.Fatalf("pruning the one record left under a bound of one = %d, %v; want 1 and no error", n, err)
	}
}

// TestACancelledContextStopsTheCall.
func TestACancelledContextStopsTheCall(t *testing.T) {
	p, _ := openPlane(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := p.Hold(ctx, held(t, firstApproval, "req-1"), minted); !errors.Is(err, context.Canceled) {
		t.Fatalf("holding under a cancelled context = %v", err)
	}
}

// TestAPlaneStartsThroughMomentaryContention. Learning whether a plane holds
// the directory means taking the lock, so anything that asks holds it for an
// instant; a plane that refused to start inside that instant would be a
// failure nobody could diagnose.
//
// The holder here keeps the lock for a tenth of a second, which is far less
// than the wait and far more than the scheduler needs, so the plane's open
// begins while the lock is held: without the wait it is refused at once, and
// the elapsed time below is what proves the case was exercised rather than
// won by arriving late.
func TestAPlaneStartsThroughMomentaryContention(t *testing.T) {
	const hold = 100 * time.Millisecond
	dir := t.TempDir()
	holder, err := approvals.OpenPlane(dir)
	if err != nil {
		t.Fatalf("opening the holder: %v", err)
	}
	released := make(chan error, 1)
	go func() {
		time.Sleep(hold)
		released <- holder.Close()
	}()

	started := time.Now()
	p, err := approvals.OpenPlane(dir)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("opening through momentary contention = %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if err := <-released; err != nil {
		t.Fatalf("the holder did not release: %v", err)
	}
	if elapsed < hold/2 {
		t.Fatalf("the open took %v, so the lock was free when it began and the case tested nothing", elapsed)
	}
}

// TestAPlaneStartsWhileAnApproverProbesTheLock runs the real interaction: a
// listing takes and releases the plane lock, and a plane opens beside it. The
// probe's window is a few system calls wide, so this cannot be made to fail on
// demand; it is here because it exercises the two paths against each other,
// and the case above is the one that fails without the wait.
func TestAPlaneStartsWhileAnApproverProbesTheLock(t *testing.T) {
	p, dir := openPlane(t)
	if err := p.Close(); err != nil {
		t.Fatalf("closing the maker of the store: %v", err)
	}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		a, err := approvals.OpenApprover(dir)
		if err != nil {
			done <- err
			return
		}
		for {
			select {
			case <-stop:
				done <- a.Close()
				return
			default:
			}
			if _, err := a.List(t.Context()); err != nil {
				done <- err
				return
			}
		}
	}()
	for range 20 {
		opened, err := approvals.OpenPlane(dir)
		if err != nil {
			close(stop)
			<-done
			t.Fatalf("a plane has to open beside a listing: %v", err)
		}
		if err := opened.Close(); err != nil {
			close(stop)
			<-done
			t.Fatalf("closing: %v", err)
		}
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatalf("the listing loop: %v", err)
	}
}

// TestFindReturnsEveryStateUnderOneBinding: three requests of one action
// share a binding, because the canonical action digest leaves identifiers out,
// and Find hands back each, held or answered, as it stands. No record says
// what became of it after that.
func TestFindReturnsEveryStateUnderOneBinding(t *testing.T) {
	p, dir := openPlane(t)
	ctx := t.Context()
	binding := bindingOf(t, "req-pending")
	for _, id := range []string{"PENDING", "APPROVED", "REJECTED"} {
		if err := p.Hold(ctx, held(t, id, "req-"+id), minted); err != nil {
			t.Fatalf("holding %s: %v", id, err)
		}
	}
	a := openApprover(t, dir)
	for id, answer := range map[string]controlv1.ApprovalState{
		"APPROVED": controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
		"REJECTED": controlv1.ApprovalState_APPROVAL_STATE_REJECTED,
	} {
		if _, err := a.Answer(ctx, id, answer, "approver-1", "", minted.Add(time.Minute)); err != nil {
			t.Fatalf("answering %s: %v", id, err)
		}
	}
	found, err := p.Find(ctx, binding, minted.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	got := map[string]controlv1.ApprovalState{}
	for _, rec := range found {
		got[rec.ApprovalID] = rec.Approval.GetState()
	}
	want := map[string]controlv1.ApprovalState{
		"PENDING":  controlv1.ApprovalState_APPROVAL_STATE_PENDING,
		"APPROVED": controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
		"REJECTED": controlv1.ApprovalState_APPROVAL_STATE_REJECTED,
	}
	if !maps.Equal(got, want) {
		t.Fatalf("Find returned %v, want %v", got, want)
	}
}
