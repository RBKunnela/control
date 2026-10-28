package holdjournal_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/holdjournal"
)

// TestAFlipBeforeTheRecordIsRefused: the write order starts at Record, and a
// flip on a journal that holds no entry for the request says so rather than
// filing one.
func TestAFlipBeforeTheRecordIsRefused(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t))
	if err := j.Mark(ctx, "req-1", holdjournal.StateClosing); !errors.Is(err, holdjournal.ErrNoEntry) {
		t.Fatalf("a flip before the entry was recorded: %v, want ErrNoEntry", err)
	}
	if names := entryFiles(t, j.Dir()); len(names) != 0 {
		t.Fatalf("a refused flip left %v behind", names)
	}
}

// TestOneRequestTakesOneEntry: a second hold under one request id is refused,
// so no two trails ever stand behind one entry.
func TestOneRequestTakesOneEntry(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t))
	record(t, j, "req-1")
	if err := j.Record(ctx, heldEntry("req-1")); !errors.Is(err, holdjournal.ErrRecorded) {
		t.Fatalf("a second entry under one request: %v, want ErrRecorded", err)
	}
	listing, err := j.List(ctx, 8)
	if err != nil {
		t.Fatalf("listing the journal: %v", err)
	}
	if len(listing.Held) != 1 || listing.Held[0].IDs.RequestID != "req-1" || !listing.Complete {
		t.Fatalf("after the record the listing is %+v", listing)
	}
}

// TestARecordThatFailsAfterTheLinkMayHaveFiledTheEntry: once the entry is
// linked, a directory that cannot be forced to disk is reported as an entry
// that may be filed, and the entry stands for the caller to flip and forget,
// counted against the bound until it does; a refusal before the link says
// nothing was filed.
func TestARecordThatFailsAfterTheLinkMayHaveFiledTheEntry(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t), holdjournal.WithMaxEntries(3))
	record(t, j, "req-1")
	if err := j.Record(ctx, heldEntry("req-1")); !errors.Is(err, holdjournal.ErrRecorded) || errors.Is(err, holdjournal.ErrMaybeRecorded) {
		t.Fatalf("a refusal at the link: %v, want ErrRecorded alone", err)
	}
	failed := errors.New("the directory cannot be forced to disk")
	restore := holdjournal.SetDirSync(func(*os.File) error { return failed })
	err := j.Record(ctx, heldEntry("req-2"))
	restore()
	if !errors.Is(err, holdjournal.ErrMaybeRecorded) || !errors.Is(err, failed) || errors.Is(err, holdjournal.ErrRecorded) {
		t.Fatalf("a directory sync that failed after the link: %v, want ErrMaybeRecorded with its cause", err)
	}
	if names := entryFiles(t, j.Dir()); len(names) != 2 {
		t.Fatalf("after the failed record the directory holds %v, want both entries", names)
	}
	record(t, j, "req-3")
	if err := j.Record(ctx, heldEntry("req-4")); !errors.Is(err, holdjournal.ErrTooManyEntries) {
		t.Fatalf("a fourth record under a bound of three, one of them maybe filed: %v, want ErrTooManyEntries", err)
	}
	mark(t, j, "req-2", holdjournal.StateClosing)
	if err := j.Forget(ctx, "req-2"); err != nil {
		t.Fatalf("forgetting the maybe-filed entry: %v", err)
	}
	record(t, j, "req-4")
}

// TestAnEntryLeavesHeldOnce: the flip an append is allowed after happens once,
// so a pass that comes later never reads the entry as a hold it may close.
func TestAnEntryLeavesHeldOnce(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t))
	record(t, j, "req-1")
	mark(t, j, "req-1", holdjournal.StateClosing)
	if err := j.Mark(ctx, "req-1", holdjournal.StateResuming); !errors.Is(err, holdjournal.ErrFlip) {
		t.Fatalf("a second flip out of held: %v, want ErrFlip", err)
	}
	listing, err := j.List(ctx, 8)
	if err != nil {
		t.Fatalf("listing the journal: %v", err)
	}
	if len(listing.Held) != 0 || listing.Interrupted != 1 || !listing.Complete {
		t.Fatalf("after the flip the listing is %+v", listing)
	}
}

// TestAForgottenEntryIsGoneForGood: the entry is dropped once its trail can
// take nothing more, and nothing brings it back.
func TestAForgottenEntryIsGoneForGood(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t))
	record(t, j, "req-1")
	mark(t, j, "req-1", holdjournal.StateClosing)
	if err := j.Forget(ctx, "req-1"); err != nil {
		t.Fatalf("forgetting the entry: %v", err)
	}
	if err := j.Mark(ctx, "req-1", holdjournal.StateClosing); !errors.Is(err, holdjournal.ErrNoEntry) {
		t.Fatalf("a flip after the entry was forgotten: %v, want ErrNoEntry", err)
	}
	listing, err := j.List(ctx, 8)
	if err != nil {
		t.Fatalf("listing the journal: %v", err)
	}
	if len(listing.Held) != 0 || listing.Interrupted != 0 || !listing.Complete {
		t.Fatalf("after the forget the listing is %+v", listing)
	}
	if names := entryFiles(t, j.Dir()); len(names) != 0 {
		t.Fatalf("the forgotten entry left %v behind", names)
	}
}

// TestForgettingARequestWithNoEntryIsNoError: the plane forgets every
// execution it closes, held or not, so a request with no entry costs an unlink
// at most and never a refusal.
func TestForgettingARequestWithNoEntryIsNoError(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t))
	for _, id := range []string{"never-held", "", "a request id that cannot name a file/../..", string([]byte{0x00, 0x01})} {
		if err := j.Forget(ctx, id); err != nil {
			t.Fatalf("forgetting %q: %v, want no error", id, err)
		}
	}
	record(t, j, "req-1")
	if err := j.Forget(ctx, "req-1"); err != nil {
		t.Fatalf("forgetting a held request: %v", err)
	}
	if names := entryFiles(t, j.Dir()); len(names) != 0 {
		t.Fatalf("the forgotten entry left %v behind", names)
	}
}

// TestForgettingARequestNeverHeldFreesNoRoom: the plane forgets every call it
// closes, held or not, so a forget that removed nothing must not count as one
// that did, or the bound would stop biting.
func TestForgettingARequestNeverHeldFreesNoRoom(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t), holdjournal.WithMaxEntries(1))
	record(t, j, "req-a")
	if err := j.Forget(ctx, "req-b"); err != nil {
		t.Fatalf("forgetting a request never held: %v", err)
	}
	if err := j.Record(ctx, heldEntry("req-c")); !errors.Is(err, holdjournal.ErrTooManyEntries) {
		t.Fatalf("a second hold under a bound of one after forgetting nothing: %v, want ErrTooManyEntries", err)
	}
	if err := j.Forget(ctx, "req-a"); err != nil {
		t.Fatalf("forgetting the held request: %v", err)
	}
	record(t, j, "req-c")
}

// TestAnEntryLeavesHeldOnlyForResumingOrClosing: every other state is refused,
// including the one it is already in and one no build knows.
func TestAnEntryLeavesHeldOnlyForResumingOrClosing(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t))
	record(t, j, "req-1")
	for _, state := range []holdjournal.State{holdjournal.StateUnknown, holdjournal.StateHeld, holdjournal.State(9)} {
		if err := j.Mark(ctx, "req-1", state); !errors.Is(err, holdjournal.ErrFlip) {
			t.Fatalf("a flip into %v: %v, want ErrFlip", state, err)
		}
	}
	listing, err := j.List(ctx, 8)
	if err != nil {
		t.Fatalf("listing the journal: %v", err)
	}
	if len(listing.Held) != 1 {
		t.Fatalf("a refused flip moved the entry: %+v", listing)
	}
}

// TestRecordRefusesWhatAClosingWouldNeed: each field a close is written from,
// removed one at a time from an entry the journal otherwise takes. The entry
// the table starts from is recorded at the end, so no case passes because the
// fixture itself was unrecordable.
func TestRecordRefusesWhatAClosingWouldNeed(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		damage func(*holdjournal.Entry)
		want   error
	}{
		"no schema version":           {func(e *holdjournal.Entry) { e.SchemaVersion = "" }, holdjournal.ErrSchemaVersion},
		"a schema major nobody reads": {func(e *holdjournal.Entry) { e.SchemaVersion = "2.0" }, holdjournal.ErrSchemaVersion},
		"no request id":               {func(e *holdjournal.Entry) { e.IDs.RequestID = "" }, holdjournal.ErrRequestName},
		"a request id over the bound": {
			func(e *holdjournal.Entry) {
				e.IDs.RequestID = string(make([]byte, holdjournal.MaxRequestIDBytes+1))
			},
			holdjournal.ErrRequestName,
		},
		"no position on the trail": {func(e *holdjournal.Entry) { e.LastEventID = "" }, holdjournal.ErrEntry},
		"no binding":               {func(e *holdjournal.Entry) { e.Binding = "" }, holdjournal.ErrEntry},
		"no approval":              {func(e *holdjournal.Entry) { e.Approval = nil }, holdjournal.ErrEntry},
		"no approval id":           {func(e *holdjournal.Entry) { e.Approval.ApprovalId = "" }, holdjournal.ErrEntry},
		"no expiry":                {func(e *holdjournal.Entry) { e.Expires = time.Time{} }, holdjournal.ErrEntry},
		"an approval naming another request": {
			func(e *holdjournal.Entry) { e.Approval.RequestId = "another" }, holdjournal.ErrEntry,
		},
		"an entry that is not held": {func(e *holdjournal.Entry) { e.State = holdjournal.StateResuming }, holdjournal.ErrEntry},
	}
	for _, v := range []string{"1.", "1.x", "1.0.0", "1.-3", "1.+3", "01.0"} {
		cases["the schema version "+v] = struct {
			damage func(*holdjournal.Entry)
			want   error
		}{func(e *holdjournal.Entry) { e.SchemaVersion = v }, holdjournal.ErrSchemaVersion}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			j := openJournal(t, newDir(t))
			entry := heldEntry("req-1")
			tc.damage(&entry)
			if err := j.Record(ctx, entry); !errors.Is(err, tc.want) {
				t.Fatalf("recording an entry with %s: %v, want %v", name, err, tc.want)
			}
			if names := entryFiles(t, j.Dir()); len(names) != 0 {
				t.Fatalf("a refused entry left %v behind", names)
			}
			if err := j.Record(ctx, heldEntry("req-1")); err != nil {
				t.Fatalf("the undamaged entry was refused too: %v", err)
			}
		})
	}
}

// mintedAt is the clock the reopened entry is written against.
func mintedAt() time.Time { return time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC) }

// writtenEntry is one complete entry, spelled out rather than built, so the
// tests that read it back assert against literals of their own.
func writtenEntry() holdjournal.Entry {
	return holdjournal.Entry{
		SchemaVersion: "1.0",
		State:         holdjournal.StateHeld,
		IDs: evidence.IDs{
			RequestID: "req-A", RunID: "run-B", ProjectID: "proj-C", TenantID: "tenant-D",
		},
		LastEventID: "evt-E",
		Binding:     approval.Binding("bind-F"),
		Approval: &controlv1.Approval{
			SchemaVersion:      "1.0",
			ApprovalId:         "appr-G",
			RequestId:          "req-A",
			ActionDigest:       "sha256:" + "abababababababababababababababababababababababababababababababab",
			PolicyBundleDigest: "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111",
			State:              controlv1.ApprovalState_APPROVAL_STATE_PENDING,
			ApproverId:         "approver-H",
			Reason:             "waiting on a person",
			RequestedAt:        timestamppb.New(mintedAt()),
			DecidedAt:          timestamppb.New(mintedAt().Add(time.Minute)),
			ExpiresAt:          timestamppb.New(mintedAt().Add(15 * time.Minute)),
		},
		Expires: mintedAt().Add(15 * time.Minute),
	}
}

// reopenedEntry files writtenEntry, closes the journal, opens the same
// directory again and hands back the one entry that pass read. What a decoder
// drops between the two is what these tests catch.
func reopenedEntry(t *testing.T) holdjournal.Entry {
	t.Helper()
	ctx := context.Background()
	dir := newDir(t)
	first := openJournal(t, dir)
	if err := first.Record(ctx, writtenEntry()); err != nil {
		t.Fatalf("recording the entry: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("closing the journal: %v", err)
	}
	listing, err := openJournal(t, dir).List(ctx, 8)
	if err != nil {
		t.Fatalf("listing the reopened journal: %v", err)
	}
	if len(listing.Held) != 1 || !listing.Complete {
		t.Fatalf("the reopened journal listed %+v", listing)
	}
	return listing.Held[0]
}

// TestAReopenedJournalReadsTheTrailBack: where the trail stands, which is what
// a close is linked to.
func TestAReopenedJournalReadsTheTrailBack(t *testing.T) {
	got := reopenedEntry(t)
	switch {
	case got.SchemaVersion != "1.0" || got.State != holdjournal.StateHeld:
		t.Fatalf("the entry came back as version %q in %v", got.SchemaVersion, got.State)
	case got.IDs != (evidence.IDs{RequestID: "req-A", RunID: "run-B", ProjectID: "proj-C", TenantID: "tenant-D"}):
		t.Fatalf("the ids came back as %+v", got.IDs)
	case got.LastEventID != "evt-E" || got.Binding != approval.Binding("bind-F"):
		t.Fatalf("the position came back as %q under %q", got.LastEventID, got.Binding)
	case !got.Expires.Equal(mintedAt().Add(15 * time.Minute)):
		t.Fatalf("the expiry came back as %v", got.Expires)
	}
}

// TestAReopenedJournalReadsTheApprovalsIdentityBack: what the store is asked
// about, and what an answer is compared against.
func TestAReopenedJournalReadsTheApprovalsIdentityBack(t *testing.T) {
	a := reopenedEntry(t).Approval
	switch {
	case a.GetSchemaVersion() != "1.0":
		t.Fatalf("the approval's schema version came back as %q", a.GetSchemaVersion())
	case a.GetApprovalId() != "appr-G" || a.GetRequestId() != "req-A":
		t.Fatalf("the approval came back as %q for %q", a.GetApprovalId(), a.GetRequestId())
	case a.GetActionDigest() != "sha256:abababababababababababababababababababababababababababababababab":
		t.Fatalf("the action digest came back as %q", a.GetActionDigest())
	case a.GetPolicyBundleDigest() != "sha256:1111111111111111111111111111111111111111111111111111111111111111":
		t.Fatalf("the bundle digest came back as %q", a.GetPolicyBundleDigest())
	}
}

// TestAReopenedJournalReadsTheApprovalsAnswerBack: the state and the name on
// it, which a closing event carries.
func TestAReopenedJournalReadsTheApprovalsAnswerBack(t *testing.T) {
	a := reopenedEntry(t).Approval
	switch {
	case a.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING:
		t.Fatalf("the approval's state came back as %v", a.GetState())
	case a.GetApproverId() != "approver-H":
		t.Fatalf("the approver came back as %q", a.GetApproverId())
	case a.GetReason() != "waiting on a person":
		t.Fatalf("the reason came back as %q", a.GetReason())
	}
}

// TestAReopenedJournalReadsTheApprovalsTimesBack: an expiry a decoder shifted
// would let a lost hold be closed as expired that was not, or the other way
// about.
func TestAReopenedJournalReadsTheApprovalsTimesBack(t *testing.T) {
	a := reopenedEntry(t).Approval
	switch {
	case !a.GetRequestedAt().AsTime().Equal(mintedAt()):
		t.Fatalf("requested at came back as %v", a.GetRequestedAt().AsTime())
	case !a.GetDecidedAt().AsTime().Equal(mintedAt().Add(time.Minute)):
		t.Fatalf("decided at came back as %v", a.GetDecidedAt().AsTime())
	case !a.GetExpiresAt().AsTime().Equal(mintedAt().Add(15 * time.Minute)):
		t.Fatalf("expires at came back as %v", a.GetExpiresAt().AsTime())
	}
}
