//go:build unix

package inbox_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/approvals/inbox"
	"github.com/guardana/control/internal/policy"
)

func inboxDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "inbox")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

// answerFile is a file an operator would file: the envelope of an answer to
// approvalID. The inbox verifies no signature, so the bytes are a stand-in.
func answerFile(t *testing.T, approvalID string) []byte {
	t.Helper()
	a := sampleAnswer()
	a.ApprovalID = approvalID
	body, err := approvals.MarshalAnswer(a)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := inbox.MarshalAnswerFile(policy.StatementEnvelope{
		PayloadType: "application/vnd.agent-approval-answer+json", Payload: body,
		Signatures: []policy.StatementSignature{{KeyID: "key-1", Signature: bytes.Repeat([]byte{1}, 64)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func put(t *testing.T, dir, name string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func openInbox(t *testing.T, dir string) *inbox.Inbox {
	t.Helper()
	in, err := inbox.OpenInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	return in
}

// TestAnInboxOthersMayWriteIsSticky: a directory a group or the world may
// write is taken only sticky, so no writer removes another's answer.
func TestAnInboxOthersMayWriteIsSticky(t *testing.T) {
	for mode, taken := range map[os.FileMode]bool{
		0o750: true, 0o770: false, 0o770 | os.ModeSticky: true, 0o757: false, 0o777 | os.ModeSticky: true,
	} {
		_, err := inbox.OpenInbox(inboxDir(t, mode))
		if (err == nil) != taken || (!taken && !errors.Is(err, inbox.ErrInboxPermissions)) {
			t.Errorf("mode %04o: OpenInbox = %v, taken %v", mode, err, taken)
		}
	}
}

// TestAFileOfAnotherAnswerIsLeftOutAlone: a name this package does not
// write, a valid answer under such a name among them, and a file whose body
// names another approval are counted and left out, and the answer beside them
// is read with the batch whole.
func TestAFileOfAnotherAnswerIsLeftOutAlone(t *testing.T) {
	dir := inboxDir(t, 0o750)
	put(t, dir, "APPROVAL1.alice.answer", answerFile(t, "APPROVAL1"))
	put(t, dir, "APPROVAL1.other.answer", answerFile(t, "APPROVAL2"))
	put(t, dir, "APPROVAL2.alice.answer", answerFile(t, "APPROVAL2"))
	put(t, dir, "notes.txt", []byte("x"))
	put(t, dir, "APPROVAL1.a.b.answer", answerFile(t, "APPROVAL1"))
	in := openInbox(t, dir)
	batch, err := in.Read(context.Background(), "APPROVAL1")
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Envelopes) != 1 || batch.Truncated || batch.Unjudged {
		t.Fatalf("read %d envelope(s), truncated %v, unjudged %v; want alice's alone, whole", len(batch.Envelopes), batch.Truncated, batch.Unjudged)
	}
	got := in.Counts()
	if got[inbox.InboxForeignName] != 2 || got[inbox.InboxOtherApproval] != 1 {
		t.Errorf("counts %v; want two foreign names and one answer of another approval", got)
	}
}

// unjudgedPlant puts at name in dir a file named for the approval that the
// inbox cannot read as an answer, and is the cause it counts.
type unjudgedPlant struct {
	plant func(t *testing.T, dir, name string)
	cause string
}

func unjudgedPlants() map[string]unjudgedPlant {
	return map[string]unjudgedPlant{
		"a link": {func(t *testing.T, dir, name string) {
			if err := os.Symlink(filepath.Join(dir, "APPROVAL1.alice.answer"), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}, inbox.InboxNotRegular},
		"a pipe": {func(t *testing.T, dir, name string) {
			if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
				t.Fatal(err)
			}
		}, inbox.InboxNotRegular},
		"junk at the bound": {func(t *testing.T, dir, name string) {
			put(t, dir, name, bytes.Repeat([]byte("x"), inbox.MaxAnswerFileBytes))
		}, inbox.InboxMalformed},
		"one byte over the bound": {func(t *testing.T, dir, name string) {
			put(t, dir, name, bytes.Repeat([]byte("x"), inbox.MaxAnswerFileBytes+1))
		}, inbox.InboxTooLarge},
		"a file the plane may not read": {func(t *testing.T, dir, name string) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a file of mode 0000")
			}
			put(t, dir, name, answerFile(t, "APPROVAL1"))
			if err := os.Chmod(filepath.Join(dir, name), 0); err != nil {
				t.Fatal(err)
			}
		}, inbox.InboxUnreadable},
	}
}

// TestAnAnswerFileTheInboxCannotReadUnjudgesTheBatch: a link, a pipe, a file
// of junk at the bound, one over it, and one the plane may not read, each
// named for the approval, may be the rejection that wins, so the batch is
// unjudged and counted under its cause; alone, alice's answer is judged.
func TestAnAnswerFileTheInboxCannotReadUnjudgesTheBatch(t *testing.T) {
	for name, c := range unjudgedPlants() {
		t.Run(name, func(t *testing.T) {
			dir := inboxDir(t, 0o750)
			put(t, dir, "APPROVAL1.alice.answer", answerFile(t, "APPROVAL1"))
			in := openInbox(t, dir)
			if batch, err := in.Read(context.Background(), "APPROVAL1"); err != nil || batch.Unjudged || len(batch.Envelopes) != 1 {
				t.Fatalf("alone: %d envelope(s), unjudged %v, %v", len(batch.Envelopes), batch.Unjudged, err)
			}
			c.plant(t, dir, "APPROVAL1.planted.answer")
			batch, err := in.Read(context.Background(), "APPROVAL1")
			if err != nil || !batch.Unjudged {
				t.Fatalf("with %s: unjudged %v, %v", name, batch.Unjudged, err)
			}
			if in.Counts()[c.cause] != 1 {
				t.Errorf("counts %v; want one %s", in.Counts(), c.cause)
			}
		})
	}
}

// TestTheInboxBoundsTruncateTheBatch: one answer past the bound on one
// approval's answers truncates its batch; at the bound it does not.
func TestTheInboxBoundsTruncateTheBatch(t *testing.T) {
	for n, truncated := range map[int]bool{inbox.MaxAnswersPerApproval: false, inbox.MaxAnswersPerApproval + 1: true} {
		dir := inboxDir(t, 0o750)
		for i := range n {
			put(t, dir, fmt.Sprintf("APPROVAL1.op%02d.answer", i), answerFile(t, "APPROVAL1"))
		}
		batch, err := openInbox(t, dir).Read(context.Background(), "APPROVAL1")
		if err != nil {
			t.Fatal(err)
		}
		if batch.Truncated != truncated || len(batch.Envelopes) != min(n, inbox.MaxAnswersPerApproval) {
			t.Errorf("%d answers: truncated %v with %d envelope(s)", n, batch.Truncated, len(batch.Envelopes))
		}
	}
	for n, truncated := range map[int]bool{inbox.MaxInboxEntries: false, inbox.MaxInboxEntries + 1: true} {
		dir := inboxDir(t, 0o750)
		for i := range n {
			put(t, dir, fmt.Sprintf("APPROVAL2.op%04d.answer", i), nil)
		}
		batch, err := openInbox(t, dir).Read(context.Background(), "APPROVAL1")
		if err != nil {
			t.Fatal(err)
		}
		if batch.Truncated != truncated {
			t.Errorf("%d names: truncated %v", n, batch.Truncated)
		}
	}
}

// TestAnInboxThatChangedIsNotRead: an inbox made writable by others since it
// opened refuses the read whole.
func TestAnInboxThatChangedIsNotRead(t *testing.T) {
	dir := inboxDir(t, 0o750)
	in := openInbox(t, dir)
	if err := os.Chmod(dir, 0o770); err != nil { //nolint:gosec // G302: the mode under test is one the inbox refuses
		t.Fatal(err)
	}
	if _, err := in.Read(context.Background(), "APPROVAL1"); !errors.Is(err, inbox.ErrInboxPermissions) {
		t.Fatalf("Read = %v", err)
	}
	if in.Usable() {
		t.Error("an inbox others may write reads as usable")
	}
}

func TestAnAnswerFileIsNamedByItsApproval(t *testing.T) {
	if name, err := inbox.AnswerFileName("APPROVAL1", "alice"); err != nil || name != "APPROVAL1.alice.answer" {
		t.Fatalf("AnswerFileName = %q, %v", name, err)
	}
	for _, c := range [][2]string{{"../x", "alice"}, {"APPROVAL1", "a.b"}, {"APPROVAL1", ""}, {"APPROVAL1", string(bytes.Repeat([]byte("l"), inbox.MaxAnswerLabelBytes+1))}} {
		if _, err := inbox.AnswerFileName(c[0], c[1]); !errors.Is(err, approvals.ErrRecordName) {
			t.Errorf("AnswerFileName(%q, %q) = %v", c[0], c[1], err)
		}
	}
	if _, err := inbox.AnswerFileName("APPROVAL1", string(bytes.Repeat([]byte("l"), inbox.MaxAnswerLabelBytes))); err != nil {
		t.Errorf("a label at the bound was refused: %v", err)
	}
}

// TestThePruneRemovesOnlyStaleAnswersOfNoLiveHold: an answer of an approval
// no longer held, older than the lifetime, is removed; one a minute younger,
// one of a live hold and a foreign name are kept; an unlink the directory
// refuses is counted and stops nothing.
func TestThePruneRemovesOnlyStaleAnswersOfNoLiveHold(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	ttl := 15 * time.Minute
	dir := inboxDir(t, 0o750)
	for name, age := range map[string]time.Duration{
		"GONE1.alice.answer": ttl, "GONE2.alice.answer": ttl - time.Minute,
		"LIVE1.alice.answer": time.Hour, "notes.txt": time.Hour,
	} {
		put(t, dir, name, answerFile(t, "GONE1"))
		if err := os.Chtimes(filepath.Join(dir, name), now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	in := openInbox(t, dir)
	live := func(id string) bool { return id == "LIVE1" }
	got, err := in.Prune(context.Background(), now, ttl, live)
	if err != nil || got != (inbox.Pruned{Removed: 1}) {
		t.Fatalf("Prune = %+v, %v; want GONE1's answer removed alone", got, err)
	}
	if left, err := os.ReadDir(dir); err != nil || len(left) != 3 {
		t.Errorf("left %d name(s), %v", len(left), err)
	}
	if n, more, err := in.Entries(); n != 3 || more || err != nil {
		t.Errorf("Entries = %d, %v, %v", n, more, err)
	}
}

// TestAnUnlinkThePruneMayNotMakeIsCountedAndStopsNothing: in a directory the
// plane may not write, a stale answer is counted refused and left.
func TestAnUnlinkThePruneMayNotMakeIsCountedAndStopsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes a file of a directory it may not write")
	}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	dir := inboxDir(t, 0o750)
	put(t, dir, "GONE1.alice.answer", answerFile(t, "GONE1"))
	if err := os.Chtimes(filepath.Join(dir, "GONE1.alice.answer"), now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	in := openInbox(t, dir)
	if err := os.Chmod(dir, 0o550); err != nil { //nolint:gosec // G302: a directory the plane may not write is the case
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: gives the temp dir back to its cleanup
	got, err := in.Prune(context.Background(), now, 15*time.Minute, func(string) bool { return false })
	if err != nil || got != (inbox.Pruned{Refused: 1}) || in.Counts()[inbox.InboxUnremoved] != 1 {
		t.Errorf("a refused unlink: %+v, %v, counts %v", got, err, in.Counts())
	}
}
