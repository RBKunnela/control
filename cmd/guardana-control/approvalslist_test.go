package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
)

// TestListShowsWhatIsWaitingAndWhatBecameOfTheRest walks one directory holding
// a record in each state an approver can meet, and reads the fields back off
// the listing.
func TestListShowsWhatIsWaitingAndWhatBecameOfTheRest(t *testing.T) {
	dir, _ := everyState(t)

	code, stdout, stderr := invoke(t, "approvals", "list", dir)
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d with %q, want 0 and nothing on stderr", code, stderr)
	}
	head, _, _ := strings.Cut(stdout, "\n\n")
	for _, want := range []string{"4 records in " + dir, "a plane holds this directory", "not bound to the", "whether a retry spent an approved record"} {
		if !strings.Contains(head, want) {
			t.Errorf("the listing's head does not say %q:\n%s", want, head)
		}
	}
	for id, state := range map[string]string{
		waitingID:  "APPROVAL_STATE_PENDING",
		answeredID: "APPROVAL_STATE_APPROVED",
		rejectedID: "APPROVAL_STATE_REJECTED",
		staleID:    "APPROVAL_STATE_PENDING",
	} {
		assertEntry(t, stdout, id, state)
	}
	if got := fieldOf(t, blockOf(t, stdout, answeredID), "answered by"); got != "duty-officer" {
		t.Errorf("answered by %q, want %q", got, "duty-officer")
	}
}

// assertEntry holds one entry of a listing to the state the record reached
// and to the request it was held for, and holds it to printing no resolution,
// which the directory no longer keeps.
func assertEntry(t *testing.T, stdout, approvalID, state string) {
	t.Helper()
	block := blockOf(t, stdout, approvalID)
	if got := fieldOf(t, block, "state"); got != state {
		t.Errorf("%s: state %q, want %q", approvalID, got, state)
	}
	if strings.Contains(block, "resolution") {
		t.Errorf("%s: the entry prints a resolution:\n%s", approvalID, block)
	}
	if got := fieldOf(t, block, "request"); got != requestOf(approvalID) {
		t.Errorf("%s: request %q, want %q", approvalID, got, requestOf(approvalID))
	}
}

// TestListPrintsTheDigestsAndTheProjectionBesideThem: the two digests come
// from the record, the readable fields from the projection, and the entry
// names both without mixing one into the other's line.
func TestListPrintsTheDigestsAndTheProjectionBesideThem(t *testing.T) {
	dir, plane := newStore(t)
	expires := clockNow().Add(15 * time.Minute)
	hold(t, plane, "WAITING", expires)

	code, stdout, _ := invoke(t, "approvals", "list", dir)
	if code != exitOK {
		t.Fatalf("exit %d, want 0", code)
	}
	block := blockOf(t, stdout, "WAITING")
	for label, want := range map[string]string{
		"action digest": string(digestOf(t, "WAITING")),
		"bundle digest": string(fixtureBundle),
		"principal":     "user-1",
		"agent":         "agent-1",
		"action":        "refund",
		"upstream":      "payments",
		"resource":      "payment pay-9",
		"effect class":  "EFFECT_CLASS_TRANSACT",
		"rule ids":      "rule-a, rule-b",
	} {
		if got := fieldOf(t, block, label); got != want {
			t.Errorf("%s = %q, want %q", label, got, want)
		}
	}
	// The expiry is the plane's, to the second, and it is printed in UTC: a
	// listing read in another zone would tell an approver the wrong deadline.
	if got := fieldOf(t, block, "expires"); got != expires.Format(time.RFC3339) {
		t.Errorf("expires = %q, want %q", got, expires.Format(time.RFC3339))
	}
}

// TestListPrintsNoFreeText: the envelope's two free-text fields and an
// approver's own reason reach a record or a digest, and none of the three
// reaches a listing. Invariant 9 and ADR-0004 are not widened by a command
// that prints more than the projection holds.
func TestListPrintsNoFreeText(t *testing.T) {
	dir, plane := newStore(t)
	hold(t, plane, "ANSWERED", clockNow().Add(15*time.Minute))
	code, _, stderr := invoke(t, "approvals", "approve", "--approver-id", "duty-officer", "--reason", approverReason, dir, "ANSWERED")
	if code != exitOK {
		t.Fatalf("approve: exit %d with %q, want 0", code, stderr)
	}
	// The reason is on disk, so a listing that printed it would have
	// something to print; the envelope's free text is nowhere, and the
	// listing may not reconstruct it either.
	if !strings.Contains(dirText(t, dir), approverReason) {
		t.Fatalf("the approver's reason never reached a record, so this test examined nothing")
	}
	code, stdout, _ := invoke(t, "approvals", "list", dir)
	if code != exitOK {
		t.Fatalf("list: exit %d, want 0", code)
	}
	if !strings.Contains(stdout, "duty-officer") {
		t.Fatalf("the listing printed no projection at all:\n%s", stdout)
	}
	for name, text := range map[string]string{
		"the arguments' redacted preview": previewText,
		"a delegation's reason":           delegationText,
		"the approver's reason":           approverReason,
	} {
		if strings.Contains(stdout, text) {
			t.Errorf("the listing prints %s", name)
		}
	}
}

// TestListOverAnEmptyStore: a store with no record is a listing of none, not
// a refusal, and it still says what an approver has to know.
func TestListOverAnEmptyStore(t *testing.T) {
	dir, _ := newStore(t)
	code, stdout, stderr := invoke(t, "approvals", "list", dir)
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d with %q, want 0 and nothing on stderr", code, stderr)
	}
	if !strings.HasPrefix(stdout, "0 records in "+dir+"\n") {
		t.Errorf("stdout = %q, want a listing of no records", stdout)
	}
	if strings.Contains(stdout, "\napproval ") {
		t.Errorf("an empty store listed an entry:\n%s", stdout)
	}
}

// TestListRefusesADirectoryThatIsNotAStore: a directory nothing wrote is
// refused, not read as an empty store. An approver told "0 records" about the
// wrong path would conclude that nothing is waiting.
func TestListRefusesADirectoryThatIsNotAStore(t *testing.T) {
	for name, dir := range map[string]string{
		"an empty directory": t.TempDir(),
		"no directory":       t.TempDir() + "/none",
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := invoke(t, "approvals", "list", dir)
			if code != exitFail {
				t.Errorf("exit %d, want %d", code, exitFail)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
			if line := oneStderrLine(t, stderr); !strings.HasPrefix(line, brand.CLI+": "+listName+": ") {
				t.Errorf("stderr = %q, want a refusal under the command's own name", line)
			}
		})
	}
}

// TestListSaysWhenNoPlaneHoldsTheDirectory: an approver reading a listing has
// to know whether anything would consume an answer.
func TestListSaysWhenNoPlaneHoldsTheDirectory(t *testing.T) {
	dir, plane := newStore(t)
	hold(t, plane, "WAITING", clockNow().Add(15*time.Minute))
	if err := plane.Close(); err != nil {
		t.Fatalf("closing the plane: %v", err)
	}
	code, stdout, _ := invoke(t, "approvals", "list", dir)
	if code != exitOK {
		t.Fatalf("exit %d, want 0", code)
	}
	if !strings.Contains(stdout, "no plane holds this directory") {
		t.Errorf("the listing does not say the directory is unheld:\n%s", stdout)
	}
}

// TestListReportsAnIncompleteListingAsAFailure: a record the store cannot
// read makes the listing neither the whole directory nor an empty one, and a
// pass would read as "these are all the approvals there are".
func TestListReportsAnIncompleteListingAsAFailure(t *testing.T) {
	dir, plane := newStore(t)
	hold(t, plane, "WAITING", clockNow().Add(15*time.Minute))
	var name string
	for n := range files(t, dir) {
		if strings.HasSuffix(n, ".rec") {
			name = n
		}
	}
	if name == "" {
		t.Fatal("the fixture wrote no record")
	}
	writeOver(t, dir, name, "not a record")
	code, stdout, stderr := invoke(t, "approvals", "list", dir)
	if code != exitFail {
		t.Errorf("exit %d, want %d", code, exitFail)
	}
	if !strings.Contains(stderr, "incomplete") || !strings.Contains(stderr, name) {
		t.Errorf("stderr = %q, want the record it could not read and the word incomplete", stderr)
	}
	if strings.Contains(stdout, "\napproval ") {
		t.Errorf("an unreadable record was listed as an entry:\n%s", stdout)
	}
}

// TestListSaysWhenTheReadableFieldsAreNotThere: the projection is not truth
// and a record without a readable one still answers, so the entry says the
// fields are missing rather than printing an empty column a reader would take
// for an empty value.
func TestListSaysWhenTheReadableFieldsAreNotThere(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"no projection":                {"", "the projection is missing"},
		"another approval's":           {`{"approval_id":"OTHER"}`, "describes another approval"},
		"a projection that is not one": {"{{{", "the projection is missing"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, plane := newStore(t)
			hold(t, plane, "WAITING", clockNow().Add(15*time.Minute))
			view := "WAITING.view.json"
			if tc.body == "" {
				if err := os.Remove(filepath.Join(dir, view)); err != nil {
					t.Fatalf("removing the projection: %v", err)
				}
			} else {
				writeOver(t, dir, view, tc.body)
			}
			code, stdout, stderr := invoke(t, "approvals", "list", dir)
			if code != exitOK {
				t.Fatalf("exit %d with %q, want 0: a projection is not truth", code, stderr)
			}
			if got := fieldOf(t, blockOf(t, stdout, "WAITING"), "readable"); !strings.Contains(got, tc.want) {
				t.Errorf("readable = %q, want one saying %q", got, tc.want)
			}
			if got := fieldOf(t, blockOf(t, stdout, "WAITING"), "action digest"); got != string(digestOf(t, "WAITING")) {
				t.Errorf("action digest = %q, want the record's own", got)
			}
		})
	}
}
