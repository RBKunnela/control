package approvals_test

import (
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

// reservedClaims spell the reserved prefix as it is, in capitals, with a
// Cyrillic a, with a dot above a full stop, in Lisu letters beside Latin, with
// a Tibetan colon and after a blank braille pattern. Every one is an
// identifier, so only the reservation refuses it.
var reservedClaims = []string{
	"authn:okta:alice", "AUTHN:okta:alice", "\u0430uthn:okta:alice", "authn.\u0307okta:alice",
	"\ua4ee\ua4f4\ua4d4\ua4e7\ua4e0:okta:alice", "authn\u0f7fokta:alice", "\u2800authn:okta:alice",
}

// dirContents is every file under dir with its bytes, so a refusal can be
// held to having written nothing at all, not only to the names it left.
func dirContents(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary directory
		out[path] = string(raw)
		return err
	})
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	return out
}

// TestAnAnswerMayNotClaimTheReservedPrefix: an approver who names themselves
// with the prefix, approving or rejecting, is refused with both the store's
// and the core's sentinel, and the directory is byte for byte what it was.
func TestAnAnswerMayNotClaimTheReservedPrefix(t *testing.T) {
	_, dir, _ := heldOne(t)
	a := openApprover(t, dir)
	before := dirContents(t, dir)
	for _, id := range reservedClaims {
		for _, state := range []controlv1.ApprovalState{
			controlv1.ApprovalState_APPROVAL_STATE_APPROVED, controlv1.ApprovalState_APPROVAL_STATE_REJECTED,
		} {
			_, err := a.Answer(t.Context(), firstApproval, state, id, "", minted.Add(time.Minute))
			if !errors.Is(err, approvals.ErrApproverID) || !errors.Is(err, approval.ErrReservedApproverID) {
				t.Errorf("%s by %+q = %v, want ErrApproverID and ErrReservedApproverID", state, id, err)
			}
		}
	}
	if after := dirContents(t, dir); !maps.Equal(before, after) {
		t.Fatalf("a refused answer changed the directory: %v, was %v", keysOf(after), keysOf(before))
	}
	if err := approvals.CheckApproverID("authn:okta:alice"); !errors.Is(err, approval.ErrReservedApproverID) {
		t.Errorf("CheckApproverID = %v, want ErrReservedApproverID", err)
	}
}

// TestARecordWrittenWithTheReservedPrefixResumesNothing: a writer of the
// directory files the answer by hand, past Answer's check, with an approver
// id in the reserved spelling. The plane neither finds it nor spends it, and
// nothing on disk changes. The same rewrite with a plain claim is consumed,
// so the refusal comes from the prefix and not from the rewrite.
func TestARecordWrittenWithTheReservedPrefixResumesNothing(t *testing.T) {
	for _, id := range append([]string{"duty-officer"}, reservedClaims...) {
		t.Run(id, func(t *testing.T) {
			p, dir, h := heldOne(t)
			answerAt(t, dir, minted.Add(time.Minute))
			writeFile(t, dir, answeredName, withApprovalField(t, readFile(t, dir, answeredName), "approverId", `"`+id+`"`))
			before := dirContents(t, dir)
			now := minted.Add(2 * time.Minute)

			_, findErr := p.Find(t.Context(), h.Binding, now)
			got, consumeErr := p.Consume(t.Context(), h.Binding, "req-1", firstApproval, now)
			if id == "duty-officer" {
				if findErr != nil || consumeErr != nil || got.GetApproverId() != id {
					t.Fatalf("the control: find %v, consume %v, approver %q", findErr, consumeErr, got.GetApproverId())
				}
				assertNames(t, dir, consumedName)
				return
			}
			for name, err := range map[string]error{"find": findErr, "consume": consumeErr} {
				if !errors.Is(err, approvals.ErrApproverID) || !errors.Is(err, approval.ErrReservedApproverID) {
					t.Errorf("%s = %v, want ErrApproverID and ErrReservedApproverID", name, err)
				}
			}
			if got != nil {
				t.Errorf("a refused consume handed back %v", got)
			}
			if after := dirContents(t, dir); !maps.Equal(before, after) {
				t.Fatalf("a refused consume changed the directory: %v, was %v", keysOf(after), keysOf(before))
			}
		})
	}
}

func keysOf(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, filepath.Base(k))
	}
	slices.Sort(keys)
	return keys
}
