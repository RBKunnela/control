//go:build unix

package approvals_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
)

// forgedGrant is an approved answer to the fixture's hold, filed in a private
// directory of its own: bytes that carry the plane's binding, ids and window,
// as anyone who may write a record file could put them there.
func forgedGrant(t *testing.T) []byte {
	t.Helper()
	donor, dir := openPlane(t)
	if err := donor.Hold(t.Context(), held(t, firstApproval, "req-1"), minted); err != nil {
		t.Fatalf("holding in the donor directory: %v", err)
	}
	answerAt(t, dir, minted.Add(time.Minute))
	return readFile(t, dir, firstApproval+".1-answered.rec")
}

// overwriteInPlace replaces the bytes of dir/name through its existing inode,
// as an account with write access to the file and none to the directory can.
func overwriteInPlace(t *testing.T, dir, name string, body []byte) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_TRUNC, 0) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatalf("opening %s: %v", name, err)
	}
	_, err = f.Write(body)
	if err = errors.Join(err, f.Close()); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

// TestARecordOthersMayWriteIsNotSpent: a held record a group or the world may
// write carries whatever answer that account put in it, so Consume refuses it
// and spends nothing. The same rewrite of a record only its owner may write is
// the owner's own answer, and is spent.
func TestARecordOthersMayWriteIsNotSpent(t *testing.T) {
	forged := forgedGrant(t)
	for _, c := range []struct {
		mode  fs.FileMode
		spent bool
	}{{0o666, false}, {0o620, false}, {0o602, false}, {0o600, true}} {
		t.Run(c.mode.String(), func(t *testing.T) {
			p, dir := openPlane(t)
			h := held(t, firstApproval, "req-1")
			if err := p.Hold(t.Context(), h, minted); err != nil {
				t.Fatalf("holding: %v", err)
			}
			heldName := firstApproval + ".0-held.rec"
			if err := os.Chmod(filepath.Join(dir, heldName), c.mode); err != nil {
				t.Fatal(err)
			}
			overwriteInPlace(t, dir, heldName, forged)

			got, err := p.Consume(t.Context(), h.Binding, "req-1", firstApproval, minted.Add(2*time.Minute))
			consumed := slices.Contains(recordNames(t, dir), firstApproval+".3-consumed.rec")
			if !c.spent {
				if !errors.Is(err, approvals.ErrForeignFile) || got != nil {
					t.Errorf("Consume over a record at %04o = %v, %v; want ErrForeignFile", c.mode, got, err)
				}
				if consumed {
					t.Errorf("a record at %04o was spent: %v", c.mode, recordNames(t, dir))
				}
				return
			}
			if err != nil || got.GetApproverId() != "approver-1" || !consumed {
				t.Errorf("Consume over the owner's own record = %v, %v, consumed %v; want it spent", got, err, consumed)
			}
		})
	}
}

// TestARecordAnotherAccountOwnsIsNotSpent: the directory stays the plane's,
// so only the record's own owner refuses it. The same record is spent once
// this account is the one that owns it again.
func TestARecordAnotherAccountOwnsIsNotSpent(t *testing.T) {
	p, dir := openPlane(t)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	answerAt(t, dir, minted.Add(time.Minute))
	at := minted.Add(2 * time.Minute)
	for _, uid := range []int{os.Geteuid() + 1, -1} {
		restore := approvals.SetEffectiveUID(func() int { return uid })
		got, err := p.Consume(t.Context(), h.Binding, "req-1", firstApproval, at)
		restore()
		if !errors.Is(err, approvals.ErrForeignFile) || got != nil {
			t.Errorf("Consume of a record uid %d does not own = %v, %v; want ErrForeignFile", uid, got, err)
		}
		if slices.Contains(recordNames(t, dir), firstApproval+".3-consumed.rec") {
			t.Fatalf("a record uid %d does not own was spent", uid)
		}
	}
	if got, err := p.Consume(t.Context(), h.Binding, "req-1", firstApproval, at); err != nil || got.GetApproverId() != "approver-1" {
		t.Errorf("Consume as the owner = %v, %v; want it spent", got, err)
	}
}
