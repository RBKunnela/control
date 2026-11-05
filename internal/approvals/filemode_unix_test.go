//go:build unix

package approvals_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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

// TestARecordOthersMayWriteIsNotRead: a held record a group or the world may
// write carries whatever answer that account put in it, so Find refuses it.
// The same rewrite of a record only its owner may write is the owner's own
// answer, and is read.
func TestARecordOthersMayWriteIsNotRead(t *testing.T) {
	forged := forgedGrant(t)
	for _, c := range []struct {
		mode fs.FileMode
		read bool
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

			found, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute))
			if !c.read {
				if !errors.Is(err, approvals.ErrForeignFile) || found != nil {
					t.Errorf("Find over a record at %04o = %v, %v; want ErrForeignFile", c.mode, found, err)
				}
				return
			}
			if err != nil || len(found) != 1 || found[0].Approval.GetApproverId() != "approver-1" {
				t.Errorf("Find over the owner's own record = %v, %v; want its answer", found, err)
			}
		})
	}
}

// TestARecordAnotherAccountOwnsIsNotRead: the directory stays the plane's, so
// only the record's own owner refuses it. The same record is read once this
// account is the one that owns it again.
func TestARecordAnotherAccountOwnsIsNotRead(t *testing.T) {
	p, dir := openPlane(t)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	answerAt(t, dir, minted.Add(time.Minute))
	at := minted.Add(2 * time.Minute)
	for _, uid := range []int{os.Geteuid() + 1, -1} {
		restore := approvals.SetEffectiveUID(func() int { return uid })
		found, err := p.Find(t.Context(), h.Binding, at)
		restore()
		if !errors.Is(err, approvals.ErrForeignFile) || found != nil {
			t.Errorf("Find of a record uid %d does not own = %v, %v; want ErrForeignFile", uid, found, err)
		}
	}
	if found, err := p.Find(t.Context(), h.Binding, at); err != nil || len(found) != 1 || found[0].Approval.GetApproverId() != "approver-1" {
		t.Errorf("Find as the owner = %v, %v; want its answer", found, err)
	}
}
