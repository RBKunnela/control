//go:build unix

package approvals_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/guardana/control/internal/approvals"
)

// TestAReaderOpensAnotherAccountsDirectory: a directory another account
// owns is refused to an approver and read by a reader, which says it does
// not run as the directory's owner; a group-writable one is refused to both.
func TestAReaderOpensAnotherAccountsDirectory(t *testing.T) {
	p, dir := openPlane(t, approvals.WithAuthority(approvals.HeldUnderSigned))
	if err := p.Hold(t.Context(), held(t, "APPROVAL1", "req-1"), minted); err != nil {
		t.Fatal(err)
	}
	if !openReader(t, dir).PlaneAccount() {
		t.Error("a reader running as the directory's owner says it does not")
	}
	restore := approvals.SetEffectiveUID(func() int { return os.Geteuid() + 1 })
	defer restore()
	if _, err := approvals.OpenApprover(dir); !errors.Is(err, approvals.ErrOwner) {
		t.Errorf("OpenApprover of another account's directory = %v, want ErrOwner", err)
	}
	r := openReader(t, dir)
	if r.PlaneAccount() {
		t.Error("a reader under another account says it is the directory's owner")
	}
	rec, err := r.Held(t.Context(), "APPROVAL1")
	if err != nil || rec.ApprovalID != "APPROVAL1" || rec.Tenant != "tenant-1" || rec.Project != "proj-1" {
		t.Fatalf("Held = %+v, %v", rec, err)
	}
	if _, err := r.Held(t.Context(), "NOSUCH"); !errors.Is(err, approvals.ErrNoApproval) {
		t.Errorf("Held of an unknown id = %v, want ErrNoApproval", err)
	}
	if err := os.Chmod(dir, 0o770); err != nil { //nolint:gosec // G302: the mode under test is one the store refuses
		t.Fatal(err)
	}
	if _, err := approvals.OpenReader(dir); !errors.Is(err, approvals.ErrPermissions) {
		t.Errorf("OpenReader of a group-writable directory = %v, want ErrPermissions", err)
	}
}

// TestASignedStoreIsReadableByItsGroup: under the signed authority the
// marker, a held record and its projection are written 0640 whatever the
// umask, so the directory's group can read them and nobody but the owner
// writes them; under the directory authority they stay 0600. A reader reads a
// held record of a 0750 directory. No test here runs as a second account.
func TestASignedStoreIsReadableByItsGroup(t *testing.T) {
	for _, c := range []struct {
		name string
		opts []approvals.Option
		mode os.FileMode
	}{
		{"signed", []approvals.Option{approvals.WithAuthority(approvals.HeldUnderSigned)}, 0o640},
		{"directory", nil, 0o600},
	} {
		t.Run(c.name, func(t *testing.T) {
			old := syscall.Umask(0o077)
			p, dir := openPlane(t, c.opts...)
			err := p.Hold(t.Context(), held(t, "APPROVAL1", "req-1"), minted)
			syscall.Umask(old)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"store.meta", "APPROVAL1.0-held.rec", "APPROVAL1.view.json"} {
				info, err := os.Stat(filepath.Join(dir, name))
				if err != nil || info.Mode().Perm() != c.mode {
					t.Errorf("%s: %v %v, want mode %04o", name, info, err, c.mode)
				}
			}
			if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: the documented group-readable directory
				t.Fatal(err)
			}
			if _, err := openReader(t, dir).Held(t.Context(), "APPROVAL1"); err != nil {
				t.Errorf("a reader of a 0750 directory: %v", err)
			}
		})
	}
}
