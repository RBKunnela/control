//go:build unix

package approvals_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
)

// TestEveryFileTheStoreWritesIsItsOwnersAlone: under a umask that narrows
// nothing, the marker, a projection, a record still held and an answer are
// each written readable and writable by their owner and nobody else.
func TestEveryFileTheStoreWritesIsItsOwnersAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "approvals")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0)
	err := holdAndAnswer(t, dir)
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"store.meta", "APPROVAL1.view.json", "APPROVAL1.1-answered.rec", "APPROVAL2.0-held.rec"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s: mode %04o, want 0600", name, got)
		}
	}
}

func holdAndAnswer(t *testing.T, dir string) error {
	t.Helper()
	p, err := approvals.OpenPlane(dir)
	if err != nil {
		return err
	}
	defer func() { _ = p.Close() }()
	if err := p.Hold(t.Context(), held(t, firstApproval, "req-1"), minted); err != nil {
		return err
	}
	if err := p.Hold(t.Context(), held(t, "APPROVAL2", "req-2"), minted); err != nil {
		return err
	}
	a, err := approvals.OpenApprover(dir)
	if err != nil {
		return err
	}
	defer func() { _ = a.Close() }()
	_, err = a.Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", minted)
	return err
}

// TestAnAnswerThatCannotBeMadeDurableIsNotFiled: the answer is linked, and
// then the directory cannot be opened to force it to disk. Answer reports the
// failure, and the name it linked is gone with it, so a plane that looks
// afterwards does not read it, and a second answer is taken.
func TestAnAnswerThatCannotBeMadeDurableIsNotFiled(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser opens a directory whatever its mode")
	}
	p, dir := openPlane(t)
	if err := p.Hold(t.Context(), held(t, firstApproval, "req-1"), minted); err != nil {
		t.Fatal(err)
	}
	var armed atomic.Bool
	armed.Store(true)
	a := openApprover(t, dir, approvals.WithSteps(func(step string) {
		if step == approvals.StepLinked && armed.CompareAndSwap(true, false) {
			if err := os.Chmod(dir, 0o300); err != nil { //nolint:gosec // G302: a directory its owner cannot list, so the sync fails
				t.Error(err)
			}
		}
	}))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: the store's own mode, back
	approved := controlv1.ApprovalState_APPROVAL_STATE_APPROVED
	_, err := a.Answer(t.Context(), firstApproval, approved, "approver-1", "", minted)
	if chmodErr := os.Chmod(dir, 0o700); chmodErr != nil { //nolint:gosec // G302: the store's own mode, back
		t.Fatal(chmodErr)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Answer with a directory it cannot force to disk = %v, want fs.ErrPermission", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "APPROVAL1.1-answered.rec")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a failed answer left its name: %v", err)
	}
	if _, err := a.Answer(t.Context(), firstApproval, approved, "approver-1", "", minted); err != nil {
		t.Fatalf("the answer after the failed one: %v", err)
	}
}

// TestAnAnswerThePlaneReadBeforeTheFailureIsTakenBack: between the
// approver's link and forcing it to disk, the plane reads the answer, and then
// the directory cannot be opened. The answer is taken back and Answer reports
// the failure alone: whether the plane spent what it read is in the plane's
// own ledger, never in this directory.
func TestAnAnswerThePlaneReadBeforeTheFailureIsTakenBack(t *testing.T) {
	var read []approvals.Record
	dir, readErr, err := answerWhileThePlaneReads(t, func(p *approvals.Plane, h approvals.Hold) error {
		found, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute))
		read = found
		return err
	})
	if readErr != nil || len(read) != 1 || read[0].Approval.GetState() != approved {
		t.Fatalf("the plane reading the answer = %v, %v; want the answer", read, readErr)
	}
	if !errors.Is(err, fs.ErrPermission) || errors.Is(err, approvals.ErrOutcomeUnknown) {
		t.Fatalf("Answer whose sync failed = %v, want fs.ErrPermission alone", err)
	}
	if got, want := recordNames(t, dir), []string{"APPROVAL1.0-held.rec"}; !slices.Equal(got, want) {
		t.Fatalf("records = %v, want %v", got, want)
	}
}

// TestAnAnswerGoneBeforeItsUndoIsNotReportedNotFiled: the plane prunes the
// record as expired between the approver's link and forcing it to disk,
// answer and all. The approver's undo finds the name gone, so whether the
// answer was read is unknown, and Answer says so beside the failure.
func TestAnAnswerGoneBeforeItsUndoIsNotReportedNotFiled(t *testing.T) {
	_, pruneErr, err := answerWhileThePlaneReads(t, func(p *approvals.Plane, _ approvals.Hold) error {
		n, err := p.Prune(t.Context(), expires)
		if err == nil && n != 1 {
			return fmt.Errorf("pruned %d records, want 1", n)
		}
		return err
	})
	if pruneErr != nil {
		t.Fatalf("the plane pruning the record: %v", pruneErr)
	}
	if !errors.Is(err, approvals.ErrOutcomeUnknown) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Answer whose undo found its name gone = %v, want ErrOutcomeUnknown beside fs.ErrPermission", err)
	}
}

// answerWhileThePlaneReads holds firstApproval and approves it. At the
// approver's link the plane runs call, and then the directory stops being
// readable, so forcing the link to disk fails. It returns the directory, what
// call returned and what Answer returned.
func answerWhileThePlaneReads(t *testing.T, call func(*approvals.Plane, approvals.Hold) error) (string, error, error) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the superuser opens a directory whatever its mode")
	}
	p, dir := openPlane(t)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatal(err)
	}
	var armed atomic.Bool
	armed.Store(true)
	var callErr error
	a := openApprover(t, dir, approvals.WithSteps(func(step string) {
		if step == approvals.StepLinked && armed.CompareAndSwap(true, false) {
			callErr = call(p, h)
			if err := os.Chmod(dir, 0o300); err != nil { //nolint:gosec // G302: a directory its owner cannot list, so the sync fails
				t.Error(err)
			}
		}
	}))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: the store's own mode, back
	_, err := a.Answer(t.Context(), firstApproval, approved, "approver-1", "", minted.Add(time.Minute))
	if chmodErr := os.Chmod(dir, 0o700); chmodErr != nil { //nolint:gosec // G302: the store's own mode, back
		t.Fatal(chmodErr)
	}
	return dir, callErr, err
}
