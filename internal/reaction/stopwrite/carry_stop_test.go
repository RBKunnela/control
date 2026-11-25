package stopwrite_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// TestASignedCarryStoppedBetweenItsWritesIsFinishedByARerun: a signed carry
// stopped between taking the write bits off the old list and writing the new
// one leaves the old list read-only, so no stop reaches a list nothing
// carries, and a rerun finishes the carry; no stop or lift is appended to the
// old list after it.
func TestASignedCarryStoppedBetweenItsWritesIsFinishedByARerun(t *testing.T) {
	from := emptyDir(t)
	fromRoute := signedRouteIn(t, from, 3)
	h, err := stopwrite.InitSigned(bg, from, fromRoute, clock0, signer(), 1)
	if err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	if _, err := stopwrite.AppendStop(bg, from, fromRoute, signedStop(t, "f-1", "run-1", "shop", clock0), clock0); err != nil {
		t.Fatalf("AppendStop: %v", err)
	}
	into := emptyDir(t)
	route := signedRouteIn(t, into, 4)
	killed := errors.New("the carry stopped between its writes")
	undo := stopwrite.SetCarryStop(func() error { return killed })
	_, err = stopwrite.CarrySigned(bg, from, fromRoute, into, route, clock0, signer(), nil)
	undo()
	if !errors.Is(err, killed) {
		t.Fatalf("CarrySigned with a stop between its writes = %v, want the stop", err)
	}
	if got := listMode(t, from); got != 0o440 {
		t.Errorf("the old list is %04o after the stop, want 0440", got)
	}
	if _, err := os.Stat(filepath.Join(into, stoplist.FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the new list after the stop: %v, want none", err)
	}
	if _, err := stopwrite.CarrySigned(bg, from, fromRoute, into, route, clock0, signer(), nil); err != nil {
		t.Fatalf("the carry run again after the stop = %v; the old list is %04o", err, listMode(t, from))
	}
	if got := listMode(t, from); got != 0o440 {
		t.Errorf("the old list is %04o after the rerun, want 0440", got)
	}
	if _, err := os.Stat(filepath.Join(into, stoplist.FileName)); err != nil {
		t.Errorf("the new list after the rerun: %v", err)
	}
	if _, err := stopwrite.AppendStop(bg, from, fromRoute, signedStop(t, "f-late", "run-9", "shop", clock0), clock0); !errors.Is(err, stopwrite.ErrCarried) {
		t.Errorf("a stop appended to the old list after the rerun = %v, want ErrCarried", err)
	}
	if _, err := stopwrite.AppendLift(bg, from, fromRoute, operatorLift(t, from, h), clock0); !errors.Is(err, stopwrite.ErrCarried) {
		t.Errorf("a lift of the carried stop appended to the old list after the rerun = %v, want ErrCarried", err)
	}
}

// TestASignedCarryRefusedAtItsWriteLeavesTheOldListWritable: a carry into a
// directory that holds a list already is refused at its write, and the old
// list gets back the write bits the carry took, since nothing carried it.
func TestASignedCarryRefusedAtItsWriteLeavesTheOldListWritable(t *testing.T) {
	from := emptyDir(t)
	fromRoute := signedRouteIn(t, from, 3)
	if _, err := stopwrite.InitSigned(bg, from, fromRoute, clock0, signer(), 1); err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	into := emptyDir(t)
	route := signedRouteIn(t, into, 4)
	if _, err := stopwrite.InitSigned(bg, into, route, clock0, signer(), 1); err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	if _, err := stopwrite.CarrySigned(bg, from, fromRoute, into, route, clock0, signer(), nil); !errors.Is(err, stopwrite.ErrExists) {
		t.Fatalf("CarrySigned into a directory holding a list = %v, want ErrExists", err)
	}
	if got := listMode(t, from); got != 0o640 {
		t.Errorf("the old list is %04o after a refused carry, want 0640", got)
	}
	if _, err := stopwrite.AppendStop(bg, from, fromRoute, signedStop(t, "f-late", "run-9", "shop", clock0), clock0); err != nil {
		t.Errorf("a stop appended to the old list after a refused carry = %v", err)
	}
}

// TestASignedCarryWhoseCreateFailedWithItsListInPlaceKeepsTheOldListReadOnly:
// a create that fails once the new list stands in place, its own removal
// failing too, leaves a list the plane may take; the old list keeps no
// write bit, so no stop reaches a list nothing carries.
func TestASignedCarryWhoseCreateFailedWithItsListInPlaceKeepsTheOldListReadOnly(t *testing.T) {
	from := emptyDir(t)
	fromRoute := signedRouteIn(t, from, 3)
	if _, err := stopwrite.InitSigned(bg, from, fromRoute, clock0, signer(), 1); err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	into := emptyDir(t)
	route := signedRouteIn(t, into, 4)
	failed := errors.New("the new list's directory did not reach the disk")
	undo := stopwrite.SetAfterCreate(func(err error) error { return errors.Join(err, failed) })
	_, err := stopwrite.CarrySigned(bg, from, fromRoute, into, route, clock0, signer(), nil)
	undo()
	if !errors.Is(err, failed) {
		t.Fatalf("CarrySigned with a failed create = %v, want the failure", err)
	}
	if _, err := os.Stat(filepath.Join(into, stoplist.FileName)); err != nil {
		t.Fatalf("the new list after the failed create: %v, want it in place", err)
	}
	if got := listMode(t, from); got != 0o440 {
		t.Errorf("the old list is %04o beside a new list in place, want 0440", got)
	}
}
