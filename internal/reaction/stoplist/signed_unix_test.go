//go:build unix

package stoplist

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/reaction"
)

// TestAListThePlanesAccountOwnsIsRefusedUnderOwnedByAnother: the signed
// read refuses a directory or a file the reading account owns, with its own
// cause, takes a list another account owns, and AnyOwner takes either.
func TestAListThePlanesAccountOwnsIsRefusedUnderOwnedByAnother(t *testing.T) {
	me, other := os.Geteuid(), os.Geteuid()+1
	for _, c := range []struct {
		name  string
		owner Owner
		uids  []int
		err   error
	}{
		{"another account's directory and file", OwnedByAnother, []int{other}, nil},
		{"the plane's directory", OwnedByAnother, []int{me}, ErrPlaneOwned},
		{"the plane's file in another account's directory", OwnedByAnother, []int{other, me}, ErrPlaneOwned},
		{"the plane's own, any owner", AnyOwner, []int{me}, nil},
		{"another account's, any owner", AnyOwner, []int{other}, nil},
		{"another account's, read as its writer", OwnedByThisUser, []int{other}, ErrDirOwner},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := listDir(t, stoppingList(t))
			actAs(t, c.uids...)
			raw, err := ReadAs(dir, c.owner)
			switch {
			case c.err == nil && (err != nil || !bytes.Equal(raw, stoppingList(t))):
				t.Fatalf("ReadAs = %d bytes, %v; want the list", len(raw), err)
			case c.err != nil && !errors.Is(err, c.err):
				t.Fatalf("ReadAs = %v, want %v", err, c.err)
			}
			if errors.Is(c.err, ErrPlaneOwned) && CauseOf(err) != CausePlaneOwned {
				t.Fatalf("CauseOf = %q, want %q", CauseOf(err), CausePlaneOwned)
			}
		})
	}
}

// TestTakeHoldsEveryAcceptedRead: Take sees the list the poller opens on
// and every read it accepts, with the bytes read, a read that added nothing
// among them; a refusal of a growth makes that read Unknown, keeps the part
// accepted before and is asked again at the next read; a refusal of a read
// that added nothing makes it Unknown too; a refusal at the first read is a
// poller that never opens, naming the refusal's cause.
func TestTakeHoldsEveryAcceptedRead(t *testing.T) {
	first := stoppingList(t)
	dir := listDir(t, first)
	var took []int
	var refuse error
	clock := &settable{now: clock0}
	p, err := Open(Options{Dir: dir, Route: testRoute(t), Interval: poll, Clock: clock.read, Owner: AnyOwner,
		Take: func(l reaction.List, content []byte) error {
			if l.Prefix().Length() != int64(len(content)) {
				t.Errorf("Take saw a list of %d bytes with %d bytes read", l.Prefix().Length(), len(content))
			}
			took = append(took, len(content))
			return refuse
		}})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	expect(t, "unchanged", p.Poll(), reaction.Stopped, "", len(first), [2]bool{true, false})
	grown := append(bytes.Clone(first), lines(stopLine(t, "f-3", "run-2", clock0))...)
	writeList(t, dir, grown)
	refuse = fmt.Errorf("%w: cut", ErrChain)
	if s := p.Poll(); s.State() != reaction.Unknown || s.Cause() != CauseChain || s.Accepted().Length() != int64(len(first)) {
		t.Fatalf("a growth Take refused: %v %q, %d bytes accepted", s.State(), s.Cause(), s.Accepted().Length())
	}
	refuse = nil
	expect(t, "grown", p.Poll(), reaction.Stopped, "", len(grown), [2]bool{true, true})
	if want := []int{len(first), len(first), len(grown), len(grown)}; !slices.Equal(took, want) {
		t.Fatalf("Take saw lists of %v bytes, want %v", took, want)
	}
	refuse = fmt.Errorf("%w: a floor raised past it", ErrChain)
	if s := p.Poll(); s.State() != reaction.Unknown || s.Cause() != CauseChain || s.Accepted().Length() != int64(len(grown)) {
		t.Fatalf("a read that added nothing, Take refused: %v %q, %d bytes accepted", s.State(), s.Cause(), s.Accepted().Length())
	}
	refusal := fmt.Errorf("%w: serial 1, the floor's 2", ErrBelowFloor)
	_, err = Open(Options{Dir: listDir(t, first), Route: testRoute(t), Interval: poll, Clock: clock.read,
		Take: func(reaction.List, []byte) error { return refusal }})
	if !errors.Is(err, ErrNotServable) || !strings.Contains(err.Error(), string(CauseBelowFloor)) {
		t.Fatalf("Open over a list Take refuses: %v", err)
	}
}
