package stopwrite_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// stoppedList starts a list under r holding one stop of run-1, the run every
// covered line below names.
func stoppedList(t *testing.T, r reaction.Route) (string, *bytes.Buffer) {
	t.Helper()
	dir, _ := initDir(t, r)
	if _, err := stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-0", "run-1", clock0), clock0); err != nil {
		t.Fatal(err)
	}
	return dir, bytes.NewBuffer(content(t, dir))
}

func coveredLine(t *testing.T, finding string) []byte {
	t.Helper()
	return must(t)(coveredOf(finding, "run-1", clock0).Marshal())
}

// expectFull fails unless a covered line naming finding is refused as past
// the bound named by judge, leaving the list as it was.
func expectFull(t *testing.T, dir string, r reaction.Route, finding string, judge error) {
	t.Helper()
	before := content(t, dir)
	n, err := stopwrite.AppendCovered(bg, dir, r, coveredOf(finding, "run-1", clock0), clock0)
	if !errors.Is(err, stopwrite.ErrFull) || !errors.Is(err, judge) || n != 0 {
		t.Errorf("past the bound: %d, %v; want ErrFull wrapping %q", n, err, judge)
	}
	if !bytes.Equal(content(t, dir), before) {
		t.Error("a write refused at the bound changed the list")
	}
}

// TestTheLineBoundAtItsLimit: a list one line short of the bound takes one
// more line, and then none.
func TestTheLineBoundAtItsLimit(t *testing.T) {
	t.Parallel()
	r := testRoute(t)
	dir, list := stoppedList(t, r)
	for i := 3; i < reaction.MaxListLines; i++ {
		list.Write(coveredLine(t, fmt.Sprintf("f-%d", i)))
		list.WriteByte('\n')
	}
	setContent(t, dir, list.Bytes())
	n, err := stopwrite.AppendCovered(bg, dir, r, coveredOf("f-last", "run-1", clock0), clock0)
	if err != nil || n != 20000 {
		t.Fatalf("the last line the bound allows = %d, %v; want line 20000", n, err)
	}
	expectFull(t, dir, r, "f-over", reaction.ErrListLines)
}

// TestTheByteBoundAtItsLimit: a covered line that ends the list one byte
// past the bound is refused, and one byte shorter it lands and the list is
// the bound exactly.
func TestTheByteBoundAtItsLimit(t *testing.T) {
	t.Parallel()
	r := testRoute(t)
	dir, list := stoppedList(t, r)
	base := len(coveredLine(t, "a")) - 1
	minLen, maxLen := base+1, base+reaction.MaxFindingIDBytes
	padded := func(prefix string, length int) string {
		return prefix + strings.Repeat("x", length-base-len(prefix))
	}
	add := func(finding string) {
		line := coveredLine(t, finding)
		list.Write(line)
		list.WriteByte('\n')
	}
	last := base + 64
	room := reaction.MaxListBytes - list.Len() - (last + 1)
	for i := 0; room > 2*(maxLen+1); i++ {
		add(padded(fmt.Sprintf("b%07d", i), maxLen))
		room -= maxLen + 1
	}
	a := min(maxLen, room-2-minLen)
	b := room - 2 - a
	if a < minLen || b < minLen || b > maxLen {
		t.Fatalf("no two lines fill %d bytes", room)
	}
	add(padded("a", a))
	add(padded("e", b))
	setContent(t, dir, list.Bytes())
	if got := list.Len() + last + 1; got != reaction.MaxListBytes {
		t.Fatalf("the construction leaves %d bytes for a line of %d", reaction.MaxListBytes-list.Len(), last)
	}
	expectFull(t, dir, r, padded("c", last+1), reaction.ErrListTooLarge)
	if _, err := stopwrite.AppendCovered(bg, dir, r, coveredOf(padded("c", last), "run-1", clock0), clock0); err != nil {
		t.Fatalf("the line that ends the list at its bound: %v", err)
	}
	if info, err := os.Stat(listPath(dir)); err != nil || info.Size() != 4<<20 {
		t.Errorf("the list at its bound: %v, %v; want 4194304 bytes", info, err)
	}
}

// TestAListPastItsByteBoundIsLeftAsItIs: a list longer than the bound, which
// only a write around this package can make, is refused as the plane's reader
// refuses it, and no write cuts the complete lines past the bound, a stop
// among them.
func TestAListPastItsByteBoundIsLeftAsItIs(t *testing.T) {
	t.Parallel()
	r := testRoute(t)
	dir, list := stoppedList(t, r)
	list.WriteString(strings.Repeat("x", reaction.MaxListBytes))
	list.WriteByte('\n')
	list.Write(must(t)(stopOf(t, "f-past", "run-2", clock0).Marshal()))
	list.WriteByte('\n')
	setContent(t, dir, list.Bytes())
	before := content(t, dir)
	n, err := stopwrite.AppendCovered(bg, dir, r, coveredOf("f-new", "run-1", clock0), clock0)
	if !errors.Is(err, stopwrite.ErrFull) || !errors.Is(err, stoplist.ErrTooLarge) || n != 0 {
		t.Errorf("an append to a list past the bound = %d, %v; want ErrFull wrapping %q", n, err, stoplist.ErrTooLarge)
	}
	if !bytes.Equal(content(t, dir), before) {
		t.Error("an append to a list past the bound changed it")
	}
}

// TestAFullListStillSaysAFindingIsNamed: on a list at its line bound, a
// finding the list names is refused as named, which a writer that read the
// list before another named it takes as done, and a new one as past the
// bound.
func TestAFullListStillSaysAFindingIsNamed(t *testing.T) {
	t.Parallel()
	r := testRoute(t)
	dir, list := stoppedList(t, r)
	for i := 3; i <= reaction.MaxListLines; i++ {
		list.Write(coveredLine(t, fmt.Sprintf("f-%d", i)))
		list.WriteByte('\n')
	}
	setContent(t, dir, list.Bytes())
	before := content(t, dir)
	if _, _, err := appendFinding(bg, dir, r, stopOf(t, "f-9", "run-1", clock0), clock0); !errors.Is(err, stopwrite.ErrNamed) {
		t.Errorf("a named finding on a full list = %v, want ErrNamed", err)
	}
	if _, _, err := appendFinding(bg, dir, r, stopOf(t, "f-new", "run-1", clock0), clock0); !errors.Is(err, stopwrite.ErrFull) {
		t.Errorf("a new finding on a full list = %v, want ErrFull", err)
	}
	if !bytes.Equal(content(t, dir), before) {
		t.Error("a refused write changed the full list")
	}
}

// TestAListThatNamesAnotherFindingTwiceIsNoNamedFinding: a list the judge
// refuses for naming one finding twice refuses every append as such, never
// as the new finding being named already.
func TestAListThatNamesAnotherFindingTwiceIsNoNamedFinding(t *testing.T) {
	t.Parallel()
	r := testRoute(t)
	dir, list := stoppedList(t, r)
	list.Write(coveredLine(t, "f-0"))
	list.WriteByte('\n')
	setContent(t, dir, list.Bytes())
	_, _, err := appendFinding(bg, dir, r, stopOf(t, "f-new", "run-2", clock0), clock0)
	if !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, reaction.ErrFindingAgain) || errors.Is(err, stopwrite.ErrNamed) {
		t.Errorf("an append to a list naming f-0 twice = %v, want ErrRefused wrapping ErrFindingAgain and not ErrNamed", err)
	}
}
