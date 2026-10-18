package stopwrite_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// TestInitStartsAListThePlaneServes: the list is the header line alone,
// owner-only, under a list id drawn fresh each time, and a plane serves it
// clear.
func TestInitStartsAListThePlaneServes(t *testing.T) {
	r := testRoute(t)
	dir, h := initDir(t, r)
	if !regexp.MustCompile(`^lst-[0-9a-f]{32}$`).MatchString(h.ListID) {
		t.Errorf("list id %q, want lst- and 32 hex digits", h.ListID)
	}
	if h.RouteID != "refunds" || h.RouteSerial != 3 || h.RouteDigest != r.Digest() {
		t.Errorf("header %+v names another route", h)
	}
	want := append(must(t)(reaction.HeaderFor(r, h.ListID).Marshal()), '\n')
	if got := content(t, dir); !bytes.Equal(got, want) {
		t.Errorf("Init wrote %q, want %q", got, want)
	}
	if info, err := os.Stat(listPath(dir)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the list's mode: %v, %v; want 0600", info, err)
	}
	if s := planeOn(t, dir, r).Current(); s.State() != reaction.Clear {
		t.Errorf("a plane over a new list: %s (%s), want clear", s.State(), s.Detail())
	}
	if _, again := initDir(t, r); again.ListID == h.ListID {
		t.Errorf("two lists drew one list id %q", h.ListID)
	}
}

// noList fails if dir holds a list.
func noList(t *testing.T, what, dir string) {
	t.Helper()
	if _, err := os.Lstat(listPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s left %s: %v", what, listPath(dir), err)
	}
}

// TestInitRefusesAndWritesNothing: a second Init over a list, a directory
// the group may write and a route never read are refused, and none of them
// writes.
func TestInitRefusesAndWritesNothing(t *testing.T) {
	r := testRoute(t)
	dir, _ := initDir(t, r)
	want := content(t, dir)
	if _, err := stopwrite.Init(bg, dir, r, clock0); !errors.Is(err, stopwrite.ErrExists) {
		t.Errorf("Init over a list = %v, want ErrExists", err)
	}
	if got := content(t, dir); !bytes.Equal(got, want) {
		t.Errorf("a refused Init changed the list to %q", got)
	}
	open := emptyDir(t)
	if err := os.Chmod(open, 0o770); err != nil { //nolint:gosec // G302: a directory the checks refuse, on purpose
		t.Fatal(err)
	}
	if _, err := stopwrite.Init(bg, open, r, clock0); !errors.Is(err, stoplist.ErrDirMode) {
		t.Errorf("Init in a directory the group may write = %v, want ErrDirMode", err)
	}
	noList(t, "Init in a directory the group may write", open)
	none := emptyDir(t)
	if _, err := stopwrite.Init(bg, none, reaction.Route{}, clock0); !errors.Is(err, stopwrite.ErrRefused) {
		t.Errorf("Init under no route = %v, want ErrRefused", err)
	}
	noList(t, "Init under no route", none)
}

// TestEachAppendIsJudgedBeforeItIsWritten: every line the plane's judge
// would refuse in its place is refused before a byte is written, with the
// judge's own refusal wrapped; the accepted ones return their line number.
func TestEachAppendIsJudgedBeforeItIsWritten(t *testing.T) {
	r := testRoute(t)
	dir, h := initDir(t, r)
	for i, w := range []func() (int64, error){
		func() (int64, error) {
			return stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-1", "run-1", clock0), clock0)
		},
		func() (int64, error) {
			return stopwrite.AppendCovered(bg, dir, r, coveredOf("f-2", "run-1", clock0), clock0)
		},
		func() (int64, error) {
			return stopwrite.AppendLift(bg, dir, r, liftOf(t, liftKey(), r, h.ListID, "run-1", 2), clock0)
		},
	} {
		if n, err := w(); err != nil || n != int64(i+2) {
			t.Fatalf("append %d = %d, %v; want line %d", i, n, err, i+2)
		}
	}
	before := content(t, dir)
	stranger := stopOf(t, "f-3", "run-2", clock0)
	stranger.TenantID = "other"
	strangerCovered := coveredOf("f-6", "run-2", clock0)
	strangerCovered.TenantID = "other"
	wrongID := stopOf(t, "f-4", "run-2", clock0)
	wrongID.EntryID = reaction.EntryID("f-5")
	for _, c := range []struct {
		name  string
		write func() (int64, error)
		judge error
	}{
		{"a finding named again as a stop", func() (int64, error) {
			return stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-2", "run-1", clock0), clock0)
		}, reaction.ErrFindingAgain},
		{"a finding named again as covered", func() (int64, error) {
			return stopwrite.AppendCovered(bg, dir, r, coveredOf("f-1", "run-1", clock0), clock0)
		}, reaction.ErrFindingAgain},
		{"a covered line of another tenant", func() (int64, error) {
			return stopwrite.AppendCovered(bg, dir, r, strangerCovered, clock0)
		}, reaction.ErrCoveredRun},
		{"a stop of another tenant", func() (int64, error) {
			return stopwrite.AppendStop(bg, dir, r, stranger, clock0)
		}, reaction.ErrStopRefused},
		{"a stop dated past the writer's clock", func() (int64, error) {
			return stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-7", "run-2", clock0.Add(time.Second)), clock0)
		}, reaction.ErrDatedAhead},
		{"a stop whose entry id is another finding's", func() (int64, error) {
			return stopwrite.AppendStop(bg, dir, r, wrongID, clock0)
		}, reaction.ErrEntryID},
		{"a lift under another key", func() (int64, error) {
			return stopwrite.AppendLift(bg, dir, r, liftOf(t, otherKey(), r, h.ListID, "run-1", 3), clock0)
		}, reaction.ErrLiftUnsigned},
		{"a lift of another list", func() (int64, error) {
			return stopwrite.AppendLift(bg, dir, r, liftOf(t, liftKey(), r, "lst-other", "run-1", 3), clock0)
		}, reaction.ErrLiftMismatch},
		{"a lift through its own line", func() (int64, error) {
			return stopwrite.AppendLift(bg, dir, r, liftOf(t, liftKey(), r, h.ListID, "run-1", 5), clock0)
		}, reaction.ErrLiftOrder},
		{"a lift repeated", func() (int64, error) {
			return stopwrite.AppendLift(bg, dir, r, liftOf(t, liftKey(), r, h.ListID, "run-1", 2), clock0)
		}, reaction.ErrLiftAgain},
		{"under another route", func() (int64, error) {
			return stopwrite.AppendStop(bg, dir, routeOf(t, 4, false), stopOf(t, "f-8", "run-2", clock0), clock0)
		}, reaction.ErrListRoute},
	} {
		n, err := c.write()
		expectRefused(t, c.name, dir, before, n, err, c.judge)
	}
	if n, err := stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-9", "run-2", clock0), clock0); err != nil || n != 5 {
		t.Errorf("a good stop after the refusals = %d, %v; want line 5", n, err)
	}
}

// expectRefused fails unless the write returned no line and ErrRefused
// wrapping judge, and left the list in dir as before.
func expectRefused(t *testing.T, what, dir string, before []byte, n int64, err, judge error) {
	t.Helper()
	if !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, judge) || n != 0 {
		t.Errorf("%s: %d, %v; want ErrRefused wrapping %q", what, n, err, judge)
	}
	if got := content(t, dir); !bytes.Equal(got, before) {
		t.Errorf("%s: the refused write changed the list", what)
	}
}

// TestTheWriterRefusesAFileThePlaneRefuses: a list others may write, a link
// at its name and a list whose lines the judge refuses are not appended to.
func TestTheWriterRefusesAFileThePlaneRefuses(t *testing.T) {
	r := testRoute(t)
	stop := stopOf(t, "f-1", "run-1", clock0)

	dir, _ := initDir(t, r)
	if err := os.Chmod(listPath(dir), 0o620); err != nil { //nolint:gosec // G302: a list the checks refuse, on purpose
		t.Fatal(err)
	}
	if _, err := stopwrite.AppendStop(bg, dir, r, stop, clock0); !errors.Is(err, stoplist.ErrFileMode) {
		t.Errorf("a list the group may write = %v, want ErrFileMode", err)
	}

	dir, _ = initDir(t, r)
	if err := os.Rename(listPath(dir), filepath.Join(dir, "real.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.jsonl", listPath(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := stopwrite.AppendStop(bg, dir, r, stop, clock0); !errors.Is(err, stoplist.ErrLink) {
		t.Errorf("a link at the list's name = %v, want ErrLink", err)
	}

	dir, _ = initDir(t, r)
	broken := append(content(t, dir), "{}\n"...)
	setContent(t, dir, broken)
	if _, err := stopwrite.AppendStop(bg, dir, r, stop, clock0); !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, reaction.ErrLineKind) {
		t.Errorf("a list holding a line the judge refuses = %v, want ErrRefused", err)
	}
	if got := content(t, dir); !bytes.Equal(got, broken) {
		t.Errorf("the refused write changed the list")
	}

	if _, err := stopwrite.AppendStop(bg, emptyDir(t), r, stop, clock0); !errors.Is(err, stoplist.ErrMissing) {
		t.Errorf("a directory with no list = %v, want ErrMissing", err)
	}
}

// TestATornTailIsRepairedByTheNextWriter: a line a writer left without its
// newline is left out by the plane, kept by a refused write, and cut by the
// next write before it appends; the plane then reads the new line.
func TestATornTailIsRepairedByTheNextWriter(t *testing.T) {
	r := testRoute(t)
	dir, _ := initDir(t, r)
	if _, err := stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-1", "run-1", clock0), clock0); err != nil {
		t.Fatal(err)
	}
	whole := content(t, dir)
	plane := planeOn(t, dir, r)
	torn := must(t)(stopOf(t, "f-2", "run-2", clock0).Marshal())
	torn = torn[:len(torn)-1]
	setContent(t, dir, append(bytes.Clone(whole), torn...))
	if s := plane.Poll(); s.State() != reaction.Stopped || s.Active("run-2", "acme", clock0, time.Time{}) ||
		s.Accepted().Length() != int64(len(whole)) {
		t.Errorf("the plane over a torn tail: %s (%s), accepted %d of %d", s.State(), s.Detail(), s.Accepted().Length(), len(whole))
	}
	if _, err := stopwrite.AppendCovered(bg, dir, r, coveredOf("f-1", "run-1", clock0), clock0); !errors.Is(err, stopwrite.ErrRefused) {
		t.Fatalf("a refused write = %v", err)
	}
	if got := content(t, dir); !bytes.Equal(got, append(bytes.Clone(whole), torn...)) {
		t.Errorf("a refused write cut the tail")
	}
	n, err := stopwrite.AppendCovered(bg, dir, r, coveredOf("f-3", "run-1", clock0), clock0)
	if err != nil || n != 3 {
		t.Fatalf("AppendCovered over a torn tail = %d, %v; want line 3", n, err)
	}
	line := must(t)(coveredOf("f-3", "run-1", clock0).Marshal())
	want := append(append(bytes.Clone(whole), line...), '\n')
	if got := content(t, dir); !bytes.Equal(got, want) {
		t.Errorf("after the repair the list is %q, want %q", got, want)
	}
	if s := plane.Poll(); s.State() != reaction.Stopped || s.Accepted().Length() != int64(len(want)) {
		t.Errorf("the plane after the repair: %s (%s), accepted %d of %d", s.State(), s.Detail(), s.Accepted().Length(), len(want))
	}
}

// TestAppendFindingStopsARunOnce: a finding of a run with no active stop is
// written as a stop, one of a run with an active stop that lasts as long as
// its own as covered, and one whose stop would outlast every active one as a
// stop; a run whose stop expired, and one whose stop a lift ended, take a
// stop again.
func TestAppendFindingStopsARunOnce(t *testing.T) {
	r := testRoute(t)
	dir, h := initDir(t, r)
	if _, err := stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-old", "run-3", clock0.Add(-2*time.Hour)), clock0); err != nil {
		t.Fatal(err)
	}
	for i, c := range []struct {
		finding, run string
		lift         bool
		line         int64
		covered      bool
	}{
		{"f-1", "run-1", false, 3, false},
		{"f-2", "run-1", false, 4, true},
		{"f-3", "run-2", false, 5, false},
		{"f-4", "run-3", false, 6, false},
		{"", "run-1", true, 7, false},
		{"f-5", "run-1", false, 8, false},
		{"f-6", "run-1", false, 9, true},
	} {
		if c.lift {
			if _, err := stopwrite.AppendLift(bg, dir, r, liftOf(t, liftKey(), r, h.ListID, c.run, 6), clock0); err != nil {
				t.Fatalf("step %d: the lift: %v", i, err)
			}
			continue
		}
		n, covered, err := appendFinding(bg, dir, r, stopOf(t, c.finding, c.run, clock0), clock0)
		if err != nil || n != c.line || covered != c.covered {
			t.Errorf("step %d, %s of %s: line %d, covered %v, %v; want line %d, covered %v", i, c.finding, c.run, n, covered, err, c.line, c.covered)
		}
	}
}

// TestAppendFindingNeverCutsALongerStopShort: a finding whose stop would last
// longer than the run's active one is written as a stop, so the run stays
// stopped until the later expiry; one that would end sooner is covered.
func TestAppendFindingNeverCutsALongerStopShort(t *testing.T) {
	r := routeOf(t, 3, true)
	dir, _ := initDir(t, r)
	short := stopOf(t, "f-short", "run-1", clock0)
	short.ExpiresAt = clock0.Add(10 * time.Minute)
	long := stopOf(t, "f-long", "run-1", clock0)
	long.RuleID, long.ExpiresAt = "DEADLINE_EXCEEDED", clock0.Add(5*time.Hour)
	shorter := stopOf(t, "f-shorter", "run-1", clock0)
	shorter.ExpiresAt = clock0.Add(time.Minute)
	for i, c := range []struct {
		s       reaction.Stop
		covered bool
	}{{short, false}, {long, false}, {shorter, true}} {
		if _, covered, err := appendFinding(bg, dir, r, c.s, clock0); err != nil || covered != c.covered {
			t.Errorf("finding %d, %s: covered %v, %v; want covered %v", i, c.s.FindingID, covered, err, c.covered)
		}
	}
	if s := planeOn(t, dir, r).Current(); !s.Active("run-1", "acme", clock0.Add(time.Hour), time.Time{}) {
		t.Error("run-1 is not stopped an hour on, after the short stop ended and while the long one holds")
	}
}
