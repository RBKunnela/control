package stopwrite_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// oldList is a list under r, at the writer's clock clock0, holding in order:
// a stop of run-1 a lift ends (f-lifted), the lift, a stop of run-1 created
// two hours ago and so expired (f-expired), a stop of run-1 still active
// (f-kept), and a covered line of run-1 (f-covered). When stranded is set it
// also holds a stop of run-2, a covered line of run-2 and a lift of run-2, so
// findings of run-2 are named and no stop of run-2 is left to carry.
func oldList(t *testing.T, r reaction.Route, stranded bool) string {
	t.Helper()
	dir, h := initDir(t, r)
	appendAll := func(writes ...func() (int64, error)) {
		t.Helper()
		for i, w := range writes {
			if _, err := w(); err != nil {
				t.Fatalf("building the old list, write %d: %v", i, err)
			}
		}
	}
	appendAll(
		func() (int64, error) {
			return stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-lifted", "run-1", clock0), clock0)
		},
		func() (int64, error) {
			return stopwrite.AppendLift(bg, dir, r, liftOf(t, liftKey(), r, h.ListID, "run-1", 2), clock0)
		},
		func() (int64, error) {
			return stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-expired", "run-1", clock0.Add(-2*time.Hour)), clock0)
		},
		func() (int64, error) {
			return stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-kept", "run-1", clock0.Add(-time.Minute)), clock0)
		},
		func() (int64, error) {
			return stopwrite.AppendCovered(bg, dir, r, coveredOf("f-covered", "run-1", clock0), clock0)
		},
	)
	if stranded {
		appendAll(
			func() (int64, error) {
				return stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-run2", "run-2", clock0), clock0)
			},
			func() (int64, error) {
				return stopwrite.AppendCovered(bg, dir, r, coveredOf("f-run2b", "run-2", clock0), clock0)
			},
			func() (int64, error) {
				return stopwrite.AppendLift(bg, dir, r, liftOf(t, liftKey(), r, h.ListID, "run-2", 7), clock0)
			},
		)
	}
	return dir
}

// TestCarryBringsEveryUnliftedStopAndNamesEveryFinding: the new list, under
// a route of a later serial, holds the two stops no lift ended, the expired
// one among them, as they were, and names every other finding as covered; a
// plane serves it, and every finding the old list names is named again.
func TestCarryBringsEveryUnliftedStopAndNamesEveryFinding(t *testing.T) {
	from, to := testRoute(t), routeOf(t, 4, true)
	old := oldList(t, from, false)
	dir := emptyDir(t)
	got, err := stopwrite.Carry(bg, old, from, dir, to, clock0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Carry: %v", err)
	}
	if got.Stops != 2 || got.Covered != 2 || got.Header.RouteSerial != 4 || got.Header.RouteDigest != to.Digest() {
		t.Errorf("Carry = %+v; want 2 stops and 2 covered under serial 4", got)
	}
	expectCarried(t, to, content(t, dir))
	if s := planeOn(t, dir, to).Current(); s.State() != reaction.Stopped || !s.Active("run-1", "acme", clock0, time.Time{}) {
		t.Errorf("a plane over the carried list: %s (%s), want run-1 stopped", s.State(), s.Detail())
	}
	_, err = stopwrite.AppendStop(bg, dir, to, stopOf(t, "f-lifted", "run-1", clock0), clock0.Add(time.Minute))
	if !errors.Is(err, reaction.ErrFindingAgain) {
		t.Errorf("a stop of a finding the old list named, after the carry = %v, want ErrFindingAgain", err)
	}
}

// TestCarryNamesTheFindingsOfARunThatKeepsNoStop: a finding of a run whose
// stops all ended, and every finding once every stop expired, is carried as a
// covered line, so it never stops its run again, while a new finding of that
// run still does.
func TestCarryNamesTheFindingsOfARunThatKeepsNoStop(t *testing.T) {
	from, to := testRoute(t), routeOf(t, 4, false)
	old := []string{"f-lifted", "f-expired", "f-kept", "f-covered"}
	t.Run("a run that keeps no stop", func(t *testing.T) {
		dir := carriedNoStop(t, oldList(t, from, true), from, to, clock0, 2, append(old, "f-run2", "f-run2b"), reaction.Stopped)
		if _, err := stopwrite.AppendStop(bg, dir, to, stopOf(t, "f-run2", "run-2", clock0), clock0); !errors.Is(err, reaction.ErrFindingAgain) {
			t.Errorf("a stop of a finding the old list named = %v, want ErrFindingAgain", err)
		}
	})
	t.Run("every stop expired", func(t *testing.T) {
		carriedNoStop(t, oldList(t, from, false), from, to, clock0.Add(2*time.Hour), 2, old, reaction.Clear)
	})
}

// carriedNoStop carries the list in old at now and fails unless the new list
// holds stops stops and a covered line for every other finding of named, a
// plane at now serves it in state with run-2 not stopped, and a new finding of
// run-2 still stops it. It returns the new list's directory.
func carriedNoStop(t *testing.T, old string, from, to reaction.Route, now time.Time, stops int, named []string, state reaction.State) string {
	t.Helper()
	dir := emptyDir(t)
	got, err := stopwrite.Carry(bg, old, from, dir, to, now)
	if err != nil {
		t.Fatalf("Carry: %v", err)
	}
	if got.Stops != stops || got.Covered != len(named)-stops {
		t.Errorf("Carry = %+v; want %d stop(s) and %d covered", got, stops, len(named)-stops)
	}
	list, err := reaction.Judge(to, reaction.Prefix{}, content(t, dir), now, 0)
	if err != nil {
		t.Fatalf("the plane's judge refuses the carried list: %v", err)
	}
	for _, f := range named {
		if !list.Names(f) {
			t.Errorf("the carried list does not name %s", f)
		}
	}
	p, err := stoplist.Open(stoplist.Options{Dir: dir, Route: to, Interval: poll, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("a plane's poller: %v", err)
	}
	if s := p.Current(); s.State() != state || s.Active("run-2", "acme", now, time.Time{}) {
		t.Errorf("a plane over the carried list: %s (%s), want %s and run-2 not stopped", s.State(), s.Detail(), state)
	}
	if _, err := stopwrite.AppendStop(bg, dir, to, stopOf(t, "f-new", "run-2", now), now); err != nil {
		t.Errorf("a stop of a new finding of run-2 = %v, want written", err)
	}
	return dir
}

// expectCarried fails unless the plane's judge takes the carried list with
// f-expired and f-kept its entries, on lines 2 and 3 with their times as they
// were, and every finding of the old list named.
func expectCarried(t *testing.T, r reaction.Route, carried []byte) {
	t.Helper()
	list, err := reaction.Judge(r, reaction.Prefix{}, carried, clock0.Add(time.Minute), 0)
	if err != nil {
		t.Fatalf("the plane's judge refuses the carried list: %v", err)
	}
	type kept struct {
		finding          string
		line             int64
		created, expires time.Time
	}
	var got []kept
	for _, e := range list.Entries() {
		got = append(got, kept{e.FindingID, e.Line, e.CreatedAt, e.ExpiresAt})
	}
	want := []kept{
		{"f-expired", 2, clock0.Add(-2 * time.Hour), clock0.Add(-time.Hour)},
		{"f-kept", 3, clock0.Add(-time.Minute), clock0.Add(59 * time.Minute)},
	}
	if !slices.Equal(got, want) {
		t.Errorf("carried entries %+v; want %+v, their times as they were", got, want)
	}
	for _, f := range []string{"f-lifted", "f-expired", "f-kept", "f-covered"} {
		if !list.Names(f) {
			t.Errorf("the carried list does not name %s", f)
		}
	}
}

// TestCarryRefusesWhatItCannotCarryWhole: a stop the new route does not
// permit, an old list judged against another route than its own and a missing
// old list are refused, and none writes a list.
func TestCarryRefusesWhatItCannotCarryWhole(t *testing.T) {
	from := testRoute(t)
	old := oldList(t, from, false)
	for _, c := range []struct {
		name      string
		from      string
		fromRoute reaction.Route
		to        reaction.Route
		now       time.Time
		errs      []error
	}{
		{"a route of another tenant", old, from, routeFor(t, 4, "other", false), clock0,
			[]error{stopwrite.ErrRefused, reaction.ErrStopRefused}},
		{"judged against another route", old, routeOf(t, 4, false), routeOf(t, 5, false), clock0,
			[]error{stopwrite.ErrRefused, reaction.ErrListRoute}},
		{"no old list", emptyDir(t), from, from, clock0, []error{stoplist.ErrMissing}},
	} {
		dir := emptyDir(t)
		_, err := stopwrite.Carry(bg, c.from, c.fromRoute, dir, c.to, c.now)
		for _, want := range c.errs {
			if !errors.Is(err, want) {
				t.Errorf("%s: Carry = %v, want %q", c.name, err, want)
			}
		}
		noList(t, c.name, dir)
	}
	before := content(t, old)
	if _, err := stopwrite.Carry(bg, old, from, old, from, clock0); !errors.Is(err, stopwrite.ErrExists) {
		t.Errorf("Carry onto a list = %v, want ErrExists", err)
	}
	if !bytes.Equal(content(t, old), before) {
		t.Error("a carry onto a list changed it")
	}
}

// TestCarryKeepsAStopAClockAheadCallsExpired: a writer whose clock runs a
// thousand hours ahead carries the stop it reads as expired as a stop, not as
// covered, so a plane whose clock is right still stops its run.
func TestCarryKeepsAStopAClockAheadCallsExpired(t *testing.T) {
	from, to := testRoute(t), routeOf(t, 4, false)
	dir := emptyDir(t)
	if _, err := stopwrite.Carry(bg, oldList(t, from, false), from, dir, to, clock0.Add(1000*time.Hour)); err != nil {
		t.Fatalf("Carry: %v", err)
	}
	if s := planeOn(t, dir, to).Current(); s.State() != reaction.Stopped || !s.Active("run-1", "acme", clock0, time.Time{}) {
		t.Errorf("a plane at the right clock over the list: %s (%s), want run-1 stopped", s.State(), s.Detail())
	}
}

// TestCarryRepairsAListBrokenAtALine: a list a plane refuses at one line, as
// one someone appended a line the route refuses to, is carried up to that
// line, the lines left out counted and the first one's refusal named, unless
// what it would leave out could be a stop the list was meant to hold: a stop
// or covered line after the refused one, a line refused for a created_at past
// the writer's clock, or a refused header.
func TestCarryRepairsAListBrokenAtALine(t *testing.T) {
	from, to := testRoute(t), routeOf(t, 4, false)
	stranger := stopOf(t, "f-stranger", "run-9", clock0)
	stranger.TenantID = "other"
	line := func(raw []byte, err error) string {
		t.Helper()
		return string(must(t)(raw, err)) + "\n"
	}
	refusedStop := line(stranger.Marshal())
	for _, c := range []struct {
		name    string
		tail    string
		leftOut int64
		errs    []error
	}{
		{"a stop the route refuses at the end", refusedStop, 1, nil},
		{"junk after it", refusedStop + "{}\nnot json\n", 3, nil},
		{"a stop after it", refusedStop + line(stopOf(t, "f-after", "run-2", clock0).Marshal()), 0,
			[]error{stopwrite.ErrRefused}},
		{"a covered line after it", refusedStop + line(coveredOf("f-after", "run-2", clock0).Marshal()), 0,
			[]error{stopwrite.ErrRefused}},
		{"a stop dated past the writer's clock", line(stopOf(t, "f-ahead", "run-2", clock0.Add(time.Hour)).Marshal()), 0,
			[]error{stopwrite.ErrRefused, reaction.ErrDatedAhead}},
	} {
		t.Run(c.name, func(t *testing.T) {
			old := oldList(t, from, false)
			setContent(t, old, append(content(t, old), c.tail...))
			dir := emptyDir(t)
			got, err := stopwrite.Carry(bg, old, from, dir, to, clock0.Add(time.Minute))
			if c.errs != nil {
				for _, want := range c.errs {
					if !errors.Is(err, want) {
						t.Errorf("Carry = %v, want %q", err, want)
					}
				}
				noList(t, c.name, dir)
				return
			}
			if err != nil {
				t.Fatalf("Carry: %v", err)
			}
			if got.Stops != 2 || got.Covered != 2 || got.LeftOut != c.leftOut || !errors.Is(got.Refused, reaction.ErrStopRefused) {
				t.Errorf("Carry = %+v; want 2 stops, 2 covered, %d line(s) left out from a stop the route refuses", got, c.leftOut)
			}
			expectCarried(t, to, content(t, dir))
		})
	}
	t.Run("a refused header", func(t *testing.T) {
		old := oldList(t, from, false)
		setContent(t, old, append([]byte("{}\n"), content(t, old)...))
		dir := emptyDir(t)
		if _, err := stopwrite.Carry(bg, old, from, dir, to, clock0); !errors.Is(err, stopwrite.ErrRefused) {
			t.Errorf("Carry of a list with a refused header = %v, want ErrRefused", err)
		}
		noList(t, "a refused header", dir)
	})
}

// TestCarriedLinesAreWhatACarryWritesAfterItsHeader: the lines after a
// carried list's header are CarriedLines of the old list, so a reader can
// tell a carry of a list from another list without its header.
func TestCarriedLinesAreWhatACarryWritesAfterItsHeader(t *testing.T) {
	r := testRoute(t)
	old := oldList(t, r, true)
	dir := emptyDir(t)
	now := clock0.Add(time.Minute)
	if _, err := stopwrite.Carry(bg, old, r, dir, r, now); err != nil {
		t.Fatalf("Carry: %v", err)
	}
	carried := content(t, dir)
	_, rest, _ := bytes.Cut(carried, []byte{'\n'})
	got, err := stopwrite.CarriedLines(r, content(t, old), now)
	if err != nil {
		t.Fatalf("CarriedLines: %v", err)
	}
	if len(got) == 0 || !bytes.Equal(got, rest) {
		t.Fatalf("CarriedLines =\n%s\nthe carry wrote after its header\n%s", got, rest)
	}
	if _, err := stopwrite.CarriedLines(r, []byte("not a list\n"), now); err == nil {
		t.Fatal("CarriedLines of no list: no error")
	}
}
