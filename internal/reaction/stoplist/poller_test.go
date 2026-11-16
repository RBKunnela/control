package stoplist

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

// settable is a clock a test moves.
type settable struct {
	mu  sync.Mutex
	now time.Time
}

func (c *settable) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *settable) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func openOn(t *testing.T, dir string, clock *settable, log *slog.Logger) *Poller {
	t.Helper()
	p, err := Open(Options{Dir: dir, Route: testRoute(t), Interval: poll, Clock: clock.read, Logger: log})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return p
}

// expect fails unless s is in state with cause, has accepted length bytes,
// and stops run-1 and run-2 as runs says.
func expect(t *testing.T, what string, s reaction.Snapshot, state reaction.State, cause reaction.Cause, length int, runs [2]bool) {
	t.Helper()
	if s.State() != state || (state == reaction.Unknown && s.Cause() != cause) {
		t.Errorf("%s: %s, %q (%s); want %s, %q", what, s.State(), s.Cause(), s.Detail(), state, cause)
	}
	if got := s.Accepted().Length(); got != int64(length) {
		t.Errorf("%s: accepted %d bytes, want %d", what, got, length)
	}
	for i, run := range []string{"run-1", "run-2"} {
		if got := stopsRun(s, "acme", run, clock0); got != runs[i] {
			t.Errorf("%s: Active(%s) = %v, want %v", what, run, got, runs[i])
		}
	}
}

func TestOpenRefusesWhatItCannotServe(t *testing.T) {
	dir := listDir(t, stoppingList(t))
	clock := (&settable{now: clock0}).read
	for _, o := range []Options{
		{Route: testRoute(t), Interval: poll, Clock: clock},
		{Dir: dir, Interval: poll, Clock: clock},
		{Dir: dir, Route: testRoute(t), Clock: clock},
		{Dir: dir, Route: testRoute(t), Interval: -poll, Clock: clock},
		{Dir: dir, Route: testRoute(t), Interval: poll},
	} {
		if p, err := Open(o); !errors.Is(err, ErrOptions) || p != nil {
			t.Errorf("Open(%+v) = %v, %v; want ErrOptions", o, p, err)
		}
	}
	other := lines(must(t)(reaction.Header{ListID: "l", RouteID: "other", RouteSerial: 1,
		RouteDigest: testRoute(t).Digest()}.Marshal()))
	for _, bad := range []string{filepath.Join(t.TempDir(), "absent"), listDir(t, other), listDir(t, nil)} {
		if p, err := Open(Options{Dir: bad, Route: testRoute(t), Interval: poll, Clock: clock}); !errors.Is(err, ErrNotServable) || p != nil {
			t.Errorf("Open over %s = %v, %v; want ErrNotServable", bad, p, err)
		}
	}
	if _, err := Open(Options{Dir: dir, Route: testRoute(t), Interval: poll, Clock: clock}); err != nil {
		t.Errorf("Open over a good list: %v", err)
	}
}

// TestTheAcceptedPrefixOnlyGrowsAcrossPolls: a list that shrinks, is
// rewritten, goes missing or comes back under another header is Unknown, and
// stays Unknown, its accepted prefix kept, until a read extends that prefix
// again; a read that does is served.
func TestTheAcceptedPrefixOnlyGrowsAcrossPolls(t *testing.T) {
	first := stoppingList(t)
	covered := lines(must(t)(reaction.Covered{FindingID: "f-2", TenantID: "acme", RunID: "run-1", CreatedAt: clock0}.Marshal()))
	edited := bytes.Replace(covered, []byte("f-2"), []byte("f-9"), 1)
	second := lines(stopLine(t, "f-3", "run-2", clock0))
	fresh := lines(headerLine(t, testRoute(t), "list-2"), stopLine(t, "f-1", "run-1", clock0))
	grown := append(append(bytes.Clone(first), covered...), second...)
	long := len(first) + len(covered)

	dir := listDir(t, first)
	clock := &settable{now: clock0}
	p := openOn(t, dir, clock, nil)
	expect(t, "the first read", p.Current(), reaction.Stopped, "", len(first), [2]bool{true, false})
	for _, step := range []struct {
		what    string
		content []byte
		state   reaction.State
		cause   reaction.Cause
		length  int
		runs    [2]bool
	}{
		{"a covered line appended", append(bytes.Clone(first), covered...), reaction.Stopped, "", long, [2]bool{true, false}},
		{"truncated to the first read", first, reaction.Unknown, reaction.CauseShrunk, long, [2]bool{}},
		{"truncated, read again", first, reaction.Unknown, reaction.CauseShrunk, long, [2]bool{}},
		{"the appended line edited", append(bytes.Clone(first), edited...), reaction.Unknown, reaction.CauseRewritten, long, [2]bool{}},
		{"extended again", grown, reaction.Stopped, "", len(grown), [2]bool{true, true}},
		{"missing", nil, reaction.Unknown, CauseMissing, len(grown), [2]bool{}},
		{"a list of another header", fresh, reaction.Unknown, reaction.CauseHeader, len(grown), [2]bool{}},
		{"that list grown past the prefix", append(bytes.Clone(fresh), grown[len(first):]...), reaction.Unknown, reaction.CauseHeader, len(grown), [2]bool{}},
		{"the accepted list back", grown, reaction.Stopped, "", len(grown), [2]bool{true, true}},
	} {
		path := filepath.Join(dir, FileName)
		if step.content == nil {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		} else {
			writeList(t, dir, step.content)
		}
		got := p.Poll()
		expect(t, step.what, got, step.state, step.cause, step.length, step.runs)
		if s := p.Current(); s.State() != got.State() || s.Accepted() != got.Accepted() {
			t.Errorf("%s: Current is not the read Poll returned", step.what)
		}
	}
}

// TestATornTailIsLeftOut: a line being written, all of it but its newline,
// stops nothing and is not accepted; with its newline it stops.
func TestATornTailIsLeftOut(t *testing.T) {
	first := stoppingList(t)
	tail := stopLine(t, "f-3", "run-2", clock0)
	dir := listDir(t, append(bytes.Clone(first), tail[:len(tail)/2]...))
	p := openOn(t, dir, &settable{now: clock0}, nil)
	expect(t, "half a line", p.Current(), reaction.Stopped, "", len(first), [2]bool{true, false})
	writeList(t, dir, append(bytes.Clone(first), tail...))
	expect(t, "all but the newline", p.Poll(), reaction.Stopped, "", len(first), [2]bool{true, false})
	appendTo(t, dir, []byte{'\n'})
	expect(t, "the newline", p.Poll(), reaction.Stopped, "", len(first)+len(tail)+1, [2]bool{true, true})
}

// TestAFileRefusalReachesTheSnapshotWithItsCause: a list that turns
// writable by others, then missing, is Unknown with that cause and counted
// under it, keeps the prefix, and is served again once it reads.
func TestAFileRefusalReachesTheSnapshotWithItsCause(t *testing.T) {
	content := stoppingList(t)
	dir := listDir(t, content)
	p := openOn(t, dir, &settable{now: clock0}, nil)
	path := filepath.Join(dir, FileName)
	if err := os.Chmod(path, 0o620); err != nil { //nolint:gosec // G302: a list the checks refuse, on purpose
		t.Fatal(err)
	}
	expect(t, "writable by the group", p.Poll(), reaction.Unknown, CauseMode, len(content), [2]bool{})
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	expect(t, "owner-only again", p.Poll(), reaction.Stopped, "", len(content), [2]bool{true, false})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	expect(t, "missing", p.Poll(), reaction.Unknown, CauseMissing, len(content), [2]bool{})
	st := p.Stats()
	if st.Polls != 4 || st.Failed[CauseMode] != 1 || st.Failed[CauseMissing] != 1 || len(st.Failed) != 2 {
		t.Errorf("Stats = %+v; want 4 polls, one failed as mode and one as missing", st)
	}
}

// TestTheStatsAndTheLogFollowTheEntries: two runs stopped, one lifted, the
// other expired by the clock; the count of active entries and the log name
// each change with its finding id.
func TestTheStatsAndTheLogFollowTheEntries(t *testing.T) {
	r := testRoute(t)
	two := lines(headerLine(t, r, "list-1"), stopLine(t, "f-1", "run-1", clock0), stopLine(t, "f-2", "run-2", clock0))
	dir := listDir(t, two)
	var out bytes.Buffer
	clock := &settable{now: clock0}
	p := openOn(t, dir, clock, slog.New(slog.NewTextHandler(&out, nil)))
	if st := p.Stats(); st.Active != 2 || st.Polls != 1 {
		t.Errorf("two stops: %+v, want 2 active after 1 poll", st)
	}
	appendTo(t, dir, lines(liftLine(t, r, "list-1", "run-1", 2)))
	if s := p.Poll(); s.State() != reaction.Stopped || p.Stats().Active != 1 {
		t.Errorf("run-1 lifted: %s, %+v; want stopped with 1 active", s.State(), p.Stats())
	}
	clock.set(clock0.Add(time.Hour))
	if s := p.Poll(); s.State() != reaction.Clear || p.Stats().Active != 0 {
		t.Errorf("run-2 expired: %s (%s), %+v; want clear with 0 active", s.State(), s.Detail(), p.Stats())
	}
	log := out.String()
	for _, want := range []string{
		`msg="stop active" entry_id=` + reaction.EntryID("f-1") + ` finding_id=f-1 run_id=run-1`,
		`msg="stop active" entry_id=` + reaction.EntryID("f-2") + ` finding_id=f-2 run_id=run-2`,
		`msg="stop ended" entry_id=` + reaction.EntryID("f-1") + ` finding_id=f-1 run_id=run-1 how=lifted`,
		`msg="stop ended" entry_id=` + reaction.EntryID("f-2") + ` finding_id=f-2 run_id=run-2 how=expired`,
		`msg="stop state changed" dir=` + dir + ` state=clear active=0`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("the log lacks %q:\n%s", want, log)
		}
	}
}

// TestANilPollerServesUnknown: a poller nobody opened serves the unknown
// state, counts nothing and only waits when run; a plane with no route is
// handed the gateway's own disabled source, never a poller.
func TestANilPollerServesUnknown(t *testing.T) {
	var none *Poller
	if none.Current().State() != reaction.Unknown || none.Poll().State() != reaction.Unknown {
		t.Errorf("a nil poller serves %s, want unknown", none.Current().State())
	}
	if st := none.Stats(); st.Polls != 0 {
		t.Errorf("a nil poller counted %+v", st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { none.Run(ctx); close(done) }()
	cancel()
	<-done
}

// TestRunPollsUntilItsContextEnds: Run reads at once and on every tick, and
// returns when its context ends.
func TestRunPollsUntilItsContextEnds(t *testing.T) {
	dir := listDir(t, stoppingList(t))
	p, err := Open(Options{Dir: dir, Route: testRoute(t), Interval: 5 * time.Millisecond, Clock: (&settable{now: clock0}).read})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for p.Stats().Polls < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if n := p.Stats().Polls; n < 4 {
		t.Errorf("Run polled %d times in 5s at a 5ms interval", n)
	}
}

// stopsRun reports whether an active entry of s, read with no age rule,
// stops run of tenant at now.
func stopsRun(s reaction.Snapshot, tenant, run string, now time.Time) bool {
	entries, _ := s.ActiveEntries(now, time.Time{})
	return slices.ContainsFunc(entries, func(e reaction.Entry) bool {
		return e.TenantID == tenant && e.Target() == reaction.Target{Scope: reaction.ScopeRun, Subject: run}
	})
}
