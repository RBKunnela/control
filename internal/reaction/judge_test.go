package reaction_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

func TestJudgeAcceptsAList(t *testing.T) {
	b := newList(t, listRoute(t))
	b.stop("fnd-a1", "run-a", clock0.Add(-time.Minute), time.Hour)
	b.covered("fnd-a2", "run-a", clock0)
	b.stop("fnd-b1", "run-b", clock0, 30*time.Minute)
	content := b.bytes()
	l := mustJudge(t, content)
	if got := entryRuns(l.Entries()); got != "run-a@2,run-b@4" {
		t.Errorf("entries %s, want run-a@2,run-b@4", got)
	}
	h := l.Header()
	if h.ListID != "list-1" || h.RouteID != "refunds" || h.RouteSerial != 3 || h.RouteDigest != listRoute(t).Digest() {
		t.Errorf("header %+v", h)
	}
	if u := l.Usage(); u.Lines != 4 || u.Bytes != int64(len(content)) {
		t.Errorf("usage %+v, want 4 lines and %d bytes", u, len(content))
	}
	for _, f := range []string{"fnd-a1", "fnd-a2", "fnd-b1"} {
		if !l.Names(f) {
			t.Errorf("the list does not name %s", f)
		}
	}
	if l.Names("fnd-c1") {
		t.Error("the list names a finding no line holds")
	}
	es := l.Entries()
	es[0].RunID = "run-z"
	if entryRuns(l.Entries()) != "run-a@2,run-b@4" {
		t.Error("Entries hands out the list's own slice")
	}
}

// TestJudgeLeavesTheTornTailOut: bytes after the last newline are a line
// being written; they change neither the entries nor the prefix.
func TestJudgeLeavesTheTornTailOut(t *testing.T) {
	b := newList(t, listRoute(t))
	b.stop("fnd-a1", "run-a", clock0, time.Hour)
	whole := b.bytes()
	torn := append(bytes.Clone(whole), []byte(`{"kind":"stop","garbage`)...)
	l := mustJudge(t, torn)
	if l.Prefix().Length() != int64(len(whole)) || entryRuns(l.Entries()) != "run-a@2" {
		t.Fatalf("prefix %d, entries %s; want %d and run-a@2", l.Prefix().Length(), entryRuns(l.Entries()), len(whole))
	}
	if l.Prefix() != mustJudge(t, whole).Prefix() {
		t.Fatal("the torn tail changed the prefix")
	}
}

type judgeCase struct {
	name    string
	content []byte
	want    error
}

func TestJudgeRefusesALineOutOfPlace(t *testing.T) {
	r := listRoute(t)
	header := string(newList(t, r).bytes())
	stop := func(finding, run string) string {
		raw, err := stopOf(t, finding, run, clock0, time.Hour).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return string(raw) + "\n"
	}
	covered := func(finding, run, tenant string) string {
		raw, err := reaction.Covered{FindingID: finding, TenantID: tenant, RunID: run, CreatedAt: clock0}.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return string(raw) + "\n"
	}
	other := func(edit func(*reaction.Header)) string {
		h := reaction.HeaderFor(r, "list-1")
		edit(&h)
		raw, err := h.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return string(raw) + "\n"
	}
	for _, c := range []judgeCase{
		{"an empty list", nil, reaction.ErrHeaderPlace},
		{"a header with no newline", bytes.TrimSuffix([]byte(header), []byte("\n")), reaction.ErrHeaderPlace},
		{"a stop before the header", []byte(stop("fnd-1", "run-a") + header), reaction.ErrHeaderPlace},
		{"two headers", []byte(header + header), reaction.ErrHeaderPlace},
		{"a header later", []byte(header + stop("fnd-1", "run-a") + header), reaction.ErrHeaderPlace},
		{"an empty line", []byte(header + "\n"), reaction.ErrLineJSON},
		{"another route id", []byte(other(func(h *reaction.Header) { h.RouteID = "returns" })), reaction.ErrListRoute},
		{"another serial", []byte(other(func(h *reaction.Header) { h.RouteSerial = 4 })), reaction.ErrListRoute},
		{"another route digest", []byte(other(func(h *reaction.Header) { h.RouteDigest = "sha256:" + bareDigest })), reaction.ErrListRoute},
		{"a finding stopped twice", []byte(header + stop("fnd-1", "run-a") + stop("fnd-1", "run-b")), reaction.ErrFindingAgain},
		{"a stop's finding covered", []byte(header + stop("fnd-1", "run-a") + covered("fnd-1", "run-a", "acme")), reaction.ErrFindingAgain},
		{"a finding covered twice", []byte(header + stop("fnd-1", "run-a") + covered("fnd-2", "run-a", "acme") + covered("fnd-2", "run-a", "acme")), reaction.ErrFindingAgain},
		{"a covered run of another tenant", []byte(header + stop("fnd-1", "run-a") + covered("fnd-2", "run-a", "other")), reaction.ErrCoveredRun},
		{"a covered run of another tenant and no stop", []byte(header + covered("fnd-2", "run-b", "other")), reaction.ErrCoveredRun},
		{"a stop with another finding's entry id", []byte(header + strings.Replace(stop("fnd-1", "run-a"), reaction.EntryID("fnd-1"), reaction.EntryID("fnd-2"), 1)), reaction.ErrEntryID},
	} {
		_, err := judge(t, c.content)
		expectOnly(t, c.name, err, c.want, judgeRefusals())
	}
}

func TestJudgeHoldsEveryStopToTheRoute(t *testing.T) {
	r := listRoute(t)
	for _, tc := range []struct {
		name string
		edit func(*reaction.Stop)
	}{
		{"another tenant", func(s *reaction.Stop) { s.TenantID = "other" }},
		{"another rule", func(s *reaction.Stop) { s.RuleID = "REPEATED_DENIAL" }},
		{"another rule version", func(s *reaction.Stop) { s.RuleVersion = "2" }},
		{"another procedure version", func(s *reaction.Stop) { s.ProcedureVersion = "2" }},
		{"another procedure digest", func(s *reaction.Stop) { s.ProcedureDigest = bareDigest }},
		{"a second past the rule's lifetime", func(s *reaction.Stop) { s.ExpiresAt = s.CreatedAt.Add(time.Hour + time.Second) }},
		{"an expiry at its creation", func(s *reaction.Stop) { s.ExpiresAt = s.CreatedAt }},
	} {
		b := newList(t, r)
		s := stopOf(t, "fnd-1", "run-a", clock0, time.Hour)
		tc.edit(&s)
		b.add(s.Marshal())
		_, err := judge(t, b.bytes())
		expectOnly(t, tc.name, err, reaction.ErrStopRefused, judgeRefusals())
	}
	b := newList(t, r)
	b.stop("fnd-1", "run-a", clock0, time.Hour)
	unbounded := stopOf(t, "fnd-2", "run-b", clock0, 720*time.Hour)
	unbounded.RuleID = "DEADLINE_EXCEEDED"
	b.add(unbounded.Marshal())
	if _, err := judge(t, b.bytes()); err != nil {
		t.Fatalf("a stop of the rule's whole lifetime and one of a rule with none: %v", err)
	}
}

// TestJudgeHoldsCreatedAtToTheClock: a created_at at the plane's clock plus
// one poll interval is taken, one second later is not, and a far-future one
// whose expiry is within its rule's lifetime is refused all the same.
func TestJudgeHoldsCreatedAtToTheClock(t *testing.T) {
	r := listRoute(t)
	for _, tc := range []struct {
		name    string
		created time.Time
		covered bool
		want    error
	}{
		{"a stop at the tolerance", clock0.Add(poll), false, nil},
		{"a stop a second past it", clock0.Add(poll + time.Second), false, reaction.ErrDatedAhead},
		{"a covered line at the tolerance", clock0.Add(poll), true, nil},
		{"a covered line a second past it", clock0.Add(poll + time.Second), true, reaction.ErrDatedAhead},
		{"a stop four years ahead lasting an hour", clock0.AddDate(4, 0, 0), false, reaction.ErrDatedAhead},
	} {
		b := newList(t, r)
		if tc.covered {
			b.stop("fnd-1", "run-a", clock0, time.Hour)
			b.covered("fnd-2", "run-a", tc.created)
		} else {
			b.stop("fnd-1", "run-a", tc.created, time.Hour)
		}
		_, err := judge(t, b.bytes())
		if tc.want == nil {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		expectOnly(t, tc.name, err, tc.want, judgeRefusals())
	}
}

func TestJudgeRefusesWhatItCannotJudge(t *testing.T) {
	content := newList(t, listRoute(t)).bytes()
	for _, tc := range []struct {
		name      string
		route     reaction.Route
		now       time.Time
		tolerance time.Duration
		want      error
	}{
		{"the zero route", reaction.Route{}, clock0, poll, reaction.ErrListRoute},
		{"the zero clock", listRoute(t), time.Time{}, poll, reaction.ErrJudgeClock},
		{"a clock past 9999", listRoute(t), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), poll, reaction.ErrJudgeClock},
		{"a negative tolerance", listRoute(t), clock0, -time.Nanosecond, reaction.ErrJudgeClock},
	} {
		_, err := reaction.Judge(tc.route, reaction.Prefix{}, content, tc.now, tc.tolerance)
		expectOnly(t, tc.name, err, tc.want, judgeRefusals())
	}
	if _, err := reaction.Judge(listRoute(t), reaction.Prefix{}, content, clock0, 0); err != nil {
		t.Fatalf("a tolerance of zero: %v", err)
	}
}

func TestLiftsEndARunsStopsThroughTheirLine(t *testing.T) {
	b := newList(t, listRoute(t))
	b.stop("fnd-a1", "run-a", clock0, time.Hour) // 2
	b.stop("fnd-b1", "run-b", clock0, time.Hour) // 3
	b.lift("run-a", 3)                           // 4: ends run-a@2, not run-b@3
	b.stop("fnd-a2", "run-a", clock0, time.Hour) // 5: a new finding after the lift
	b.covered("fnd-a3", "run-a", clock0)         // 6
	b.lift("run-a", 4)                           // 7: ends nothing new
	b.lift("run-b", 1)                           // 8: through the header, ends nothing
	if got := entryRuns(mustJudge(t, b.bytes()).Entries()); got != "run-b@3,run-a@5" {
		t.Fatalf("entries %s, want run-b@3,run-a@5", got)
	}
	b.lift("run-a", 5) // 9
	b.lift("run-a", 2) // 10: a lower line revives nothing
	if got := entryRuns(mustJudge(t, b.bytes()).Entries()); got != "run-b@3" {
		t.Fatalf("entries %s, want run-b@3", got)
	}
}

func TestJudgeRefusesALiftThatIsNotTheListsOwn(t *testing.T) {
	r := listRoute(t)
	signedFor := func(key []byte, list, digest, run string, line, signedLine int64) []byte {
		b := newList(t, r)
		b.stop("fnd-a1", "run-a", clock0, time.Hour)
		b.stop("fnd-a2", "run-a", clock0, time.Hour)
		b.add(liftLineOf(t, key, list, digest, run, line, signedLine).Marshal())
		return b.bytes()
	}
	tamper := func(old, repl string) []byte {
		c := signedFor(liftKey(), "list-1", r.Digest(), "run-a", 2, 2)
		edited := bytes.Replace(c, []byte(old), []byte(repl), 1)
		if bytes.Equal(edited, c) {
			t.Fatalf("%q is not in the list", old)
		}
		return edited
	}
	twice := newList(t, r)
	twice.stop("fnd-a1", "run-a", clock0, time.Hour)
	twice.lift("run-a", 2)
	twice.lift("run-a", 2)
	for _, c := range []judgeCase{
		{"through its own line", signedFor(liftKey(), "list-1", r.Digest(), "run-a", 4, 4), reaction.ErrLiftOrder},
		{"through a later line", signedFor(liftKey(), "list-1", r.Digest(), "run-a", 5, 5), reaction.ErrLiftOrder},
		{"a run and line lifted before", twice.bytes(), reaction.ErrLiftAgain},
		{"under the route key", signedFor(routeKey(), "list-1", r.Digest(), "run-a", 2, 2), reaction.ErrLiftUnsigned},
		{"unsigned", stripSignatures(t, signedFor(liftKey(), "list-1", r.Digest(), "run-a", 2, 2)), reaction.ErrLiftUnsigned},
		{"under the route's payload type", tamper(`"payloadType":"application/vnd.agent-reaction-lift+json"`, `"payloadType":"application/vnd.agent-reaction-route+json"`), reaction.ErrLiftUnsigned},
		{"of another list", signedFor(liftKey(), "list-2", r.Digest(), "run-a", 2, 2), reaction.ErrLiftMismatch},
		{"of another route", signedFor(liftKey(), "list-1", "sha256:"+bareDigest, "run-a", 2, 2), reaction.ErrLiftMismatch},
		{"signed for another run", tamper(`"run_id":"run-a","through_line":2`, `"run_id":"run-b","through_line":2`), reaction.ErrLiftMismatch},
		{"signed for another line", signedFor(liftKey(), "list-1", r.Digest(), "run-a", 3, 2), reaction.ErrLiftMismatch},
	} {
		_, err := judge(t, c.content)
		expectOnly(t, c.name, err, c.want, judgeRefusals())
	}
}

// stripSignatures empties the signature list of the last line's envelope.
func stripSignatures(t *testing.T, content []byte) []byte {
	t.Helper()
	start := bytes.Index(content, []byte(`"signatures":[`))
	end := bytes.Index(content[start:], []byte(`]`))
	if start < 0 || end < 0 {
		t.Fatal("no signatures")
	}
	return slicesConcat(content[:start], []byte(`"signatures":[]`), content[start+end+1:])
}

func slicesConcat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestVerifyLiftLineTiesTheLiftToItsList(t *testing.T) {
	r := listRoute(t)
	h := reaction.HeaderFor(r, "list-1")
	line := liftLineOf(t, liftKey(), "list-1", r.Digest(), "run-a", 2, 2)
	if l, err := reaction.VerifyLiftLine(line, h, r); err != nil || l.RunID != "run-a" || l.ThroughLine != 2 {
		t.Fatalf("VerifyLiftLine = %+v, %v", l, err)
	}
	otherHeader := h
	otherHeader.ListID = "list-2"
	staleHeader := h
	staleHeader.RouteDigest = "sha256:" + bareDigest
	staleLine := liftLineOf(t, liftKey(), "list-1", staleHeader.RouteDigest, "run-a", 2, 2)
	for _, tc := range []struct {
		name string
		line reaction.LiftLine
		h    reaction.Header
		r    reaction.Route
		want error
	}{
		{"another list's header", line, otherHeader, r, reaction.ErrLiftMismatch},
		{"a header and lift of another route than the plane's", staleLine, staleHeader, r, reaction.ErrLiftMismatch},
		{"the zero route", line, h, reaction.Route{}, reaction.ErrListRoute},
	} {
		_, err := reaction.VerifyLiftLine(tc.line, tc.h, tc.r)
		expectOnly(t, tc.name, err, tc.want, judgeRefusals())
	}
}

// TestACoveredLineNamesAnyRunAndStopsNothing: a covered line is a finding the
// list names and will not stop again. It may name a run no stop names, one
// whose stops were lifted, or one stopped only later, and it stops none.
func TestACoveredLineNamesAnyRunAndStopsNothing(t *testing.T) {
	r := listRoute(t)
	b := newList(t, r)
	b.covered("fnd-b1", "run-b", clock0)         // 2: no stop of run-b anywhere
	b.covered("fnd-a0", "run-a", clock0)         // 3: before run-a's stop
	b.stop("fnd-a1", "run-a", clock0, time.Hour) // 4
	b.lift("run-a", 4)                           // 5
	b.covered("fnd-a2", "run-a", clock0)         // 6: after the lift
	b.stop("fnd-c1", "run-c", clock0, time.Hour) // 7
	l := mustJudge(t, b.bytes())
	if got := entryRuns(l.Entries()); got != "run-c@7" {
		t.Fatalf("entries %s, want run-c@7", got)
	}
	for _, f := range []string{"fnd-b1", "fnd-a0", "fnd-a2"} {
		if !l.Names(f) {
			t.Errorf("the list does not name %s", f)
		}
	}
	s := reaction.Snapshot{}.Next(r, b.bytes(), clock0, poll)
	for _, run := range []string{"run-a", "run-b"} {
		if got, cause, _ := s.ForSubject(reaction.Subject{Tenant: "acme", Run: run}, clock0, clock0); got != reaction.Clear || cause != "" {
			t.Errorf("a call of %s: %s %q, want clear", run, got, cause)
		}
	}
}
