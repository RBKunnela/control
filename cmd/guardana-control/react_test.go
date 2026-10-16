package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/runs"
)

// lineTime is t as a stop list line spells it.
func lineTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

// runEnd is a run's expiry as a stop that lasts to it spells it: rounded up
// to the whole second, so the stop holds through the run's last instant.
func runEnd(t time.Time) string {
	if t.Nanosecond() != 0 {
		t = t.Add(time.Second)
	}
	return lineTime(t)
}

// runExpiry is when run expires, as the runs directory records it.
func (tr stopTree) runExpiry(t *testing.T, run string) time.Time {
	t.Helper()
	plane, err := runs.OpenPlane(tr.runs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plane.Close() }()
	rec, err := plane.Lookup(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	return rec.ExpiresAt
}

func reacted(t *testing.T, code int, stdout, stderr string, want ...string) {
	t.Helper()
	if code != exitOK || stderr != "" {
		t.Fatalf("react answered %d: %q\n%s", code, stderr, stdout)
	}
	if got := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("react printed\n%s\nwant\n%s", stdout, strings.Join(want, "\n"))
	}
}

// TestReactStopsARunOnceAndCoversItsOtherFindings: three confirmed findings
// of one run under one rule give one stop and two covered lines, a finding of
// a second run is that run's own stop, a rule's lifetime ends a stop before
// its run does and a rule with none ends it with its run, and a finding whose
// stop would outlast the run's active one is a stop of its own, never covered
// under the shorter.
func TestReactStopsARunOnceAndCoversItsOtherFindings(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now()
	log := tr.findingsDir(t, "log",
		finding(1, tr.open, denial, confirmed), finding(2, tr.open, denial, confirmed),
		finding(3, tr.open, denial, confirmed), finding(4, tr.second, outside, confirmed),
		finding(5, tr.open, outside, confirmed))
	code, stdout, stderr := tr.react(t, log, now)
	reacted(t, code, stdout, stderr,
		"stop line 2 run "+tr.open+" finding "+fid(1)+" rule REPEATED_DENIAL expires_at "+lineTime(now.Add(600*time.Second)),
		"covered line 3 run "+tr.open+" finding "+fid(2),
		"covered line 4 run "+tr.open+" finding "+fid(3),
		"stop line 5 run "+tr.second+" finding "+fid(4)+" rule STEP_OUTSIDE_PROCEDURE expires_at "+runEnd(tr.runExpiry(t, tr.second)),
		"stop line 6 run "+tr.open+" finding "+fid(5)+" rule STEP_OUTSIDE_PROCEDURE expires_at "+runEnd(tr.runExpiry(t, tr.open)),
		"stops 3, covered 2, already named 0, not stopping 0, not written 0")
	entries := tr.judged(t, now).Entries()
	if len(entries) != 3 || entries[0].RunID != tr.open || entries[1].RunID != tr.second || entries[2].RunID != tr.open {
		t.Fatalf("entries %+v, want a stop of each run and the open run's longer one", entries)
	}
}

// TestAStopNeverOutlivesItsRun: a run that expires in five minutes is
// stopped until then, not for the rule's ten.
func TestAStopNeverOutlivesItsRun(t *testing.T) {
	tr := newStopTree(t)
	short := openRun(t, tr.runs, who, "5m").runID
	now := time.Now()
	code, stdout, stderr := tr.react(t, tr.findingsDir(t, "log", finding(1, short, denial, confirmed)), now)
	reacted(t, code, stdout, stderr,
		"stop line 2 run "+short+" finding "+fid(1)+" rule REPEATED_DENIAL expires_at "+runEnd(tr.runExpiry(t, short)),
		"stops 1, covered 0, already named 0, not stopping 0, not written 0")
}

// TestReactWritesNothingForAFindingThatMayNotStop: each finding below
// fails one condition of a stop and leaves the list as it was; the last
// case, which fails none, writes one.
func TestReactWritesNothingForAFindingThatMayNotStop(t *testing.T) {
	tr := newStopTree(t)
	alienChild := openRun(t, tr.runs, otherTenant, "30m", "--parent", tr.alien).runID
	now := time.Now()
	with := func(f *findingv1alpha1.FindingRecord, change func(*findingv1alpha1.FindingRecord)) *findingv1alpha1.FindingRecord {
		change(f)
		return f
	}
	for _, c := range []struct {
		name string
		f    *findingv1alpha1.FindingRecord
		now  time.Time
	}{
		{"suspected", finding(1, tr.open, denial, controlv1.FindingVerdict_FINDING_VERDICT_SUSPECTED), now},
		{"indeterminate", finding(1, tr.open, denial, controlv1.FindingVerdict_FINDING_VERDICT_INDETERMINATE), now},
		{"a closed run", finding(1, tr.closed, denial, confirmed), now},
		{"an expired run", finding(1, tr.open, denial, confirmed), now.Add(2 * time.Hour)},
		{"an unknown run", finding(1, "run-"+strings.Repeat("f", 32), denial, confirmed), now},
		{"a run id no run has", finding(1, "local-run-7", denial, confirmed), now},
		{"another tenant's run", finding(1, tr.alien, denial, confirmed), now},
		{"another tenant's child run", finding(1, alienChild, denial, confirmed), now},
		{"another tenant", with(finding(1, tr.alien, denial, confirmed), func(f *findingv1alpha1.FindingRecord) { f.TenantId = "globex" }), now},
		{"a procedure digest the route does not list", with(finding(1, tr.open, denial, confirmed), func(f *findingv1alpha1.FindingRecord) {
			f.Procedure.Digest = strings.Repeat("e", 64)
		}), now},
		{"a procedure version the route does not list", with(finding(1, tr.open, denial, confirmed), func(f *findingv1alpha1.FindingRecord) {
			f.Procedure.Version = "2"
		}), now},
		{"a rule the route does not list", finding(1, tr.open, "DEADLINE_EXCEEDED", confirmed), now},
		{"a rule version the route does not list", with(finding(1, tr.open, denial, confirmed), func(f *findingv1alpha1.FindingRecord) {
			f.Finding.RuleVersion = "1"
		}), now},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := tr.listBytes(t)
			code, stdout, stderr := tr.react(t, tr.findingsDir(t, strings.ReplaceAll(c.name, " ", "-"), c.f), c.now)
			reacted(t, code, stdout, stderr, "stops 0, covered 0, already named 0, not stopping 1, not written 0")
			if !bytes.Equal(tr.listBytes(t), before) {
				t.Fatal("the list changed")
			}
		})
	}
	code, stdout, stderr := tr.react(t, tr.findingsDir(t, "control", finding(1, tr.open, denial, confirmed)), now)
	reacted(t, code, stdout, stderr,
		"stop line 2 run "+tr.open+" finding "+fid(1)+" rule REPEATED_DENIAL expires_at "+lineTime(now.Add(600*time.Second)),
		"stops 1, covered 0, already named 0, not stopping 0, not written 0")
}

// TestReactStopsAChild: a child's confirmed finding is a stop of the child
// alone, named by its own run id, not its root's.
func TestReactStopsAChild(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now()
	code, stdout, stderr := tr.react(t, tr.findingsDir(t, "log", finding(1, tr.child, denial, confirmed)), now)
	reacted(t, code, stdout, stderr,
		"stop line 2 run "+tr.child+" finding "+fid(1)+" rule REPEATED_DENIAL expires_at "+lineTime(now.Add(600*time.Second)),
		"stops 1, covered 0, already named 0, not stopping 0, not written 0")
	entries := tr.judged(t, now).Entries()
	if len(entries) != 1 || entries[0].RunID != tr.child {
		t.Fatalf("entries %+v, want one stop of the child %s alone", entries, tr.child)
	}
}

// TestReactRefusesARouteNamingARuleThatMayNotStop: a route signed with the
// route key by other means than route sign, naming a rule that may not stop
// a run, or a stopping rule at another version, beside one that may, is
// refused whole before a finding is read. The log holds a confirmed finding
// of that very rule at that version and the list is one the judge accepts
// under the route, so only the check stands between it and a stop. The
// route naming REPEATED_DENIAL version "2" is the control: it writes the
// stop.
func TestReactRefusesARouteNamingARuleThatMayNotStop(t *testing.T) {
	tr := newStopTree(t)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed))
	findingOf := func(n int, id, version string) *findingv1alpha1.FindingRecord {
		f := finding(n, tr.open, id, confirmed)
		f.Finding.RuleVersion = version
		return f
	}
	lift := base64.StdEncoding.EncodeToString(seeded(0x4c).Public().(ed25519.PublicKey))
	rule := func(id, version string) string {
		return `{"procedure_id":"refund","version":"1","digest":"` + stopProcDigest + `","rule_id":"` + id +
			`","rule_version":"` + version + `"}`
	}
	doc := func(rules ...string) string {
		return `{"kind":"reaction-route/v1alpha1","route_id":"direct","serial":1,"tenant_id":"acme","scope":"run",` +
			`"lift_public_key":"` + lift + `","rules":[` + strings.Join(rules, ",") + `]}`
	}
	setUp := func(name, body string) reactArgs {
		route := filepath.Join(tr.dir, name+".signed")
		parsed := signRouteFile(t, route, body, seeded(0x52))
		a := tr.reactArgs(log)
		a.route, a.stops = route, tr.listUnder(t, "stops-"+name, parsed, tr.second)
		return a
	}
	for i, c := range mayNotStop {
		a := setUp("refused-"+strconv.Itoa(i), doc(rule(outside, "1"), rule(c.id, c.version)))
		own := tr.findingsDir(t, "log-"+strconv.Itoa(i), findingOf(10+i, c.id, c.version))
		for _, findings := range []string{own, filepath.Join(tr.dir, "no-findings-here")} {
			a.findings = findings
			before := readList(t, a.stops)
			var out, errOut bytes.Buffer
			code := react(context.Background(), a, time.Now, &out, &errOut)
			want := "react: --route " + a.route + ": " + mayNotStopRefusal(1, c.id, c.version)
			if code != exitFail || out.Len() != 0 || !strings.Contains(errOut.String(), want) {
				t.Errorf("%s %s over %s: react answered %d: %q %q, want 1 and %q", c.id, c.version, findings, code, out.String(), errOut.String(), want)
			}
			if !bytes.Equal(readList(t, a.stops), before) {
				t.Errorf("%s %s: a refused route changed the list", c.id, c.version)
			}
		}
	}
	a := setUp("control", doc(rule(outside, "1"), rule(denial, "2")))
	var out, errOut bytes.Buffer
	if code := react(context.Background(), a, time.Now, &out, &errOut); code != exitOK || !strings.HasPrefix(out.String(), "stop line 3 run "+tr.open+" ") {
		t.Fatalf("the control route: react answered %d: %q %q", code, out.String(), errOut.String())
	}
}

// readList is the stop list in dir as it stands.
func readList(t *testing.T, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, stoplist.FileName)) //nolint:gosec // G304: a file of the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestAModelsOrAnUnknownFindingStopsNothing: the findings log holds no such
// finding, so the pass is given one directly; the same finding as a
// deterministic CONFIRMED one is the control that writes.
func TestAModelsOrAnUnknownFindingStopsNothing(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	plane, err := runs.OpenPlane(tr.runs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plane.Close() }()
	pass := func(change func(*controlv1.Finding)) *reactor {
		f := finding(1, tr.open, denial, confirmed)
		change(f.Finding)
		r := newReactor(context.Background(), tr.parsed, tr.judged(t, now), plane.Lookup, tr.stops, clockAt(now))
		if err := r.each([]*findingv1alpha1.Record{{Record: &findingv1alpha1.Record_FindingRecord{FindingRecord: f}}}); err != nil {
			t.Fatal(err)
		}
		return r
	}
	for name, change := range map[string]func(*controlv1.Finding){
		"a model's":              func(f *controlv1.Finding) { f.Source = controlv1.FindingSource_FINDING_SOURCE_MODEL },
		"an unspecified source":  func(f *controlv1.Finding) { f.Source = 0 },
		"an unknown source":      func(f *controlv1.Finding) { f.Source = 99 },
		"an unspecified verdict": func(f *controlv1.Finding) { f.Verdict = 0 },
		"an unknown verdict":     func(f *controlv1.Finding) { f.Verdict = 99 },
	} {
		if r := pass(change); r.skipped != 1 || r.stops+r.covered != 0 {
			t.Errorf("%s finding: %d skipped, %d stops, %d covered", name, r.skipped, r.stops, r.covered)
		}
	}
	if r := pass(func(*controlv1.Finding) {}); r.stops != 1 {
		t.Fatalf("the control wrote %d stops: %q", r.stops, r.unwritten)
	}
}

// TestALiftHoldsAndOnlyANewFindingStopsAgain: what a stopped run does is
// covered; after a lift the same findings write nothing, and a finding the
// list has not seen stops the run again.
func TestALiftHoldsAndOnlyANewFindingStopsAgain(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now()
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed))
	code, stdout, stderr := tr.react(t, log, now)
	reacted(t, code, stdout, stderr,
		"stop line 2 run "+tr.open+" finding "+fid(1)+" rule REPEATED_DENIAL expires_at "+lineTime(now.Add(600*time.Second)),
		"stops 1, covered 0, already named 0, not stopping 0, not written 0")

	appendLog(t, log, finding(2, tr.open, denial, confirmed), finding(3, tr.open, denial, confirmed),
		finding(4, tr.open, denial, confirmed))
	code, stdout, stderr = tr.react(t, log, now)
	reacted(t, code, stdout, stderr,
		"covered line 3 run "+tr.open+" finding "+fid(2),
		"covered line 4 run "+tr.open+" finding "+fid(3),
		"covered line 5 run "+tr.open+" finding "+fid(4),
		"stops 0, covered 3, already named 1, not stopping 0, not written 0")

	lift := append(append([]string{"stops", "lift"}, tr.routeArgs()...), "--key", tr.liftKey, "--run", tr.open, tr.stops)
	if code, stdout, stderr := invoke(t, lift...); code != exitOK || stdout != "lift line 6 run "+tr.open+" through line 5\n" {
		t.Fatalf("stops lift answered %d: %q %q", code, stdout, stderr)
	}
	if entries := tr.judged(t, now).Entries(); len(entries) != 0 {
		t.Fatalf("after the lift the list holds %+v", entries)
	}
	before := tr.listBytes(t)
	code, stdout, stderr = tr.react(t, log, now)
	reacted(t, code, stdout, stderr, "stops 0, covered 0, already named 4, not stopping 0, not written 0")
	if !bytes.Equal(tr.listBytes(t), before) {
		t.Fatal("react over the same findings changed the list")
	}

	appendLog(t, log, finding(5, tr.open, outside, confirmed))
	code, stdout, stderr = tr.react(t, log, now)
	reacted(t, code, stdout, stderr,
		"stop line 7 run "+tr.open+" finding "+fid(5)+" rule STEP_OUTSIDE_PROCEDURE expires_at "+runEnd(tr.runExpiry(t, tr.open)),
		"stops 1, covered 0, already named 4, not stopping 0, not written 0")
}

// TestReactRefusesARouteItCannotTrust: a route signed by another key, and a
// route that verifies but is not the one the list's header names, are
// refused before anything is written.
func TestReactRefusesARouteItCannotTrust(t *testing.T) {
	tr := newStopTree(t)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed))
	forged := tr.dir + "/forged.signed"
	signRouteFile(t, forged, routeDoc(seeded(0x4c), 1), seeded(0x58))
	next := tr.dir + "/next.signed"
	signRouteFile(t, next, routeDoc(seeded(0x4c), 2), seeded(0x52))
	before := tr.listBytes(t)
	for route, want := range map[string]string{forged: "--route " + forged + ": reaction:", next: "unknown (another route)"} {
		a := tr.reactArgs(log)
		a.route = route
		var out, errOut bytes.Buffer
		if code := react(context.Background(), a, time.Now, &out, &errOut); code != exitFail || out.Len() != 0 || !strings.Contains(errOut.String(), want) {
			t.Errorf("react with %s answered %d: %q %q, want 1 and %q", route, code, out.String(), errOut.String(), want)
		}
	}
	if !bytes.Equal(tr.listBytes(t), before) {
		t.Fatal("a refused route changed the list")
	}
}

// TestAPassStopsAtARunItCannotLookUp: a runs directory that fails a lookup
// for a reason other than there being no such run is no zero run.
func TestAPassStopsAtARunItCannotLookUp(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	broken := errors.New("unreadable")
	r := newReactor(context.Background(), tr.parsed, tr.judged(t, now),
		func(context.Context, string) (runs.Record, error) { return runs.Record{}, broken }, tr.stops, clockAt(now))
	f := finding(1, tr.open, denial, confirmed)
	if err := r.each([]*findingv1alpha1.Record{{Record: &findingv1alpha1.Record_FindingRecord{FindingRecord: f}}}); !errors.Is(err, broken) {
		t.Fatalf("each = %v, want the lookup's error", err)
	}
}

// TestReactReadsTheRunsAndTheFindingsAndWritesNeither: every file of the
// runs directory and of the findings log keeps its bytes, mode and time, and
// neither directory gains or loses a file, while the stop list grows.
func TestReactReadsTheRunsAndTheFindingsAndWritesNeither(t *testing.T) {
	tr := newStopTree(t)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.second, outside, confirmed))
	runsBefore, logBefore, listBefore := treeState(t, tr.runs), treeState(t, log), tr.listBytes(t)
	if code, stdout, stderr := tr.react(t, log, time.Now()); code != exitOK {
		t.Fatalf("react answered %d: %q %q", code, stdout, stderr)
	}
	if bytes.Equal(tr.listBytes(t), listBefore) {
		t.Fatal("react wrote nothing; the case examined no write")
	}
	for name, c := range map[string][2]map[string]string{
		"--runs":     {runsBefore, treeState(t, tr.runs)},
		"--findings": {logBefore, treeState(t, log)},
	} {
		if !maps.Equal(c[0], c[1]) {
			t.Errorf("react changed %s: %v, now %v", name, c[0], c[1])
		}
	}
}

// treeState is each file under dir by its path, with its bytes, mode and
// modification time.
func treeState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		body := ""
		if d.Type().IsRegular() {
			raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
			if err != nil {
				return err
			}
			body = string(raw)
		}
		out[path] = fmt.Sprintf("%v %v %q", info.Mode(), info.ModTime().UnixNano(), body)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAFindingAnotherReactNamedIsAlreadyNamed: a react that read the list
// before another wrote a finding's line takes the writer's refusal of that
// finding as already named, not as a line it could not write.
func TestAFindingAnotherReactNamedIsAlreadyNamed(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	stale := tr.judged(t, now)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed))
	if code, stdout, stderr := tr.react(t, log, now); code != exitOK {
		t.Fatalf("the other react answered %d: %q %q", code, stdout, stderr)
	}
	records, err := findinglog.ReadFile(filepath.Join(log, findinglog.FileName))
	if err != nil {
		t.Fatal(err)
	}
	plane, err := runs.OpenPlane(tr.runs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plane.Close() }()
	r := newReactor(context.Background(), tr.parsed, stale, plane.Lookup, tr.stops, clockAt(now))
	if err := r.each(records); err != nil || r.alreadyNamed != 1 || r.stops+r.covered != 0 || len(r.unwritten) != 0 {
		t.Errorf("the late react: %v, %d already named, %d stops, %d covered, unwritten %q; want the finding already named",
			err, r.alreadyNamed, r.stops, r.covered, r.unwritten)
	}
}
