package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// mayNotStop is each rule, at a version, a route may not name: rules whose
// finding may not stop a run, an id no rule has, and a rule that may stop at
// a version that is not its own.
var mayNotStop = []struct{ id, version string }{
	{"EXCEPTION_TAKEN", "1"}, {"DENIED_ACTION_RETRIED_AROUND", "1"}, {"REQUIRED_STEP_SKIPPED", "1"},
	{"NO_SUCH_RULE", "1"}, {"REPEATED_DENIAL", "9"}, {"REPEATED_DENIAL", "1"},
}

// supersededRule is the rule version a later one replaced, which only the
// route a list is carried from may name.
var supersededRule = struct{ id, version string }{"REPEATED_DENIAL", "1"}

// mayNotStopRefusal is what a reader of a signed route says, after the flag
// and path that named the route, of rules[i] naming id at version.
func mayNotStopRefusal(i int, id, version string) string {
	return "rules[" + strconv.Itoa(i) + "]: reaction: the route names a rule that may not stop a run: rule_id " +
		strconv.Quote(id) + " rule_version " + strconv.Quote(version)
}

// routeDocNaming is the fixture's route at serial with its first rule,
// REPEATED_DENIAL at version "2", replaced by id at version.
func routeDocNaming(t *testing.T, serial int, id, version string) string {
	t.Helper()
	const first = `"rule_id":"REPEATED_DENIAL","rule_version":"2"`
	doc := routeDoc(seeded(0x4c), serial)
	if !strings.Contains(doc, first) {
		t.Fatalf("the route fixture holds no %s", first)
	}
	return strings.Replace(doc, first, `"rule_id":`+strconv.Quote(id)+`,"rule_version":`+strconv.Quote(version), 1)
}

// listUnder writes, in a fresh owner-only directory of tr named name, a stop
// list of route's header and a stop of run under STEP_OUTSIDE_PROCEDURE, the
// fixture's rule that may stop, written here rather than by the writers,
// which refuse such a route.
func (tr stopTree) listUnder(t *testing.T, name string, route reaction.Route, run string) string {
	t.Helper()
	header, err := reaction.HeaderFor(route, "lst-0123456789abcdef0123456789abcdef").Marshal()
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	stop, err := reaction.Stop{EntryID: reaction.EntryID(fid(90)), TenantID: "acme", RunID: run, FindingID: fid(90),
		ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: stopProcDigest,
		RuleID: outside, RuleVersion: "1", CreatedAt: created, ExpiresAt: created.Add(time.Hour)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	dir := ownerDir(t, filepath.Join(tr.dir, name))
	body := append(append(append(header, '\n'), stop...), '\n')
	if err := os.WriteFile(filepath.Join(dir, stoplist.FileName), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestEveryStopsCommandRefusesARouteNamingARuleThatMayNotStop: a route signed
// with the route key by other means than route sign, naming a rule that may
// not stop a run or a stopping rule at another version, is refused by stops
// init, stops list, stops lift and both sides of a carry, each naming the
// flag and the rule, over a list the judge accepts under that route, and
// nothing is written; the superseded version alone is taken as the route a
// list is carried from. The route naming REPEATED_DENIAL version "2", over a
// list written the same way, is the control: every command takes it.
func TestEveryStopsCommandRefusesARouteNamingARuleThatMayNotStop(t *testing.T) {
	tr := newStopTree(t)
	next := filepath.Join(tr.dir, "next.signed")
	signRouteFile(t, next, routeDoc(seeded(0x4c), 2), seeded(0x52))
	pub := []string{"--public-key", tr.routePub}
	for i, c := range mayNotStop {
		name := "refused-" + strconv.Itoa(i)
		bad := filepath.Join(tr.dir, name+".signed")
		parsed := signRouteFile(t, bad, routeDocNaming(t, 1, c.id, c.version), seeded(0x52))
		list := tr.listUnder(t, name+"-list", parsed, tr.open)
		before := readList(t, list)
		fresh := ownerDir(t, filepath.Join(tr.dir, name+"-fresh"))
		refusal := mayNotStopRefusal(0, c.id, c.version)
		runs := []refusedRun{
			{"stops init", withFlags(pub, "stops", "init", "--route", bad, fresh), "--route " + bad + ": " + refusal},
			{"stops list", withFlags(pub, "stops", "list", "--route", bad, list), "--route " + bad + ": " + refusal},
			{"stops lift", withFlags(pub, "stops", "lift", "--route", bad, "--key", tr.liftKey, "--run", tr.open, list),
				"--route " + bad + ": " + refusal},
			{"a carry from it", withFlags(pub, "stops", "init", "--route", next, "--carry", list, "--carry-route", bad, fresh),
				"--carry-route " + bad + ": " + refusal},
			{"a carry into it", withFlags(pub, "stops", "init", "--route", bad, "--carry", tr.stops, "--carry-route", tr.route, fresh),
				"--route " + bad + ": " + refusal},
		}
		if c == supersededRule {
			runs = slices.DeleteFunc(runs, func(r refusedRun) bool { return r.what == "a carry from it" })
		}
		expectRefused(t, c.id+" "+c.version, runs)
		if !bytes.Equal(readList(t, list), before) {
			t.Errorf("%s %s: a refused route changed the list", c.id, c.version)
		}
		if _, err := os.Lstat(filepath.Join(fresh, stoplist.FileName)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s %s: a refused route started a list: %v", c.id, c.version, err)
		}
	}

	control := tr.listUnder(t, "control-list", tr.parsed, tr.open)
	for _, run := range []struct {
		what string
		args []string
	}{
		{"stops init", withFlags(pub, "stops", "init", "--route", tr.route, ownerDir(t, filepath.Join(tr.dir, "control-fresh")))},
		{"stops list", withFlags(pub, "stops", "list", "--route", tr.route, control)},
		{"a carry from it", withFlags(pub, "stops", "init", "--route", next, "--carry", control, "--carry-route", tr.route,
			ownerDir(t, filepath.Join(tr.dir, "control-carried")))},
		{"stops lift", withFlags(pub, "stops", "lift", "--route", tr.route, "--key", tr.liftKey, "--run", tr.open, control)},
	} {
		if code, stdout, stderr := invoke(t, run.args...); code != exitOK || stderr != "" {
			t.Errorf("the 0.9 route: %s answered %d: %q %q", run.what, code, stdout, stderr)
		}
	}
}

// refusedRun is one command a test expects to refuse with want.
type refusedRun struct {
	what string
	args []string
	want string
}

// expectRefused runs each of runs and expects it to answer 1 with nothing on
// standard output and its want on standard error.
func expectRefused(t *testing.T, label string, runs []refusedRun) {
	t.Helper()
	for _, run := range runs {
		code, stdout, stderr := invoke(t, run.args...)
		if code != exitFail || stdout != "" || !strings.Contains(stderr, run.want) {
			t.Errorf("%s: %s answered %d: %q %q, want 1 and %q", label, run.what, code, stdout, stderr, run.want)
		}
	}
}

// withFlags is the first two of words, then flags, then the rest of words.
func withFlags(flags []string, words ...string) []string {
	return append(append(append([]string{}, words[:2]...), flags...), words[2:]...)
}
