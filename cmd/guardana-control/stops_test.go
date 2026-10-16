package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

var listIDShape = regexp.MustCompile(`^list_id: lst-[0-9a-f]{32}$`)

func (tr stopTree) stopsRun(t *testing.T, words string, args ...string) (int, string, string) {
	t.Helper()
	return invoke(t, append(append(strings.Fields(words), tr.routeArgs()...), args...)...)
}

func TestStopsInitStartsAListUnderTheRoute(t *testing.T) {
	tr := newStopTree(t)
	dir := ownerDir(t, filepath.Join(tr.dir, "fresh"))
	code, stdout, stderr := tr.stopsRun(t, "stops init", dir)
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if code != exitOK || stderr != "" || len(lines) != 4 || !listIDShape.MatchString(lines[0]) ||
		strings.Join(lines[1:], "\n") != "route_id: refund-stops\nroute_serial: 1\nroute_digest: "+tr.parsed.Digest() {
		t.Fatalf("stops init answered %d: %q\n%s", code, stderr, stdout)
	}
	raw, err := stoplist.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	list, err := reaction.Judge(tr.parsed, reaction.Prefix{}, raw, time.Now(), 0)
	if err != nil || "list_id: "+list.Header().ListID != lines[0] {
		t.Fatalf("the list started is %q: %v", list.Header().ListID, err)
	}
	if code, _, stderr := tr.stopsRun(t, "stops init", dir); code != exitFail || !strings.Contains(stderr, "exists already") {
		t.Fatalf("a second init answered %d: %q", code, stderr)
	}
}

// TestStopsRefuseARouteTheyCannotTrust: a route signed by another key and a
// route the list's header does not name are refused by every stops command,
// which then writes nothing.
func TestStopsRefuseARouteTheyCannotTrust(t *testing.T) {
	tr := newStopTree(t)
	forged := filepath.Join(tr.dir, "forged.signed")
	signRouteFile(t, forged, routeDoc(seeded(0x4c), 1), seeded(0x58))
	next := filepath.Join(tr.dir, "next.signed")
	signRouteFile(t, next, routeDoc(seeded(0x4c), 2), seeded(0x52))
	fresh := ownerDir(t, filepath.Join(tr.dir, "fresh"))
	before := tr.listBytes(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"stops", "init", "--route", forged, "--public-key", tr.routePub, fresh}, "--route " + forged},
		{[]string{"stops", "init", "--route", next, "--public-key", tr.routePub, "--carry", tr.stops, "--carry-route", forged, fresh},
			"--carry-route " + forged},
		{[]string{"stops", "init", "--route", next, "--public-key", tr.routePub, "--carry", tr.stops, "--carry-route", next, fresh},
			"another route"},
		{[]string{"stops", "list", "--route", forged, "--public-key", tr.routePub, tr.stops}, "--route " + forged},
		{[]string{"stops", "list", "--route", next, "--public-key", tr.routePub, tr.stops}, "unknown (another route)"},
		{[]string{"stops", "lift", "--route", forged, "--public-key", tr.routePub, "--key", tr.liftKey, "--run", tr.open, tr.stops},
			"--route " + forged},
		{[]string{"stops", "lift", "--route", next, "--public-key", tr.routePub, "--key", tr.liftKey, "--run", tr.open, tr.stops},
			"unknown (another route)"},
	} {
		code, stdout, stderr := invoke(t, c.args...)
		if code != exitFail || stdout != "" || !strings.Contains(stderr, c.want) {
			t.Errorf("%q answered %d: %q %q, want 1 and %q", c.args[:2], code, stdout, stderr, c.want)
		}
	}
	if !bytes.Equal(tr.listBytes(t), before) {
		t.Fatal("a refused route changed the list")
	}
	if _, err := os.Lstat(filepath.Join(fresh, stoplist.FileName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused route started a list: %v", err)
	}
}

// TestALiftUnderAnotherKeyIsRefusedBeforeAWrite: the route key and a key the
// route does not name sign no lift, and the list is left as it was.
func TestALiftUnderAnotherKeyIsRefusedBeforeAWrite(t *testing.T) {
	tr := newStopTree(t)
	code, stdout, stderr := tr.react(t, tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed)), time.Now())
	if code != exitOK {
		t.Fatalf("react answered %d: %q %q", code, stdout, stderr)
	}
	stray := filepath.Join(tr.dir, "stray")
	if code, _, stderr := invoke(t, "policy", "keygen", "--out", stray); code != exitOK {
		t.Fatalf("keygen answered %d: %q", code, stderr)
	}
	before := tr.listBytes(t)
	for _, key := range []string{tr.routeKey, filepath.Join(stray, policykey.PrivateFile)} {
		code, stdout, stderr := tr.stopsRun(t, "stops lift", "--key", key, "--run", tr.open, tr.stops)
		if code != exitFail || stdout != "" || !strings.Contains(stderr, "--key: its public half is not the route's lift_public_key") {
			t.Errorf("a lift under %s answered %d: %q %q", key, code, stdout, stderr)
		}
	}
	if !bytes.Equal(tr.listBytes(t), before) {
		t.Fatal("a refused lift changed the list")
	}
}

// TestALiftEndsTheStopsThroughItsLine: a --through of zero or below is a
// usage error, never the widest lift; a lift that would end no stop of its
// run, through the header, of a run the list does not stop, or of a run whose
// stops were lifted already, is refused and writes nothing; a lift through a
// stop's line, or the default, the list's last line, ends that run's stops
// and no other run's.
func TestALiftEndsTheStopsThroughItsLine(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now()
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.second, denial, confirmed))
	if code, stdout, stderr := tr.react(t, log, now); code != exitOK {
		t.Fatalf("react answered %d: %q %q", code, stdout, stderr)
	}
	runsOf := func() []string {
		var out []string
		for _, e := range tr.judged(t, time.Now()).Entries() {
			out = append(out, e.RunID)
		}
		return out
	}
	for _, c := range []struct {
		run, through string
		code         int
		line         string
		want         []string
	}{
		{tr.open, "0", exitUsage, "", []string{tr.open, tr.second}},
		{tr.open, "-1", exitUsage, "", []string{tr.open, tr.second}},
		{tr.open, "1", exitFail, "", []string{tr.open, tr.second}},
		{"run-ffffffffffffffffffffffffffffffff", "", exitFail, "", []string{tr.open, tr.second}},
		{tr.open, "2", exitOK, "lift line 4 run " + tr.open + " through line 2", []string{tr.second}},
		{tr.open, "", exitFail, "", []string{tr.second}},
		{tr.second, "", exitOK, "lift line 5 run " + tr.second + " through line 4", nil},
	} {
		args := []string{"--key", tr.liftKey, "--run", c.run}
		if c.through != "" {
			args = append(args, "--through", c.through)
		}
		before := tr.listBytes(t)
		code, stdout, stderr := tr.stopsRun(t, "stops lift", append(args, tr.stops)...)
		switch {
		case code != c.code:
			t.Fatalf("stops lift --run %s --through %q answered %d: %q %q, want %d", c.run, c.through, code, stdout, stderr, c.code)
		case code == exitOK && stdout != c.line+"\n":
			t.Fatalf("stops lift answered %q, want %q", stdout, c.line)
		case code != exitOK && !bytes.Equal(tr.listBytes(t), before):
			t.Fatalf("a refused lift --run %s --through %q changed the list", c.run, c.through)
		}
		if got := runsOf(); strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Fatalf("after --run %s --through %q the stopped runs are %q, want %q", c.run, c.through, got, c.want)
		}
	}
}

// TestStopsCarryBringsNoOldFindingBack: a carried list keeps the stop no
// lift ended and names every other finding as covered, so react over the
// same log writes nothing, a new finding of the lifted run stops it and one
// of the run still stopped is covered.
func TestStopsCarryBringsNoOldFindingBack(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now()
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.open, outside, confirmed),
		finding(3, tr.second, outside, confirmed))
	if code, stdout, stderr := tr.react(t, log, now); code != exitOK {
		t.Fatalf("react answered %d: %q %q", code, stdout, stderr)
	}
	if code, _, stderr := tr.stopsRun(t, "stops lift", "--key", tr.liftKey, "--run", tr.open, tr.stops); code != exitOK {
		t.Fatalf("stops lift answered %d: %q", code, stderr)
	}
	next := filepath.Join(tr.dir, "next.signed")
	signRouteFile(t, next, routeDoc(seeded(0x4c), 2), seeded(0x52))
	carried := ownerDir(t, filepath.Join(tr.dir, "carried"))
	code, stdout, stderr := invoke(t, "stops", "init", "--route", next, "--public-key", tr.routePub,
		"--carry", tr.stops, "--carry-route", tr.route, carried)
	if code != exitOK || !strings.HasSuffix(stdout, "route_serial: 2\nroute_digest: "+routeDigestOf(t, routeDoc(seeded(0x4c), 2))+
		"\nstops: 1\ncovered: 2\n") {
		t.Fatalf("stops init --carry answered %d: %q\n%s", code, stderr, stdout)
	}
	a := tr.reactArgs(log)
	a.route, a.stops = next, carried
	var out, errOut bytes.Buffer
	if code := react(context.Background(), a, clockAt(now), &out, &errOut); code != exitOK ||
		out.String() != "stops 0, covered 0, already named 3, not stopping 0, not written 0\n" {
		t.Fatalf("react over the carried list answered %d: %q %q", code, out.String(), errOut.String())
	}
	appendLog(t, log, finding(4, tr.open, denial, confirmed), finding(5, tr.second, denial, confirmed))
	out.Reset()
	if code := react(context.Background(), a, clockAt(now), &out, &errOut); code != exitOK || out.String() != fmt.Sprintf(
		"stop line 5 run %s finding %s rule REPEATED_DENIAL expires_at %s\ncovered line 6 run %s finding %s\n"+
			"stops 1, covered 1, already named 3, not stopping 0, not written 0\n",
		tr.open, fid(4), lineTime(now.Add(600*time.Second)), tr.second, fid(5)) {
		t.Fatalf("react after the carry answered %d: %q %q", code, out.String(), errOut.String())
	}
}

// TestStopsListPrintsEachStopAsAPlaneJudgesIt: a stop is active until its
// expiry and expired from then on.
func TestStopsListPrintsEachStopAsAPlaneJudgesIt(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now()
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.open, denial, confirmed),
		finding(3, tr.second, outside, confirmed))
	if code, stdout, stderr := tr.react(t, log, now); code != exitOK {
		t.Fatalf("react answered %d: %q %q", code, stdout, stderr)
	}
	raw := tr.listBytes(t)
	header := strings.SplitN(string(raw), "\n", 2)[0]
	listID := regexp.MustCompile(`"list_id":"([^"]+)"`).FindStringSubmatch(header)[1]
	for _, c := range []struct {
		at    time.Time
		state string
	}{{now, "active"}, {now.Add(600 * time.Second), "expired"}} {
		var out, errOut bytes.Buffer
		code := stopsList(routeFlags{route: tr.route, publicKey: tr.routePub}, tr.stops, c.at, &out, &errOut)
		want := strings.Join([]string{
			"list_id: " + listID, "route_id: refund-stops", "route_serial: 1", "route_digest: " + tr.parsed.Digest(),
			fmt.Sprintf("stop line 2 run %s finding %s rule REPEATED_DENIAL created_at %s expires_at %s %s",
				tr.open, fid(1), lineTime(now), lineTime(now.Add(600*time.Second)), c.state),
			fmt.Sprintf("stop line 4 run %s finding %s rule STEP_OUTSIDE_PROCEDURE created_at %s expires_at %s active",
				tr.second, fid(3), lineTime(now), runEnd(tr.runExpiry(t, tr.second))),
			"covered: 1, lifts: 0",
			fmt.Sprintf("bytes: %d of 4194304, lines: 4 of 20000", len(raw)),
		}, "\n") + "\n"
		if code != exitOK || out.String() != want {
			t.Fatalf("stops list at %s answered %d: %q\n%s\nwant\n%s", c.state, code, errOut.String(), out.String(), want)
		}
	}
}

// TestStopsListRefusesAListAPlaneWouldNot: an earlier line edited and a list
// the group may write each exit 1 naming the cause a plane reports.
func TestStopsListRefusesAListAPlaneWouldNot(t *testing.T) {
	tr := newStopTree(t)
	if code, stdout, stderr := tr.react(t, tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed)), time.Now()); code != exitOK {
		t.Fatalf("react answered %d: %q %q", code, stdout, stderr)
	}
	path := filepath.Join(tr.stops, stoplist.FileName)
	good := tr.listBytes(t)
	edited := bytes.Replace(good, []byte(`"rule_id":"REPEATED_DENIAL"`), []byte(`"rule_id":"REPEATED_DENIAL "`), 1)
	if bytes.Equal(edited, good) {
		t.Fatal("the edit changed nothing")
	}
	for _, c := range []struct {
		name, want string
		set        func()
	}{
		{"an edited line", "unknown (malformed)", func() { writeFixture(t, path, string(edited)) }},
		{"a list the group may write", "unknown (writable by others)", func() {
			writeFixture(t, path, string(good))
			if err := os.Chmod(path, 0o620); err != nil { //nolint:gosec // G302: the mode the command must refuse
				t.Fatal(err)
			}
		}},
	} {
		c.set()
		code, stdout, stderr := tr.stopsRun(t, "stops list", tr.stops)
		if code != exitFail || stdout != "" || !strings.Contains(stderr, c.want) ||
			!strings.Contains(stderr, "a plane reading this list blocks every call") {
			t.Errorf("%s: stops list answered %d: %q %q, want 1 and %q", c.name, code, stdout, stderr, c.want)
		}
	}
}

// TestStopsCarryRepairsAListBrokenAtItsEnd: a line appended around the
// writer, which a plane refuses and so blocks every call on, is left out of
// a carry, which says so; the stop before it is carried.
func TestStopsCarryRepairsAListBrokenAtItsEnd(t *testing.T) {
	tr := newStopTree(t)
	if code, stdout, stderr := tr.react(t, tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed)), time.Now()); code != exitOK {
		t.Fatalf("react answered %d: %q %q", code, stdout, stderr)
	}
	f, err := os.OpenFile(filepath.Join(tr.stops, stoplist.FileName), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(tr.dir, "next.signed")
	signRouteFile(t, next, routeDoc(seeded(0x4c), 2), seeded(0x52))
	carried := ownerDir(t, filepath.Join(tr.dir, "carried"))
	code, stdout, stderr := invoke(t, "stops", "init", "--route", next, "--public-key", tr.routePub,
		"--carry", tr.stops, "--carry-route", tr.route, carried)
	if code != exitOK || !strings.Contains(stdout, "\nstops: 1\ncovered: 0\nleft out: the last 1 line(s) of the old list, from line 3: ") {
		t.Fatalf("stops init --carry of a broken list answered %d: %q\n%s", code, stderr, stdout)
	}
}
