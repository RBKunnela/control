//go:build twoaccounts && unix

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// stopsReadArg is what the read-stops role reads: a stops directory and the
// route, roster and root key a signed plane judges its list with.
type stopsReadArg struct {
	Stops, Route, Roster, Root string
}

// TestASignedStopListIsReadByAPlaneInTheWritersGroup: the stop writers'
// account starts a list under a signed route and stops a run through react,
// in a stops directory it owns at 2750, and the list stays its own at 0640.
// A plane of another account in the writers' group reads the list as a
// signed plane does and finds the stop; the same plane outside that group,
// or reading a list the writer left 0600, cannot read it, and a list or a
// directory handed to the plane's own account is refused.
func TestASignedStopListIsReadByAPlaneInTheWritersGroup(t *testing.T) {
	plane, writer := twoAccounts(t)
	tr := newSignedTree(t)
	findings := ownerDir(t, filepath.Join(tr.dir, "findings"))
	runsAt := runsDir(t)
	run := openRun(t, runsAt, who, "1h").runID
	appendLog(t, findings, finding(1, run, outside, confirmed))
	approvalsDir := handStopsToWriter(t, tr, plane, writer)
	list := filepath.Join(tr.stops, stoplist.FileName)

	start := append([]string{"stops", "init", "--key", tr.keys["alice"], "--route", tr.route}, tr.judge...)
	if stdout, stderr, code := writer.as(t, "cli", append(start, tr.stops)); code != exitOK {
		t.Fatalf("stops init as the writer answered %d: %q %q", code, stdout, stderr)
	}
	expectOwned(t, list, writer.uid, 0o640)
	pass := append([]string{"react", "--findings", findings, "--runs", runsAt, "--route", tr.route}, tr.judge...)
	pass = append(pass, "--approvals", approvalsDir, "--stops", tr.stops)
	if stdout, stderr, code := writer.as(t, "cli", pass); code != exitOK || !strings.Contains(stdout, "stops 1, covered 0") {
		t.Fatalf("react as the writer answered %d: %q %q; want one stop", code, stdout, stderr)
	}
	expectOwned(t, list, writer.uid, 0o640)

	arg := stopsReadArg{Stops: tr.stops, Route: tr.route, Roster: tr.judge[1], Root: tr.judge[3]}
	inGroup := plane
	inGroup.groups = []uint32{writer.gid}
	if out := readStopsAs(t, inGroup, arg); out != "ok lines 2 stop run "+run {
		t.Errorf("a plane in the writers' group: %q; want the list read and the run stopped", out)
	}
	if out := readStopsAs(t, plane, arg); !strings.Contains(out, "permission denied") {
		t.Errorf("a plane outside the writers' group: %q; want the list unreadable", out)
	}
	expectUnreadableAt0600(t, list, inGroup, arg)
	expectRefusedWhenThePlanesOwn(t, list, plane, writer, inGroup, arg)
	expectRefusedWhenThePlanesOwn(t, tr.stops, plane, writer, inGroup, arg)
}

// handStopsToWriter gives the signed tree, the findings and the runs to the
// writer, the stops directory 2750 in the writer's group and the route and
// trust files 0644, and returns an approvals directory the plane's account
// owns and holds, 2750 in the writer's group, as react under a signed route
// requires.
func handStopsToWriter(t *testing.T, tr signedTree, plane, writer account) string {
	t.Helper()
	giveTree(t, filepath.Dir(tr.dir), writer)
	openToEveryAccount(t, tr.dir)
	if err := os.Chmod(tr.stops, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{tr.route, tr.judge[1], tr.judge[3]} {
		if err := os.Chmod(f, 0o644); err != nil { //nolint:gosec // G302: files the writer and the plane read
			t.Fatal(err)
		}
	}
	approvalsDir := filepath.Join(tr.dir, "approvals")
	if err := os.Mkdir(approvalsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(approvalsDir, int(plane.uid), int(writer.gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(approvalsDir, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	plane.holding(t, approvalsDir)
	return approvalsDir
}

// expectUnreadableAt0600 leaves the list 0600, as a list written owner-only
// is, expects the plane in the writers' group unable to read it, and puts
// the mode back.
func expectUnreadableAt0600(t *testing.T, list string, inGroup account, arg stopsReadArg) {
	t.Helper()
	if err := os.Chmod(list, 0o600); err != nil {
		t.Fatal(err)
	}
	if out := readStopsAs(t, inGroup, arg); !strings.Contains(out, "permission denied") {
		t.Errorf("a plane in the writers' group over a 0600 list: %q; want the list unreadable", out)
	}
	if err := os.Chmod(list, 0o640); err != nil { //nolint:gosec // G302: the writers' group reads the stop list
		t.Fatal(err)
	}
}

// expectRefusedWhenThePlanesOwn hands path to the plane's account, keeping
// the writers' group, expects the plane in that group refused as the owner,
// and hands path back to the writer.
func expectRefusedWhenThePlanesOwn(t *testing.T, path string, plane, writer, inGroup account, arg stopsReadArg) {
	t.Helper()
	if err := os.Lchown(path, int(plane.uid), int(writer.gid)); err != nil {
		t.Fatal(err)
	}
	if out := readStopsAs(t, inGroup, arg); !strings.Contains(out, string(stoplist.ErrPlaneOwned)) {
		t.Errorf("%s owned by the plane's account: %q; want it refused", path, out)
	}
	if err := os.Lchown(path, int(writer.uid), int(writer.gid)); err != nil {
		t.Fatal(err)
	}
}

func readStopsAs(t *testing.T, a account, arg stopsReadArg) string {
	t.Helper()
	out, stderr, code := a.as(t, "read-stops", arg)
	if code != 0 {
		t.Fatalf("the plane as uid %d exited %d: %q %q", a.uid, code, out, stderr)
	}
	return strings.TrimSpace(out)
}

// readStopsAsPlane reads the stop list as a plane under the signed authority
// does, on an account that owns neither the list nor its directory, judges
// it against the route the roster vouches for, and prints its lines and the
// run each stop names, or why it was refused.
func readStopsAsPlane(raw []byte) int {
	var a stopsReadArg
	if err := json.Unmarshal(raw, &a); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	list, err := stoplist.ReadAs(a.Stops, stoplist.OwnedByAnother)
	if err != nil {
		return tellParent("read: " + err.Error())
	}
	route, err := rosterRoute("--route", a.Route, a.Roster, a.Root, a.Stops, "", nil, reaction.VerifySignedRoute)
	if err != nil {
		return tellParent("route: " + err.Error())
	}
	l, err := reaction.Judge(route, reaction.Prefix{}, list, time.Now(), 0)
	if err != nil {
		return tellParent("judge: " + err.Error())
	}
	out := fmt.Sprintf("ok lines %d", l.Usage().Lines)
	for _, e := range l.Entries() {
		out += fmt.Sprintf(" stop %s %s", e.Scope, e.Subject)
	}
	return tellParent(out)
}
