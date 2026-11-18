//go:build twoaccounts && unix

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/recovery"
)

// guidePlane is a stopped 0.17 signed plane as the 0.18 upgrade guide's
// signed steps find it: in files, a directory the plane's account may not
// write, the old route and the 2.0 list the stop writers' account wrote,
// whose head is head, and the new route signed at a path of its own; in
// state, the plane's account's own, its configuration naming the old route
// and list, and its stop list floor holding the old list.
type guidePlane struct {
	tr                         signedTree
	files, oldRoute, oldStops  string
	newRoute, newStops         string
	state, floor, config, head string
	plane, writer              account
}

// TestTheUpgradeGuidesSignedStepsRunOnTwoAccounts follows the 0.18 upgrade
// guide's signed steps 3 to 6, each as the account it names. Root copies the
// plane's stop list floor, modes kept, hands the copy to the stop writers'
// account and makes the new stops directory theirs, 2750 in the plane's
// group. The writers' account carries the old list into it held to the
// copy, which says the plane and the previous head, and leaves the list
// 0640; the plane's own floor, which that account cannot open, is refused.
// The copy is removed. Under a configuration naming the new route and
// directory, the plane's account backs up a 0.2 manifest naming the plane
// and holding the carried list, and reads that list as a signed plane does.
func TestTheUpgradeGuidesSignedStepsRunOnTwoAccounts(t *testing.T) {
	plane, writer := twoAccounts(t)
	g := newGuidePlane(t, plane, writer)

	floorCopy := filepath.Join(g.files, "stopsfloor-copy")
	copyKeepingOwners(t, g.floor, floorCopy)
	giveTree(t, floorCopy, account{uid: writer.uid, gid: plane.gid})
	noErr(t, os.Mkdir(g.newStops, 0o750))
	noErr(t, os.Chown(g.newStops, int(writer.uid), int(plane.gid)))
	noErr(t, os.Chmod(g.newStops, 0o750|os.ModeSetgid))

	list := filepath.Join(g.newStops, stoplist.FileName)
	stdout, stderr, code := writer.as(t, "cli", g.carryArgs(g.floor))
	if code == exitOK || !strings.Contains(stderr, "--stops-floor "+g.floor+": ") || !strings.Contains(stderr, "permission denied") {
		t.Fatalf("the carry held to the plane's own floor as the writers' account: %d, %q, %q; want it refused", code, stdout, stderr)
	}
	if _, err := os.Lstat(list); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the refused carry left %s: %v", list, err)
	}
	stdout, stderr, code = writer.as(t, "cli", g.carryArgs(floorCopy))
	if code != exitOK || !strings.Contains(stdout, "stops: 1") ||
		!strings.Contains(stderr, " for plane plane-a ") || !strings.Contains(stderr, "previous head "+g.head) {
		t.Fatalf("the carry held to the copy as the writers' account: %d, %q, %q; want plane-a after %s", code, stdout, stderr, g.head)
	}
	expectOwned(t, list, writer.uid, 0o640)

	noErr(t, os.RemoveAll(floorCopy))
	if _, err := os.Lstat(floorCopy); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the copy is still there: %v", err)
	}

	g.pointAtTheNewList(t)
	g.expectBackedUpAsPlane(t, listBytes(t, g.newStops))
	arg := stopsReadArg{Stops: g.newStops, Route: g.newRoute, Roster: g.tr.judge[1], Root: g.tr.judge[3]}
	if out := readStopsAs(t, plane, arg); out != "ok lines 2 stop run run-1" {
		t.Errorf("the plane's account reading the carried list: %q; want two lines and run-1 stopped", out)
	}
}

// newGuidePlane is the set-up the guide's steps assume, made as root: the
// plane's state and floor handed to plane, the old list and alice's key to
// writer, and the routes, roster and root key readable by both.
func newGuidePlane(t *testing.T, plane, writer account) guidePlane {
	t.Helper()
	g := guidePlane{tr: newSignedTree(t), plane: plane, writer: writer}
	g.files = filepath.Join(g.tr.dir, "plane")
	noErr(t, os.Mkdir(g.files, 0o700))
	g.head = writeV2Plane(t, g.files)
	g.oldRoute, g.oldStops = filepath.Join(g.files, "route.json"), filepath.Join(g.files, "stops")
	g.newRoute, g.newStops = filepath.Join(g.files, "route-018.json"), filepath.Join(g.files, "stops-018")
	if code, stderr := g.tr.signRouteDoc(t, routeDocAt("plane-a", "2"), g.newRoute); code != exitOK {
		t.Fatalf("route sign of the v1alpha3 route at its own path: %d, %q", code, stderr)
	}
	for _, f := range []string{g.oldRoute, g.newRoute, g.tr.judge[1], g.tr.judge[3]} {
		if err := os.Chmod(f, 0o644); err != nil { //nolint:gosec // G302: files the writers and the plane read
			t.Fatal(err)
		}
	}

	g.state, g.config = signedStatePlane(t)
	g.floor = filepath.Join(g.state, "stopsfloor")
	takenByA017Plane(t, g.tr, g.floor, g.oldRoute, g.oldStops)
	raw := fileBytesOf(t, g.config)
	noErr(t, os.WriteFile(g.config, append(raw, guideReaction(g.oldRoute, g.oldStops)...), 0o600))

	openToEveryAccount(t, g.files)
	openToEveryAccount(t, g.state)
	giveTree(t, g.state, plane)
	giveTree(t, g.oldStops, writer)
	giveTree(t, filepath.Dir(g.tr.keys["alice"]), writer)
	return g
}

// guideReaction is the runs and reaction blocks of a signed plane serving
// the route at route and the list in stops.
func guideReaction(route, stops string) string {
	return fmt.Sprintf("runs:\n  dir: runs\nreaction:\n  route: %s\n  floor_dir: routefloor\n  stops: %s\n  stops_floor_dir: stopsfloor\n", route, stops)
}

// takenByA017Plane makes floor the stop list floor of acme and orders and
// has it take the 2.0 list in oldStops, judged under the v1alpha2 route at
// oldRoute, as the 0.17 plane took it.
func takenByA017Plane(t *testing.T, tr signedTree, floor, oldRoute, oldStops string) {
	t.Helper()
	noErr(t, policystate.InitStops(t.Context(), floor, "acme", "orders"))
	from, err := rosterRoute("--carry-route", oldRoute, tr.judge[1], tr.judge[3], oldStops, "plane-a", nil, reaction.VerifySignedCarrySource)
	noErr(t, err)
	raw := listBytes(t, oldStops)
	l, err := reaction.JudgeCarrySource(from, raw, time.Now())
	noErr(t, err)
	f, err := signedstops.NewFloor(floor, "acme", "orders")
	noErr(t, err)
	if taken, err := f.Take(t.Context(), l, raw); err != nil || taken.Serial != 3 {
		t.Fatalf("the 0.17 plane's floor over the 2.0 list: %+v, %v; want serial 3", taken, err)
	}
}

// carryArgs is the guide's step 4 with floor as its --stops-floor.
func (g guidePlane) carryArgs(floor string) []string {
	args := append([]string{"stops", "init", "--key", g.tr.keys["alice"], "--route", g.newRoute}, g.tr.judge...)
	return append(args, "--carry", g.oldStops, "--carry-route", g.oldRoute, "--stops-floor", floor, g.newStops)
}

// pointAtTheNewList is the guide's step 6 edit: the configuration names the
// new route and the new stops directory in place of the old ones.
func (g guidePlane) pointAtTheNewList(t *testing.T) {
	t.Helper()
	raw, old := string(fileBytesOf(t, g.config)), guideReaction(g.oldRoute, g.oldStops)
	if !strings.Contains(raw, old) {
		t.Fatal("the plane's configuration no longer names the old route and list")
	}
	noErr(t, os.WriteFile(g.config, []byte(strings.Replace(raw, old, guideReaction(g.newRoute, g.newStops), 1)), 0o600))
}

// expectBackedUpAsPlane runs state backup as the plane's account into a
// directory it owns and expects a 0.2 manifest naming plane-a whose one stop
// list entry is the list in the new stops directory, holding carried.
func (g guidePlane) expectBackedUpAsPlane(t *testing.T, carried []byte) {
	t.Helper()
	backups := t.TempDir()
	openToEveryAccount(t, backups)
	giveTree(t, backups, g.plane)
	backup := filepath.Join(backups, "plane-2")
	if stdout, stderr, code := g.plane.as(t, "cli", []string{"state", "backup", g.config, backup}); code != exitOK {
		t.Fatalf("state backup as the plane's account: %d, %q, %q", code, stdout, stderr)
	}
	raw := fileBytesOf(t, filepath.Join(backup, recovery.ManifestName))
	m, err := recovery.ParseManifest(raw)
	if err != nil || !strings.Contains(string(raw), `"schema_version": "0.2"`) || m.PlaneID != "plane-a" {
		t.Fatalf("the backup's manifest names plane %q, %v: %s; want 0.2 naming plane-a", m.PlaneID, err, raw)
	}
	var held [][]byte
	for _, e := range m.Entries {
		if e.Key != "reaction.stops" {
			continue
		}
		if e.Source != filepath.Join(g.newStops, stoplist.FileName) {
			t.Errorf("the backup's stop list is %s; want the new stops directory's", e.Source)
		}
		held = append(held, fileBytesOf(t, filepath.Join(backup, filepath.FromSlash(e.Path))))
	}
	if len(held) != 1 || !bytes.Equal(held[0], carried) {
		t.Errorf("the backup holds %d stop lists; want the carried list alone", len(held))
	}
}

// copyKeepingOwners copies the directory from to to as cp -Rp run by root
// does: every entry's mode, owner and group kept.
func copyKeepingOwners(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("%s is %v, not a file or a directory", path, info.Mode())
		}
		target := filepath.Join(to, rel)
		if err := copyEntry(path, target, info); err != nil {
			return err
		}
		if err := os.Lchown(target, int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
		return os.Chmod(target, info.Mode().Perm())
	})
	if err != nil {
		t.Fatalf("copying %s: %v", from, err)
	}
}

func copyEntry(path, target string, info fs.FileInfo) error {
	if info.IsDir() {
		return os.Mkdir(target, 0o700)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a floor this test made
	if err != nil {
		return err
	}
	return os.WriteFile(target, raw, 0o600)
}
