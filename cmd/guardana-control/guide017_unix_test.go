//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/reaction"
)

// TestTheUpgradeGuidesStepsServeTheNewRoute follows the 0.17 upgrade guide
// in its order: the new route signed beside the old one at a path of its
// own, the old list carried under both, and the plane's files pointed at the
// new route and directory, which stops list then serves. The new route moved
// onto the old route's path is refused, as a signed route names its own file.
func TestTheUpgradeGuidesStepsServeTheNewRoute(t *testing.T) {
	tr := newSignedTree(t)
	plane := ownerDir(t, filepath.Join(tr.dir, "plane"))
	writeV2Plane(t, plane)
	oldRoute, oldStops := filepath.Join(plane, "route.json"), filepath.Join(plane, "stops")
	newRoute, newStops := filepath.Join(plane, "route-018.json"), ownerDir(t, filepath.Join(plane, "stops-018"))
	if code, stderr := tr.signRouteDoc(t, routeDocAt("plane-a", "2"), newRoute); code != exitOK {
		t.Fatalf("route sign at a new path: %d, %q", code, stderr)
	}
	carry := append([]string{"stops", "init", "--key", tr.keys["alice"], "--route", newRoute, "--carry", oldStops, "--carry-route", oldRoute}, tr.judge...)
	if code, _, stderr := invoke(t, append(carry, newStops)...); code != exitOK {
		t.Fatalf("stops init --carry: %d, %q", code, stderr)
	}
	list := func(route string) (int, string, string) {
		return invoke(t, append(append([]string{"stops", "list", "--route", route}, tr.judge...), newStops)...)
	}
	if code, stdout, stderr := list(newRoute); code != exitOK || !strings.Contains(stdout, "run-1") {
		t.Fatalf("stops list under the new route: %d, %q, %q", code, stdout, stderr)
	}
	noErr(t, os.Rename(newRoute, oldRoute))
	if code, _, stderr := list(oldRoute); code == exitOK || !strings.Contains(stderr, reaction.ErrOtherFile.Error()) {
		t.Fatalf("stops list under the new route moved to the old path: %d, %q, want %v", code, stderr, reaction.ErrOtherFile)
	}
}
