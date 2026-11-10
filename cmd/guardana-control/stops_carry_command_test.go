package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
)

// TestASignedCarryRunAsACommandIsTakenByThePlanesFloor: the plane's floor
// took alice's list with its stop of run-1; stops init --carry held to that
// floor, the way back after a restore, carries the stop into a new directory,
// says the roster's line once though it judges two routes with it, and the
// same floor then takes the carried list, in which run-1 is still stopped.
func TestASignedCarryRunAsACommandIsTakenByThePlanesFloor(t *testing.T) {
	tr := newSignedTree(t)
	judged := resignRoster(t, tr.judge[1], seeded(0x7e))
	if code, _, stderr := tr.run(t, "stops init", "--key", tr.keys["alice"], tr.stops); code != exitOK {
		t.Fatalf("stops init: %d, %q", code, stderr)
	}
	tr.appendRunStop(t)
	floorDir := filepath.Join(tr.dir, "stopsfloor")
	if code, _, stderr := invoke(t, "stops", "floor", "init", "--tenant", "acme", "--project", "orders", floorDir); code != exitOK {
		t.Fatalf("stops floor init: %d, %q", code, stderr)
	}
	tr.takenByPlane(t, floorDir)
	old := listBytes(t, tr.stops)

	into := ownerDir(t, filepath.Join(tr.dir, "stops2"))
	code, stdout, stderr := tr.run(t, "stops init", "--key", tr.keys["alice"], "--carry", tr.stops, "--carry-route", tr.route,
		"--stops-floor", floorDir, into)
	if code != exitOK || !strings.Contains(stdout, "stops: 1") || !judgedOnce(stderr, stopsInitName, judged, "signed list header") {
		t.Fatalf("stops init --carry held to the floor: %d, %q, %q", code, stdout, stderr)
	}
	if after := listBytes(t, tr.stops); string(after) != string(old) {
		t.Fatal("the carry changed the list it carried from")
	}

	carried := tr
	carried.stops = into
	raw := listBytes(t, into)
	l, err := reaction.Judge(carried.takenRoute(t), reaction.Prefix{}, raw, time.Now(), time.Second)
	if err != nil {
		t.Fatalf("a plane judging the carried list: %v", err)
	}
	floor, err := signedstops.NewFloor(floorDir, "acme", "orders")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := floor.Take(t.Context(), l, raw); err != nil {
		t.Fatalf("the plane's floor refuses the carried list: %v", err)
	}
	if entries := l.Entries(); len(entries) != 1 || entries[0].RunID != "run-1" {
		t.Errorf("the carried list a plane takes stops %+v, want run-1 alone", entries)
	}
}
