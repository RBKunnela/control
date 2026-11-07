package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// takenByPlane has a plane's floor in floorDir take the tree's list as it
// stands.
func (tr signedTree) takenByPlane(t *testing.T, floorDir string) {
	t.Helper()
	raw := listBytes(t, tr.stops)
	l, err := reaction.Judge(tr.takenRoute(t), reaction.Prefix{}, raw, time.Now(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := signedstops.NewFloor(floorDir, "acme", "orders")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := floor.Take(t.Context(), l, raw); err != nil {
		t.Fatal(err)
	}
}

// TestASignedCarryHeldToTheFloorRefusesAListCutBack: the plane took the list
// with its stop; cut back to its header, it is not carried with
// --stops-floor, which writes nothing, and without it is carried as it
// stands, saying the floor was not read. A --stops-floor outside a signed
// carry is a usage error.
func TestASignedCarryHeldToTheFloorRefusesAListCutBack(t *testing.T) {
	tr := newSignedTree(t)
	if code, _, stderr := tr.run(t, "stops init", "--key", tr.keys["alice"], tr.stops); code != exitOK {
		t.Fatalf("stops init: %d, %q", code, stderr)
	}
	tr.appendRunStop(t)
	floorDir := filepath.Join(tr.dir, "stopsfloor")
	if code, _, stderr := invoke(t, "stops", "floor", "init", "--tenant", "acme", "--project", "orders", floorDir); code != exitOK {
		t.Fatalf("stops floor init: %d, %q", code, stderr)
	}
	tr.takenByPlane(t, floorDir)
	raw := listBytes(t, tr.stops)
	if err := os.WriteFile(filepath.Join(tr.stops, stoplist.FileName), raw[:bytes.IndexByte(raw, '\n')+1], 0o600); err != nil {
		t.Fatal(err)
	}

	into := ownerDir(t, filepath.Join(tr.dir, "stops2"))
	carry := []string{"--key", tr.keys["alice"], "--carry", tr.stops, "--carry-route", tr.route}
	code, _, stderr := tr.run(t, "stops init", append(carry, "--stops-floor", floorDir, into)...)
	if code == exitOK || !strings.Contains(stderr, string(stoplist.ErrChain)) {
		t.Fatalf("a carry of the cut list held to the floor: %d, %q", code, stderr)
	}
	if entries, err := os.ReadDir(into); err != nil || len(entries) != 0 {
		t.Fatalf("a refused carry wrote %v, %v", entries, err)
	}
	code, stdout, stderr := tr.run(t, "stops init", append(carry, into)...)
	if code != exitOK || !strings.Contains(stderr, "stop list floor was not read") || !strings.Contains(stdout, "stops: 0") {
		t.Fatalf("a carry of the cut list held to nothing: %d, %q, %q", code, stdout, stderr)
	}
	if code, _, _ := tr.run(t, "stops init", "--key", tr.keys["alice"], "--stops-floor", floorDir, filepath.Join(tr.dir, "x")); code != exitUsage {
		t.Fatalf("--stops-floor without --carry: %d, want a usage error", code)
	}
}
