package stopwrite_test

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// denialStopOf is stopOf under REPEATED_DENIAL at version, lasting ten
// minutes.
func denialStopOf(t *testing.T, finding, run, version string, created time.Time) reaction.Stop {
	t.Helper()
	s := stopOf(t, finding, run, created)
	s.RuleID, s.RuleVersion, s.ExpiresAt = "REPEATED_DENIAL", version, created.Add(10*time.Minute)
	return s
}

// writeLines writes lines as the list in a fresh directory, as a release
// whose route named a version since superseded wrote it.
func writeLines(t *testing.T, lines ...[]byte) string {
	t.Helper()
	dir := emptyDir(t)
	if err := os.WriteFile(listPath(dir), append(bytes.Join(lines, []byte{'\n'}), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestACarryFromASupersededRouteKeepsItsStopsAndLifts: a list under a route
// naming REPEATED_DENIAL at version "1", holding a stop of run-1, a stop of
// run-2 and a lift of run-2, is carried into a list under the route naming
// version "2": the stop of run-1 is kept as it was and still stops run-1,
// the lifted one is covered, and a plane serves the new list.
func TestACarryFromASupersededRouteKeepsItsStopsAndLifts(t *testing.T) {
	from, to := routeNamingAlso(t, "REPEATED_DENIAL", "1"), routeNamingAlso(t, "REPEATED_DENIAL", "2")
	h := reaction.HeaderFor(from, "lst-0123456789abcdef0123456789abcdef")
	kept := must(t)(denialStopOf(t, "f-1", "run-1", "1", clock0.Add(-time.Minute)).Marshal())
	old := writeLines(t, must(t)(h.Marshal()), kept,
		must(t)(denialStopOf(t, "f-2", "run-2", "1", clock0.Add(-time.Minute)).Marshal()),
		must(t)(liftOf(t, liftKey(), from, h.ListID, "run-2", 3).Marshal()))
	dir := emptyDir(t)
	got, err := stopwrite.Carry(bg, old, from, dir, to, clock0)
	if err != nil {
		t.Fatalf("Carry from the old route: %v", err)
	}
	if got.Stops != 1 || got.Covered != 1 || got.LeftOut != 0 {
		t.Errorf("Carry = %+v; want 1 stop and 1 covered", got)
	}
	lines := strings.Split(string(content(t, dir)), "\n")
	if len(lines) != 4 || lines[1] != string(kept) || !strings.Contains(lines[2], `"finding_id":"f-2"`) || lines[3] != "" {
		t.Fatalf("the carried list:\n%s", content(t, dir))
	}
	p := planeOn(t, dir, to)
	if s, _ := p.Current().ForCall("run-1", "acme", clock0, time.Time{}); s != reaction.Stopped {
		t.Errorf("run-1 on the carried list: %s, want %s", s, reaction.Stopped)
	}
	if s, _ := p.Current().ForCall("run-2", "acme", clock0, time.Time{}); s != reaction.Clear {
		t.Errorf("run-2 on the carried list: %s, want %s", s, reaction.Clear)
	}
}

// TestNoWriterAppendsAStopOfASupersededVersion: on a list carried under the
// route naming REPEATED_DENIAL at version "2", which holds a stop of version
// "1", AppendStop and AppendFinding refuse a new stop of version "1" and
// write nothing; the same stop at version "2", and a lift of the carried
// stop, are the control.
func TestNoWriterAppendsAStopOfASupersededVersion(t *testing.T) {
	to := routeNamingAlso(t, "REPEATED_DENIAL", "2")
	h := reaction.HeaderFor(to, "lst-0123456789abcdef0123456789abcdef")
	dir := writeLines(t, must(t)(h.Marshal()), must(t)(denialStopOf(t, "f-1", "run-1", "1", clock0.Add(-time.Minute)).Marshal()))
	before := content(t, dir)
	stale := denialStopOf(t, "f-2", "run-2", "1", clock0)
	_, err := stopwrite.AppendStop(bg, dir, to, stale, clock0)
	if !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, reaction.ErrStopSuperseded) {
		t.Errorf("AppendStop of a version 1 stop: %v", err)
	}
	_, _, err = appendFinding(bg, dir, to, stale, clock0)
	if !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, reaction.ErrStopSuperseded) {
		t.Errorf("AppendFinding of a version 1 stop: %v", err)
	}
	stale.RunID = "run-1"
	_, _, err = appendFinding(bg, dir, to, stale, clock0)
	if !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, reaction.ErrStopSuperseded) {
		t.Errorf("AppendFinding of a version 1 stop of a stopped run: %v", err)
	}
	if !bytes.Equal(content(t, dir), before) {
		t.Fatal("a refused append changed the list")
	}
	if n, err := stopwrite.AppendStop(bg, dir, to, denialStopOf(t, "f-2", "run-2", "2", clock0), clock0); err != nil || n != 3 {
		t.Errorf("the control's AppendStop: line %d, %v", n, err)
	}
	if n, err := stopwrite.AppendLift(bg, dir, to, liftOf(t, liftKey(), to, h.ListID, "run-1", 2), clock0); err != nil || n != 4 {
		t.Errorf("a lift of the carried stop: line %d, %v", n, err)
	}
}
