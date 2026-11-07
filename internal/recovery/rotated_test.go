package recovery_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/recovery"
)

// rotate replaces the plane's route, after its backup, with one at serial 2
// under the same route key and the same rule, and returns the new route and
// the file of the route the backup's list was written under.
func rotate(t *testing.T, p *plane) (reaction.Route, []byte) {
	t.Helper()
	old := readOrFail(t, p.path("route/route.json"))
	rule := stopRoute.Rules()[0]
	doc := `{"kind":"reaction-route/v1alpha1","route_id":"refunds","serial":2,"tenant_id":"acme","scope":"run","lift_public_key":"` +
		base64.StdEncoding.EncodeToString(liftKey.Public().(ed25519.PublicKey)) +
		`","rules":[{"procedure_id":"refund","version":"1","digest":"` + rule.ProcedureDigest +
		`","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","expires_seconds":3600}]}`
	r, err := reaction.ParseRoute([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if r.Digest() == stopRoute.Digest() {
		t.Fatal("the rotated route is the old one")
	}
	writeFile(t, p.path("route/route.json"), routeFile(t, r))
	return r, old
}

func routeFile(t *testing.T, r reaction.Route) []byte {
	t.Helper()
	env, err := reaction.SignRoute(r, routeKey)
	if err != nil {
		t.Fatal(err)
	}
	file, err := reaction.MarshalRouteFile(env)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// carryLive carries the plane's list from fromRoute into a list judged
// against route, in the place of the old one.
func carryLive(t *testing.T, p *plane, fromRoute, route reaction.Route, at time.Time) {
	t.Helper()
	if err := os.Mkdir(p.path("stops2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := stopwrite.Carry(t.Context(), p.path("stops"), fromRoute, p.path("stops2"), route, at); err != nil {
		t.Fatalf("carry: %v", err)
	}
	if err := os.RemoveAll(p.path("stops")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p.path("stops2"), p.path("stops")); err != nil {
		t.Fatal(err)
	}
}

// stoppedUnder is the runs the plane's list stops, judged against route.
func stoppedUnder(t *testing.T, p *plane, route reaction.Route) []string {
	t.Helper()
	l, err := reaction.Judge(route, reaction.Prefix{}, p.stopList(t), t0, 0)
	if err != nil {
		t.Fatalf("the list under route serial %d: %v", route.Serial(), err)
	}
	var out []string
	for _, e := range l.Entries() {
		out = append(out, e.RunID)
	}
	slices.Sort(out)
	return out
}

// TestRestoreRefusesTheBackupsListUnderAReplacedRoute: once the route is
// replaced, the backup's list names a route the plane no longer reads.
// Whether the live list is lost or was carried into the new route, the
// restore refuses before its first write.
func TestRestoreRefusesTheBackupsListUnderAReplacedRoute(t *testing.T) {
	for name, after := range map[string]func(t *testing.T, p *plane, newRoute reaction.Route){
		"the list lost": func(t *testing.T, p *plane, _ reaction.Route) {
			if err := os.Remove(p.path("stops/" + stoplist.FileName)); err != nil {
				t.Fatal(err)
			}
		},
		"the list carried into the new route": func(t *testing.T, p *plane, newRoute reaction.Route) {
			carryLive(t, p, stopRoute, newRoute, t0)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, dir, _ := stopsPlane(t)
			newRoute, _ := rotate(t, p)
			after(t, p, newRoute)
			before := tree(t, p.root)
			if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, reaction.ErrListRoute) {
				t.Fatalf("err = %v, want ErrListRoute", err)
			}
			if got := tree(t, p.root); fmt.Sprint(got) != fmt.Sprint(before) {
				t.Fatal("a refused restore changed the plane's tree")
			}
		})
	}
}

// TestRestoreUnderAReplacedRouteTakesTheOldRouteBack is the way back the
// guide names: the route the backup's list was written under is put back at
// reaction.route for the restore, then the current one. A list the restore
// carried names the old route, and a carry into the current route makes it
// one the plane reads; a list already carried into the current route is
// kept.
func TestRestoreUnderAReplacedRouteTakesTheOldRouteBack(t *testing.T) {
	t.Run("the list lost", func(t *testing.T) {
		p, dir, _ := stopsPlane(t)
		p.addStop(t, "f-c", "run-c")
		newRoute, oldFile := rotate(t, p)
		current := readOrFail(t, p.path("route/route.json"))
		if err := os.Remove(p.path("stops/" + stoplist.FileName)); err != nil {
			t.Fatal(err)
		}
		writeFile(t, p.path("route/route.json"), oldFile)
		if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
			t.Fatalf("Restore under the old route: %v", err)
		}
		writeFile(t, p.path("route/route.json"), current)
		if _, err := reaction.Judge(newRoute, reaction.Prefix{}, p.stopList(t), t0, 0); !errors.Is(err, reaction.ErrListRoute) {
			t.Fatalf("the restored list under the current route: %v, want ErrListRoute", err)
		}
		carryLive(t, p, stopRoute, newRoute, restoreAt)
		if got := stoppedUnder(t, p, newRoute); fmt.Sprint(got) != "[run-a run-b]" {
			t.Fatalf("the list carried into the current route stops %v, want the backup's run-a and run-b", got)
		}
	})
	t.Run("the list carried into the new route", func(t *testing.T) {
		p, dir, _ := stopsPlane(t)
		newRoute, oldFile := rotate(t, p)
		current := readOrFail(t, p.path("route/route.json"))
		carryLive(t, p, stopRoute, newRoute, t0)
		list := p.stopList(t)
		writeFile(t, p.path("route/route.json"), oldFile)
		report, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
		if err != nil {
			t.Fatalf("Restore under the old route: %v", err)
		}
		writeFile(t, p.path("route/route.json"), current)
		if !bytes.Equal(p.stopList(t), list) || !slices.ContainsFunc(report.Done, func(s string) bool { return strings.Contains(s, "carries the backup's list") }) {
			t.Fatalf("the carried list was not kept: Done = %q", report.Done)
		}
		if got := stoppedUnder(t, p, newRoute); fmt.Sprint(got) != "[run-a run-b]" {
			t.Fatalf("the kept list stops %v", got)
		}
	})
}

// TestRestoreKeepsACarriedListThatGrew: a list a restore carried, which then
// took a stop of its own, still carries the backup's and is kept as it is.
func TestRestoreKeepsACarriedListThatGrew(t *testing.T) {
	p, dir, _ := stopsPlane(t)
	if err := os.Remove(p.path("stops/" + stoplist.FileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
		t.Fatalf("the first restore: %v", err)
	}
	p.addStop(t, "f-c", "run-c")
	grown := p.stopList(t)
	report, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("a restore over the grown list: %v", err)
	}
	if !bytes.Equal(p.stopList(t), grown) || !slices.ContainsFunc(report.Done, func(s string) bool { return strings.Contains(s, "carries the backup's list") }) {
		t.Fatalf("the grown list was not kept: Done = %q", report.Done)
	}
	if _, got := p.stopped(t); fmt.Sprint(got) != "[run-a run-b run-c]" {
		t.Fatalf("the kept list stops %v", got)
	}
}
