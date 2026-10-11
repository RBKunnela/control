//go:build unix

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// buildServing builds the serving plane over the tree, or returns why not.
func buildServing(t *testing.T, tr tree) (*plane, error) {
	t.Helper()
	p, err := build(tr.load(t), slog.New(slog.DiscardHandler), time.Now(), roleServe, "")
	if err == nil {
		t.Cleanup(func() {
			if err := p.close(); err != nil {
				t.Errorf("closing the plane: %v", err)
			}
		})
	}
	return p, err
}

// refusesStart fails unless the start is refused with want, naming key.
func refusesStart(t *testing.T, tr tree, want error, key string) {
	t.Helper()
	_, err := buildServing(t, tr)
	if !errors.Is(err, want) {
		t.Fatalf("build = %v, want %v", err, want)
	}
	if !strings.Contains(err.Error(), key) {
		t.Errorf("the refusal does not name %s: %v", key, err)
	}
}

// TestAPlaneWithARouteRaisesItsFloorAndReadsItsList: the start takes the
// route into its floor and hands the pipeline the stop list's reader; a plane
// with no route hands it the disabled source.
func TestAPlaneWithARouteRaisesItsFloorAndReadsItsList(t *testing.T) {
	tr := newTree(t)
	route := tr.withReaction(t)
	p, err := buildServing(t, tr)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	floor, err := policystate.ReadRoute(filepath.Join(tr.dir, "routefloor"), fixtureRouteID)
	if err != nil {
		t.Fatal(err)
	}
	if floor.Serial != 1 || floor.Digest != route.Digest() {
		t.Errorf("the floor after the start is %+v, want serial 1 and %s", floor, route.Digest())
	}
	if p.stopSource() != p.stops.poller {
		t.Errorf("the stop source is %T, want the stop list's reader", p.stopSource())
	}
	if st := p.stopSource().Current().State(); st != reaction.Clear {
		t.Errorf("the stop state of a list holding its header is %v, want clear", st)
	}

	bare := newTree(t)
	q, err := buildServing(t, bare)
	if err != nil {
		t.Fatalf("build without a route: %v", err)
	}
	if q.stops != nil || q.stopSource() != gateway.StopsDisabled() {
		t.Errorf("a plane with no route has stops %v and source %T", q.stops, q.stopSource())
	}
}

// TestARouteTheFloorDoesNotTakeRefusesTheStart: a route below the floor's
// serial, and one at it with another digest, are refused and leave the floor
// as it was.
func TestARouteTheFloorDoesNotTakeRefusesTheStart(t *testing.T) {
	for _, c := range []struct {
		name   string
		serial int64
		digest string
		want   error
	}{
		{"below the floor", 2, "", policystate.ErrRouteBelowFloor},
		{"at the floor with another digest", 1, "sha256:" + strings.Repeat("0", 64), policystate.ErrRouteForked},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := newTree(t)
			route := tr.withReaction(t)
			digest := c.digest
			if digest == "" {
				digest = route.Digest()
			}
			floorDir := filepath.Join(tr.dir, "routefloor")
			if _, err := policystate.RaiseRoute(context.Background(), floorDir, fixtureRouteID, c.serial, digest); err != nil {
				t.Fatal(err)
			}
			before := floorBytes(t, floorDir)
			refusesStart(t, tr, c.want, "reaction.floor_dir")
			if after := floorBytes(t, floorDir); after != before {
				t.Errorf("a refused start changed the floor from %q to %q", before, after)
			}
		})
	}
}

// floorBytes is what the route floor directory's files hold, by name.
func floorBytes(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: a file of the test's own temp dir
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(e.Name() + "=" + string(raw) + "\n")
	}
	return b.String()
}

// TestARemovedFloorRefusesTheStartAndNothingMakesOne: with the route's floor
// file gone, or its whole directory, the start is refused and leaves no floor
// behind.
func TestARemovedFloorRefusesTheStartAndNothingMakesOne(t *testing.T) {
	t.Run("the floor file", func(t *testing.T) {
		tr := newTree(t)
		tr.withReaction(t)
		floorDir := filepath.Join(tr.dir, "routefloor")
		entries, err := os.ReadDir(floorDir)
		if err != nil {
			t.Fatal(err)
		}
		removed := ""
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".route.json") {
				removed = filepath.Join(floorDir, e.Name())
			}
		}
		if removed == "" {
			t.Fatalf("no floor file of %s in %v", fixtureRouteID, entries)
		}
		if err := os.Remove(removed); err != nil {
			t.Fatal(err)
		}
		refusesStart(t, tr, policystate.ErrNoFloor, "reaction.floor_dir")
		if _, err := os.Lstat(removed); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the refused start left a floor file: %v", err)
		}
	})
	t.Run("the floor directory", func(t *testing.T) {
		tr := newTree(t)
		tr.withReaction(t)
		floorDir := filepath.Join(tr.dir, "routefloor")
		if err := os.RemoveAll(floorDir); err != nil {
			t.Fatal(err)
		}
		refusesStart(t, tr, policystate.ErrNotStateDir, "reaction.floor_dir")
		if _, err := os.Lstat(floorDir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the refused start made a floor directory: %v", err)
		}
	})
}

// TestARouteThatDoesNotVerifyRefusesTheStart: a route signed with another key
// than the one configured, and a route's envelope under another payload
// type, are refused before the floor is touched.
func TestARouteThatDoesNotVerifyRefusesTheStart(t *testing.T) {
	t.Run("signed with another key", func(t *testing.T) {
		tr := newTree(t)
		route := tr.withReaction(t)
		other := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", ed25519.SeedSize)))
		writeRouteFile(t, tr.dir, route, other, routeSigningKey().Public().(ed25519.PublicKey))
		refusesStart(t, tr, reaction.ErrRouteKey, "reaction.route")
		unraised(t, tr)
	})
	t.Run("another payload type", func(t *testing.T) {
		tr := newTree(t)
		route := tr.withReaction(t)
		env, err := reaction.SignRoute(route, routeSigningKey())
		if err != nil {
			t.Fatal(err)
		}
		env.PayloadType = reaction.LiftPayloadType
		writeEnvelope(t, tr.dir, env)
		refusesStart(t, tr, reaction.ErrRoutePayloadType, "reaction.route")
		unraised(t, tr)
	})
}

// unraised fails unless the route floor still holds no serial.
func unraised(t *testing.T, tr tree) {
	t.Helper()
	floor, err := policystate.ReadRoute(filepath.Join(tr.dir, "routefloor"), fixtureRouteID)
	if err != nil || floor.HasSerial() {
		t.Errorf("the floor after a refused route is %+v, %v; want no serial yet", floor, err)
	}
}

// TestARouteTheConfigurationDoesNotServeRefusesTheStart: a route of another
// tenant than the listener's, and a route whose key is the policy key, are
// refused at the start.
func TestARouteTheConfigurationDoesNotServeRefusesTheStart(t *testing.T) {
	t.Run("another tenant", func(t *testing.T) {
		tr := newTree(t)
		tr.withReaction(t)
		writeRouteFile(t, tr.dir, readRouteDocument(t, routeDocument("globex", 1)), routeSigningKey(), routeSigningKey().Public().(ed25519.PublicKey))
		_, err := buildServing(t, tr)
		if err == nil || !strings.Contains(err.Error(), "tenant") {
			t.Fatalf("build = %v, want a refusal naming the tenant", err)
		}
		unraised(t, tr)
	})
	t.Run("the policy key signs the route", func(t *testing.T) {
		tr := newTree(t)
		route := tr.withReaction(t)
		writeRouteFile(t, tr.dir, route, fixtureKey(), fixtureKey().Public().(ed25519.PublicKey))
		refusesStart(t, tr, reaction.ErrKeysEqual, "policy.public_key")
		unraised(t, tr)
	})
}

// signedDirectly replaces the tree's route with a route of rule at version,
// signed with the route key by other means than route sign, and replaces the
// stop list with one holding that route's header, written here since no
// writer starts a list under a route naming a rule that may not stop, so
// only the start's check of the rule stands between the route and a serving
// plane.
func signedDirectly(t *testing.T, tr tree, rule, version string) {
	t.Helper()
	route := readRouteDocument(t, routeDocumentOf(runsTenant, 1, rule, version))
	writeRouteFile(t, tr.dir, route, routeSigningKey(), routeSigningKey().Public().(ed25519.PublicKey))
	header, err := reaction.HeaderFor(route, "lst-0123456789abcdef0123456789abcdef").Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tr.dir, "stops", stoplist.FileName), append(header, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mayNotStop is each rule, at a version, a route may not name: rules whose
// finding may not stop a run, an id no rule has, and rules that may stop at a
// version that is not their own, one a version it had before.
var mayNotStop = []struct{ rule, version string }{
	{"EXCEPTION_TAKEN", "1"}, {"DENIED_ACTION_RETRIED_AROUND", "1"}, {"REQUIRED_STEP_SKIPPED", "1"},
	{"NO_SUCH_RULE", "1"}, {"REPEATED_DENIAL", "9"}, {"REPEATED_DENIAL", "1"}, {"STEP_OUTSIDE_PROCEDURE", "2"},
}

// TestARouteNamingARuleThatMayNotStopRefusesTheStart: a route naming a rule
// whose finding may not stop a run, no rule supervise has, or a stopping rule
// at another version, is refused before the floor is touched. The route
// naming REPEATED_DENIAL version "2" over a list written the same way is the
// control, and starts.
func TestARouteNamingARuleThatMayNotStopRefusesTheStart(t *testing.T) {
	for _, c := range mayNotStop {
		t.Run(c.rule+" "+c.version, func(t *testing.T) {
			tr := newTree(t)
			tr.withReaction(t)
			signedDirectly(t, tr, c.rule, c.version)
			refusesStart(t, tr, reaction.ErrRouteRuleStops,
				`reaction.route: rules[0]: reaction: the route names a rule that may not stop a run: rule_id "`+c.rule+`" rule_version "`+c.version+`"`)
			unraised(t, tr)
		})
	}
	tr := newTree(t)
	tr.withReaction(t)
	signedDirectly(t, tr, "REPEATED_DENIAL", "2")
	if _, err := buildServing(t, tr); err != nil {
		t.Fatalf("the control route: %v", err)
	}
}

// TestAStopListThatCannotBeServedRefusesTheStart: a list that is not there,
// and one whose header names another route, are refused at the first read,
// and leave the route floor as it was.
func TestAStopListThatCannotBeServedRefusesTheStart(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		tr := newTree(t)
		tr.withReaction(t)
		if err := os.Remove(filepath.Join(tr.dir, "stops", stoplist.FileName)); err != nil {
			t.Fatal(err)
		}
		refusesStart(t, tr, stoplist.ErrNotServable, "reaction.stops")
		unraised(t, tr)
	})
	t.Run("another route's list", func(t *testing.T) {
		tr := newTree(t)
		tr.withReaction(t)
		if err := os.Remove(filepath.Join(tr.dir, "stops", stoplist.FileName)); err != nil {
			t.Fatal(err)
		}
		older := readRouteDocument(t, routeDocument("acme", 2))
		if _, err := stopwrite.Init(context.Background(), filepath.Join(tr.dir, "stops"), older, time.Now()); err != nil {
			t.Fatal(err)
		}
		refusesStart(t, tr, stoplist.ErrNotServable, "reaction.stops")
		unraised(t, tr)
	})
}
