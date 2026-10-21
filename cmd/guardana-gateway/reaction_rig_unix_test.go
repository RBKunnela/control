//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/runs"
)

// The route these cases sign: one rule of the refund procedure, whose stops
// last an hour.
const (
	fixtureRouteID   = "refunds"
	fixtureProcedure = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fixtureRule      = "STEP_OUTSIDE_PROCEDURE"
	fixtureFinding   = "finding-1"
)

// routeSigningKey and liftSigningKey are apart from the fixture's policy and
// freshness keys, whose seeds are 7 and 21.
func routeSigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
}

func liftSigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4c}, ed25519.SeedSize))
}

// routeDocument is a route of tenant at serial, written out by hand.
func routeDocument(tenant string, serial int64) string {
	return routeDocumentOf(tenant, serial, fixtureRule, "1")
}

// routeDocumentOf is a route of tenant at serial whose one rule is rule of
// the refund procedure, at rule version version.
func routeDocumentOf(tenant string, serial int64, rule, version string) string {
	lift := base64.StdEncoding.EncodeToString(liftSigningKey().Public().(ed25519.PublicKey))
	return `{"kind":"reaction-route/v1alpha1","route_id":"` + fixtureRouteID + `","serial":` + strconv.FormatInt(serial, 10) +
		`,"tenant_id":"` + tenant + `","scope":"run","lift_public_key":"` + lift + `","rules":[` +
		`{"procedure_id":"refund","version":"3","digest":"` + fixtureProcedure + `","rule_id":"` + rule +
		`","rule_version":"` + version + `","expires_seconds":3600}]}`
}

// readRouteDocument reads doc as a route, failing the case where it is none.
func readRouteDocument(t *testing.T, doc string) reaction.Route {
	t.Helper()
	r, err := reaction.ParseRoute([]byte(doc))
	if err != nil {
		t.Fatalf("the case's route does not parse: %v", err)
	}
	return r
}

// writeRouteFile signs route with key, writes it as dir/route.json and the
// route key's public line, of the key the configuration names, as
// dir/route.pub.
func writeRouteFile(t *testing.T, dir string, route reaction.Route, key ed25519.PrivateKey, named ed25519.PublicKey) {
	t.Helper()
	env, err := reaction.SignRoute(route, key)
	if err != nil {
		t.Fatalf("signing the route: %v", err)
	}
	writeEnvelope(t, dir, env)
	line := base64.StdEncoding.EncodeToString(named) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "route.pub"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeEnvelope(t *testing.T, dir string, env reaction.Envelope) {
	t.Helper()
	raw, err := reaction.MarshalRouteFile(env)
	if err != nil {
		t.Fatalf("writing the route file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "route.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// layOutReaction writes, in dir, a route of the listener's tenant at serial
// 1 signed with the route key, a route floor holding no serial yet, a stop list holding its
// header and a runs directory holding no run, and returns the route.
func layOutReaction(t *testing.T, dir string) reaction.Route {
	t.Helper()
	route := readRouteDocument(t, routeDocument(runsTenant, 1))
	writeRouteFile(t, dir, route, routeSigningKey(), routeSigningKey().Public().(ed25519.PublicKey))
	if err := policystate.InitRoute(context.Background(), filepath.Join(dir, "routefloor"), fixtureRouteID); err != nil {
		t.Fatalf("making the route floor: %v", err)
	}
	for _, sub := range []string{"stops", "runs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := runs.InitAdmin(context.Background(), filepath.Join(dir, "runs"))
	if err == nil {
		err = admin.Close()
	}
	if err != nil {
		t.Fatalf("making the runs directory: %v", err)
	}
	if _, err := stopwrite.Init(context.Background(), filepath.Join(dir, "stops"), route, time.Now()); err != nil {
		t.Fatalf("starting the stop list: %v", err)
	}
	return route
}

// reactionKeys is the configuration's reaction block over layOutReaction's
// files, with a runs directory, as YAML.
const reactionKeys = `runs:
  dir: runs
reaction:
  route: route.json
  public_key: route.pub
  floor_dir: routefloor
  stops: stops
  poll_interval: 100ms
`

// withReaction lays out a route in the tree and sets the configuration's
// reaction keys through the environment.
func (tr tree) withReaction(t *testing.T) reaction.Route {
	t.Helper()
	route := layOutReaction(t, tr.dir)
	for key, value := range map[string]string{
		"runs.dir": "runs", "reaction.route": "route.json", "reaction.public_key": "route.pub",
		"reaction.floor_dir": "routefloor", "reaction.stops": "stops", "reaction.poll_interval": "100ms",
	} {
		setEnv(t, key, value)
	}
	return route
}

// stopOf is a stop of runID in the listener's tenant for findingID under the
// fixture's rule, written at now and lasting half an hour.
func stopOf(runID, findingID string, now time.Time) reaction.Stop {
	created := now.UTC().Truncate(time.Second)
	return reaction.Stop{
		EntryID: reaction.EntryID(findingID), TenantID: runsTenant, RunID: runID, FindingID: findingID,
		ProcedureID: "refund", ProcedureVersion: "3", ProcedureDigest: fixtureProcedure,
		RuleID: fixtureRule, RuleVersion: "1",
		CreatedAt: created, ExpiresAt: created.Add(30 * time.Minute),
	}
}

// appendStop writes a stop of runID for fixtureFinding to the list in dir.
func appendStop(t *testing.T, dir string, route reaction.Route, runID string) {
	t.Helper()
	stopAt := func(now time.Time) (reaction.Stop, error) { return stopOf(runID, fixtureFinding, now), nil }
	if _, _, covered, err := stopwrite.AppendFinding(context.Background(), filepath.Join(dir, "stops"), route, time.Now, stopAt); err != nil || covered {
		t.Fatalf("appending a stop: covered %v, %v", covered, err)
	}
}
