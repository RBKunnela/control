package gatewayconfig

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/reaction"
)

const signedReaction = `
runs:
  dir: runs
reaction:
  route: route.json
  floor_dir: routefloor
  stops: stops
  stops_floor_dir: stopsfloor
`

// TestASignedRouteNeedsAStopListFloorAndNoRouteKey: under the signed
// authority the stop list floor is one of the reaction keys and the route
// key is refused; under any other the floor is refused; the floor keeps
// apart from the stops directory.
func TestASignedRouteNeedsAStopListFloorAndNoRouteKey(t *testing.T) {
	cfg, err := Load(write(t, signedBlock+signedReaction), os.Environ())
	if err != nil {
		t.Fatalf("a signed reaction block was refused: %v", err)
	}
	if !cfg.Reaction.Configured() || cfg.Reaction.StopsFloorDir != "stopsfloor" {
		t.Errorf("reaction = %+v", cfg.Reaction)
	}
	without := strings.Replace(signedReaction, "  stops_floor_dir: stopsfloor\n", "", 1)
	for _, c := range []struct{ name, text, says string }{
		{"no stop list floor", signedBlock + without, "reaction.stops_floor_dir: not set"},
		{"a route key", signedBlock + signedReaction + "  public_key: route.pub\n", "reaction.public_key: set, and the signed authority"},
		{"a stop list floor under directory", fileProvider + withRoute + "  stops_floor_dir: stopsfloor\n", "reaction.stops_floor_dir: set, and the directory authority"},
		{"the floor as the stops directory", signedBlock + strings.Replace(signedReaction, "stops_floor_dir: stopsfloor", "stops_floor_dir: stops", 1), "reaction.stops: "},
		{"the floor inside the stops directory", signedBlock + strings.Replace(signedReaction, "stops_floor_dir: stopsfloor", "stops_floor_dir: stops/floor", 1), "reaction.stops: "},
	} {
		if _, err := Load(write(t, c.text), os.Environ()); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v, want a refusal saying %q", c.name, err, c.says)
		}
	}
}

// routeDocFor is a route of kind for plane, tenant acme and project, as a
// plane reads it once an operator signed it: a v1alpha2 one names no plane.
func routeDocFor(t *testing.T, kind, plane, project string) reaction.Route {
	t.Helper()
	doc := map[string]any{"kind": kind, "alg": "ed25519", "keyId": "ed25519-0000000000000000", "route_id": "refunds", "serial": 1,
		"tenant_id": "acme", "project_id": project, "file": "/plane/route.json", "plane_id": plane,
		"rules": []any{map[string]any{"procedure_id": "refund", "version": "3",
			"digest":  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"rule_id": "STEP_OUTSIDE_PROCEDURE", "rule_version": "1", "scope": "run"}}}
	if plane == "" {
		delete(doc, "plane_id")
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	body, err := canon.CanonicalizeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := reaction.ParseRoute(body)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestARouteIsOfTheAuthoritysFormatAndThePlanesProject: under signed a
// v1alpha3 route of the plane's id and project is taken and one of another
// id or project, a v1alpha1 route or the zero route refused; a v1alpha2
// route is refused under any authority, naming the command that upgrades
// it; elsewhere a v1alpha3 route is refused.
func TestARouteIsOfTheAuthoritysFormatAndThePlanesProject(t *testing.T) {
	signed, err := Load(write(t, signedBlock+signedReaction), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	v3, v2 := reaction.SignedRouteKindV3, reaction.SignedRouteKind
	if err := signed.CheckRoute(routeDocFor(t, v3, "plane-a", "orders"), nil); err != nil {
		t.Errorf("a v1alpha3 route of the plane's id and project: %v", err)
	}
	other := routeConfig(t, seeded(1), seeded(2))
	// The zero route's tenant is empty, so only a configuration of no tenant
	// lets it past the tenant check to the format check.
	untenanted := *signed
	untenanted.TenantID, untenanted.Listener.PrincipalTenant = "", ""
	for _, c := range []struct {
		name  string
		cfg   *Config
		route reaction.Route
		says  string
	}{
		{"another project", signed, routeDocFor(t, v3, "plane-a", "billing"), "project_id"},
		{"another plane_id", signed, routeDocFor(t, v3, "plane-b", "orders"), "plane_id"},
		{"a v1alpha1 route under signed", signed, routeFor(t, "acme", seeded(4)), "v1alpha1 route under the signed authority"},
		{"a v1alpha2 route under signed", signed, routeDocFor(t, v2, "", "orders"), "route sign"},
		{"the zero route under signed", &untenanted, reaction.Route{}, "no route was read"},
		{"a v1alpha3 route under memory", other, routeDocFor(t, v3, "plane-a", "orders"), "v1alpha3 route under the memory authority"},
		{"a v1alpha2 route under memory", other, routeDocFor(t, v2, "", "orders"), "route sign"},
	} {
		if err := c.cfg.CheckRoute(c.route, seeded(3)); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v, want a refusal saying %q", c.name, err, c.says)
		}
	}
}
