package gatewayconfig

import (
	"os"
	"strings"
	"testing"

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

// routeDocFor is a v1alpha2 route of tenant and project, as a plane reads it
// once an operator signed it.
func routeDocFor(t *testing.T, tenant, project string) reaction.Route {
	t.Helper()
	doc := `{"kind":"reaction-route/v1alpha2","route_id":"refunds","serial":1,"tenant_id":"` + tenant + `","project_id":"` + project + `",` +
		`"rules":[{"procedure_id":"refund","version":"3","digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",` +
		`"rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run"}]}`
	body, err := reaction.SignedRouteBody([]byte(doc), "ed25519-0000000000000000", "/plane/route.json")
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
// v1alpha2 route of the plane's project is taken and one of another project,
// or a v1alpha1 route, refused; elsewhere a v1alpha2 route is refused.
func TestARouteIsOfTheAuthoritysFormatAndThePlanesProject(t *testing.T) {
	signed, err := Load(write(t, signedBlock+signedReaction), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.CheckRoute(routeDocFor(t, "acme", "orders"), nil); err != nil {
		t.Errorf("a v1alpha2 route of the plane's project: %v", err)
	}
	if err := signed.CheckRoute(routeDocFor(t, "acme", "billing"), nil); err == nil || !strings.Contains(err.Error(), "project_id") {
		t.Errorf("a v1alpha2 route of another project: %v", err)
	}
	if err := signed.CheckRoute(routeFor(t, "acme", seeded(4)), seeded(3)); err == nil || !strings.Contains(err.Error(), "v1alpha1 route under the signed authority") {
		t.Errorf("a v1alpha1 route under signed: %v", err)
	}
	other := routeConfig(t, seeded(1), seeded(2))
	if err := other.CheckRoute(routeDocFor(t, "acme", "orders"), seeded(3)); err == nil || !strings.Contains(err.Error(), "v1alpha2 route under the memory authority") {
		t.Errorf("a v1alpha2 route under memory: %v", err)
	}
}
