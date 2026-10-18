package stopwrite_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"testing"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// routeNamingAlso is testRoute's rule and the rule id at version beside it.
func routeNamingAlso(t *testing.T, id, version string) reaction.Route {
	t.Helper()
	pub := base64.StdEncoding.EncodeToString(liftKey().Public().(ed25519.PublicKey))
	rule := func(id, version, extra string) string {
		return `{"procedure_id":"refund","version":"1","digest":"` + refundDigest(t) + `","rule_id":"` + id +
			`","rule_version":"` + version + `"` + extra + `}`
	}
	doc := `{"kind":"reaction-route/v1alpha1","route_id":"refunds","serial":3,"tenant_id":"acme","scope":"run",` +
		`"lift_public_key":"` + pub + `","rules":[` + rule("STEP_OUTSIDE_PROCEDURE", "1", `,"expires_seconds":3600`) +
		`,` + rule(id, version, "") + `]}`
	r, err := reaction.ParseRoute([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRoute: %v", err)
	}
	return r
}

// headerOnly is a fresh directory holding a list of r's header alone, written
// here rather than by Init.
func headerOnly(t *testing.T, r reaction.Route) string {
	t.Helper()
	line, err := reaction.HeaderFor(r, "lst-0123456789abcdef0123456789abcdef").Marshal()
	if err != nil {
		t.Fatal(err)
	}
	dir := emptyDir(t)
	if err := os.WriteFile(listPath(dir), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func refusedForTheRule(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, reaction.ErrRouteRuleStops) {
		t.Errorf("%s = %v, want ErrRefused for a rule that may not stop", what, err)
	}
}

// TestNoWriterTakesARouteNamingARuleThatMayNotStop: Init, an append and a
// carry from or into a list are refused under a route that names a rule
// outside the table, or a stopping rule at another version, beside one that
// may stop, though the judge accepts every list involved; nothing is written.
// A carry from a route naming a superseded version alone is taken.
// The same writes under a route of REPEATED_DENIAL at version "2" are the
// control.
func TestNoWriterTakesARouteNamingARuleThatMayNotStop(t *testing.T) {
	good := routeNamingAlso(t, "REPEATED_DENIAL", "2")
	for _, c := range []struct{ id, version string }{
		{"EXCEPTION_TAKEN", "1"}, {"STEP_OUT_OF_ORDER", "1"}, {"NO_SUCH_RULE", "1"},
		{"REPEATED_DENIAL", "9"}, {"REPEATED_DENIAL", "1"}, {"DEADLINE_EXCEEDED", "2"},
	} {
		bad := routeNamingAlso(t, c.id, c.version)
		name := c.id + " " + c.version
		dir := emptyDir(t)
		_, err := stopwrite.Init(bg, dir, bad, clock0)
		refusedForTheRule(t, name+": Init", err)
		noList(t, name+": Init", dir)

		list := headerOnly(t, bad)
		before := content(t, list)
		_, err = stopwrite.AppendStop(bg, list, bad, stopOf(t, "f-1", "run-1", clock0), clock0)
		refusedForTheRule(t, name+": AppendStop", err)
		_, _, err = appendFinding(bg, list, bad, stopOf(t, "f-1", "run-1", clock0), clock0)
		refusedForTheRule(t, name+": AppendFinding", err)
		_, err = stopwrite.AppendCovered(bg, list, bad, coveredOf("f-2", "run-1", clock0), clock0)
		refusedForTheRule(t, name+": AppendCovered", err)
		if !bytes.Equal(content(t, list), before) {
			t.Errorf("%s: a refused append changed the list", name)
		}

		into := emptyDir(t)
		_, err = stopwrite.Carry(bg, list, bad, into, good, clock0)
		if c == (struct{ id, version string }{"REPEATED_DENIAL", "1"}) {
			if err != nil {
				t.Errorf("%s: Carry from it, which a superseded version allows: %v", name, err)
			}
			into = emptyDir(t)
		} else {
			refusedForTheRule(t, name+": Carry from it", err)
			noList(t, name+": Carry from it", into)
		}
		from, _ := initDir(t, good)
		_, err = stopwrite.Carry(bg, from, good, into, bad, clock0)
		refusedForTheRule(t, name+": Carry into it", err)
		noList(t, name+": Carry into it", into)
	}

	dir, _ := initDir(t, good)
	if _, err := stopwrite.AppendStop(bg, dir, good, stopOf(t, "f-1", "run-1", clock0), clock0); err != nil {
		t.Fatalf("the control's AppendStop: %v", err)
	}
	list := headerOnly(t, good)
	if _, err := stopwrite.AppendStop(bg, list, good, stopOf(t, "f-1", "run-1", clock0), clock0); err != nil {
		t.Fatalf("the control's AppendStop to a header written here: %v", err)
	}
	if _, err := stopwrite.Carry(bg, list, good, emptyDir(t), good, clock0); err != nil {
		t.Fatalf("the control's Carry: %v", err)
	}
}
