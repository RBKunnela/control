package stopwrite_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// v2RouteIn is the route of plane-a's tenant and project at serial as a 0.17
// operator signed it, v1alpha2 and naming no plane, taken as the route a
// list in dir is carried from.
func v2RouteIn(t *testing.T, dir string, serial int) reaction.Route {
	t.Helper()
	return v2RouteWith(t, dir, serial, v2Rule(t, "STEP_OUTSIDE_PROCEDURE"))
}

// v2Rule is a v1alpha2 rule stopping a run of refund version "1" for an hour
// under rule id at version "1".
func v2Rule(t *testing.T, id string) map[string]any {
	return map[string]any{"procedure_id": "refund", "version": "1", "digest": refundDigest(t),
		"rule_id": id, "rule_version": "1", "scope": "run", "expires_seconds": 3600}
}

// v2RouteWith is v2RouteIn with rules.
func v2RouteWith(t *testing.T, dir string, serial int, rules ...map[string]any) reaction.Route {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"kind": "reaction-route/v1alpha2", "alg": "ed25519", "keyId": operatorID(), "route_id": "refunds", "serial": serial,
		"tenant_id": "acme", "project_id": "shop", "file": "/plane/route.json", "rules": rules,
	})
	noErr(t, err)
	body, err := canon.CanonicalizeJSON(raw)
	noErr(t, err)
	r, err := reaction.VerifySignedCarrySource(envelopeBy(t, operatorKey(), reaction.SignedRoutePayloadType, body), planeVoucher(dir))
	if err != nil {
		t.Fatalf("VerifySignedCarrySource: %v", err)
	}
	return r
}

// v2ListIn writes a 2.0 list under r in dir at serial: stops of run-1 and
// run-2, a v1alpha2 lift of run-2 and a covered line of run-1, and returns
// its head digest.
func v2ListIn(t *testing.T, dir string, r reaction.Route, serial int64) string {
	t.Helper()
	body, err := reaction.HeaderBody(reaction.Header{ListID: "lst-old", RouteID: r.ID(), RouteSerial: r.Serial(), RouteDigest: r.Digest(),
		Signed: reaction.HeaderSigned{KeyID: operatorID(), TenantID: "acme", ProjectID: "shop", File: listPath(dir), Serial: serial}})
	noErr(t, err)
	header, err := reaction.SignedHeaderLine(envelopeBy(t, operatorKey(), reaction.SignedHeaderPayloadType, body))
	noErr(t, err)
	head := bundle.Digest(body)
	liftBody, err := reaction.SignedLift{KeyID: operatorID(), ListHead: head, RunID: "run-2", ThroughLine: 3,
		TenantID: "acme", Project: "shop", File: listPath(dir)}.Payload()
	noErr(t, err)
	stop := func(finding, run string) []byte {
		s := stopOf(t, finding, run, clock0)
		s.ProjectID, s.Scope = "shop", reaction.ScopeRun
		line, err := s.Marshal()
		noErr(t, err)
		return line
	}
	lift, err := reaction.LiftLine{RunID: "run-2", ThroughLine: 3,
		Envelope: envelopeBy(t, operatorKey(), reaction.SignedLiftPayloadType, liftBody)}.Marshal()
	noErr(t, err)
	covered, err := reaction.Covered{FindingID: "f-4", TenantID: "acme", RunID: "run-1", ProjectID: "shop", CreatedAt: clock0}.Marshal()
	noErr(t, err)
	for _, line := range [][]byte{header, stop("f-1", "run-1"), stop("f-2", "run-2"), lift, covered} {
		appendRaw(t, dir, line)
	}
	return head
}

// TestACarryFromA20ListChainsA30Header: a 2.0 list of a v1alpha2 route is
// carried into a 3.0 list of a v1alpha3 route: the new header names the
// plane, takes the next serial and names the old head as its previous; the
// stop no lift ended is carried as scope run with its run as its subject,
// the lifted run's finding and the covered one are covered, and every line
// is 3.0. The old list is not served under the new route.
func TestACarryFromA20ListChainsA30Header(t *testing.T) {
	from := emptyDir(t)
	fromRoute := v2RouteIn(t, from, 3)
	head := v2ListIn(t, from, fromRoute, 5)
	into := emptyDir(t)
	route := signedRouteIn(t, into, 4)
	c, err := stopwrite.CarrySigned(bg, from, fromRoute, into, route, clock0, signer(), nil)
	noErr(t, err)
	if s := c.Header.Signed; s.Serial != 6 || s.Previous != head || s.PlaneID != "plane-a" || c.Stops != 1 || c.Covered != 2 {
		t.Fatalf("carried: serial %d previous %q plane %q, %d stops, %d covered", s.Serial, s.Previous, s.PlaneID, c.Stops, c.Covered)
	}
	raw := content(t, into)
	expectEveryLine30(t, raw)
	l, err := reaction.Judge(route, reaction.Prefix{}, raw, clock0, poll)
	noErr(t, err)
	e := l.Entries()
	if len(e) != 1 || e[0].RunID != "run-1" || e[0].Scope != reaction.ScopeRun || e[0].Subject != "run-1" {
		t.Fatalf("entries %+v, want run-1's stop of subject run-1", e)
	}
	if _, err := reaction.Judge(route, reaction.Prefix{}, content(t, from), clock0, poll); !errors.Is(err, reaction.ErrListUpgrade) {
		t.Fatalf("the old list under the new route: %v, want %v", err, reaction.ErrListUpgrade)
	}
}

func expectEveryLine30(t *testing.T, raw []byte) {
	t.Helper()
	for i, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'}) {
		l, err := reaction.ParseLine(line)
		if err != nil || l.Version != reaction.SignedListVersionV3 {
			t.Fatalf("line %d: version %q, %v", i+1, l.Version, err)
		}
	}
}

// TestACarryIntoA20ListIsRefused: a 0.18 writer starts no 2.0 list, and
// carries none into one.
func TestACarryIntoA20ListIsRefused(t *testing.T) {
	from := emptyDir(t)
	fromRoute := v2RouteIn(t, from, 3)
	v2ListIn(t, from, fromRoute, 5)
	into := emptyDir(t)
	if _, err := stopwrite.CarrySigned(bg, from, fromRoute, into, v2RouteIn(t, into, 4), clock0, signer(), nil); !errors.Is(err, stopwrite.ErrRefused) {
		t.Fatalf("a carry into a v1alpha2 route's list: %v", err)
	}
	if _, err := stopwrite.InitSigned(bg, into, v2RouteIn(t, into, 4), clock0, signer(), 1); !errors.Is(err, stopwrite.ErrRefused) {
		t.Fatalf("a 2.0 list started: %v", err)
	}
	if _, err := stopwrite.Carry(bg, from, fromRoute, into, signedRouteIn(t, into, 4), clock0); !errors.Is(err, stopwrite.ErrRefused) {
		t.Fatalf("a carry by route key of a signed list: %v", err)
	}
	if _, _, err := appendFinding(bg, from, fromRoute, signedStop(t, "f-9", "run-9", "shop", clock0.Add(time.Second)), clock0); !errors.Is(err, reaction.ErrRouteUpgrade) {
		t.Fatalf("a stop appended under a v1alpha2 route: %v", err)
	}
}

func noErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
