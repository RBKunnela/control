package signedstops_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

const routeDoc = `{"kind":"reaction-route/v1alpha2","route_id":"refunds","serial":7,"tenant_id":"t1","project_id":"A",
 "rules":[{"procedure_id":"refund","version":"3","digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
 "rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run","expires_seconds":3600}]}`

// routeFor is the route dave signs for the route file of f's plane, taken
// by the roster voucher of the plane whose stop list is in dir.
func (f *fixture) routeFor(t *testing.T, routeFile, dir string, verify func(reaction.Envelope, reaction.Voucher) (reaction.Route, error)) reaction.Route {
	t.Helper()
	body, err := reaction.SignedRouteBody([]byte(routeDoc), keyID("dave"), routeFile)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(reaction.SignedRoutePayloadType, body, key("dave"))
	if err != nil {
		t.Fatal(err)
	}
	env := reaction.Envelope{PayloadType: reaction.SignedRoutePayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: keyID("dave"), Signature: sig}}}
	plane, err := signedstops.PlaneOf("t1", "A", f.plane.RouteFile, dir, stoplist.FileName)
	if err != nil {
		t.Fatal(err)
	}
	v, err := signedstops.NewRoster(f.roster, plane)
	if err != nil {
		t.Fatal(err)
	}
	r, err := verify(env, v)
	if err != nil {
		t.Fatalf("the route for %s: %v", dir, err)
	}
	return r
}

func alice() stopwrite.Signer {
	return stopwrite.Signer{KeyID: keyID("alice"), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key("alice"))
	}}
}

func (f *fixture) dir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(f.base, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// listAt is a list a judge accepted and the bytes it was judged from.
type listAt struct {
	l   reaction.List
	raw []byte
}

func judged(t *testing.T, dir string, r reaction.Route) (listAt, error) {
	t.Helper()
	raw, err := stoplist.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := reaction.Judge(r, reaction.Prefix{}, raw, now, 0)
	return listAt{l: l, raw: raw}, err
}

func mustJudge(t *testing.T, dir string, r reaction.Route) listAt {
	t.Helper()
	l, err := judged(t, dir, r)
	if err != nil {
		t.Fatalf("Judge %s: %v", dir, err)
	}
	return l
}

func (c chainFixture) take(t *testing.T, x listAt) (policystate.StopsFloor, error) {
	t.Helper()
	return c.floor.Take(t.Context(), x.l, x.raw)
}

// chainFixture is a plane's stop list floor and the first list its plane
// took, at serial 1.
type chainFixture struct {
	*fixture
	floorDir string
	floor    signedstops.Floor
	first    listAt
}

func newChain(t *testing.T) chainFixture {
	t.Helper()
	f := newFixture(t)
	c := chainFixture{fixture: f, floorDir: filepath.Join(f.base, "floor")}
	if err := policystate.InitStops(t.Context(), c.floorDir, "t1", "A"); err != nil {
		t.Fatal(err)
	}
	floor, err := signedstops.NewFloor(c.floorDir, "t1", "A")
	if err != nil {
		t.Fatal(err)
	}
	c.floor = floor
	stops := filepath.Join(f.base, "stops")
	r := f.routeFor(t, f.plane.RouteFile, stops, reaction.VerifySignedRoute)
	if _, err := stopwrite.InitSigned(t.Context(), stops, r, now, alice(), 1); err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	c.first = mustJudge(t, stops, r)
	return c
}

// fresh is a list started in a directory of its own at serial, naming no
// previous header.
func (c chainFixture) fresh(t *testing.T, name string, serial int64) listAt {
	t.Helper()
	dir := c.dir(t, name)
	r := c.routeFor(t, c.plane.RouteFile, dir, reaction.VerifySignedRoute)
	if _, err := stopwrite.InitSigned(t.Context(), dir, r, now, alice(), serial); err != nil {
		t.Fatal(err)
	}
	return mustJudge(t, dir, r)
}

// carried is the first list carried into a directory of its own.
func (c chainFixture) carried(t *testing.T) listAt {
	t.Helper()
	from, into := filepath.Join(c.base, "stops"), c.dir(t, "stops2")
	fromRoute := c.routeFor(t, c.plane.RouteFile, from, reaction.VerifySignedCarrySource)
	r := c.routeFor(t, c.plane.RouteFile, into, reaction.VerifySignedRoute)
	got, err := stopwrite.CarrySigned(t.Context(), from, fromRoute, into, r, now, alice(), nil)
	if err != nil {
		t.Fatalf("CarrySigned: %v", err)
	}
	if got.Header.Signed.Serial != 2 || got.Header.Signed.Previous != c.first.l.Header().Signed.Digest {
		t.Fatalf("the carry's header: %+v", got.Header.Signed)
	}
	return mustJudge(t, into, r)
}

// expectFloor expects the floor at serial, x's head and the whole of x's
// bytes as its accepted part.
func (c chainFixture) expectFloor(t *testing.T, what string, serial int64, x listAt) {
	t.Helper()
	stored, err := policystate.ReadStops(c.floorDir, "t1", "A")
	if err != nil || stored.Serial != serial || stored.Digest != x.l.Header().Signed.Digest ||
		stored.Length != int64(len(x.raw)) || stored.Prefix != sha256Of(x.raw) {
		t.Fatalf("%s: the floor %+v, %v; want serial %d and %d bytes", what, stored, err, serial, len(x.raw))
	}
}

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TestTheFloorFollowsTheChainOfHeaders: the plane takes a new list, again,
// then a carry of it, and the floor holds the carry's serial and head.
func TestTheFloorFollowsTheChainOfHeaders(t *testing.T) {
	c := newChain(t)
	for range 2 {
		if _, err := c.take(t, c.first); err != nil {
			t.Fatalf("Take of the first list: %v", err)
		}
	}
	c.expectFloor(t, "the first list", 1, c.first)
	second := c.carried(t)
	if _, err := c.take(t, second); err != nil {
		t.Fatalf("Take of the carry: %v", err)
	}
	c.expectFloor(t, "the carry", 2, second)
}

// TestTheFloorRefusesAListOffTheChain: over a floor at the carry's head,
// the older list, a fresh list naming no previous head and another list at
// the floor's serial are each refused, and the floor does not move; a floor
// of another project is unusable.
func TestTheFloorRefusesAListOffTheChain(t *testing.T) {
	c := newChain(t)
	second := c.carried(t)
	for _, l := range []listAt{c.first, second} {
		if _, err := c.take(t, l); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []struct {
		name string
		l    listAt
		want error
	}{
		{"the list the carry replaced", c.first, stoplist.ErrBelowFloor},
		{"a fresh list above the floor", c.fresh(t, "stops3", 3), stoplist.ErrChain},
		{"another list at the floor's serial", c.fresh(t, "stops4", 2), stoplist.ErrForked},
	} {
		if _, err := c.take(t, r.l); !errors.Is(err, r.want) || errors.Is(err, stoplist.ErrFloor) {
			t.Errorf("%s: %v, want %v and not a floor the plane cannot use", r.name, err, r.want)
		}
	}
	c.expectFloor(t, "after the refusals", 2, second)
	other, err := signedstops.NewFloor(c.floorDir, "t1", "B")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Take(t.Context(), second.l, second.raw); !errors.Is(err, stoplist.ErrFloor) {
		t.Fatalf("a floor of another project: %v", err)
	}
	if _, err := signedstops.NewFloor(c.floorDir, "t1", ""); !errors.Is(err, signedstops.ErrOptions) {
		t.Fatalf("a floor with no project: %v", err)
	}
}

func TestCheckHoldsAHeaderToTheStoredFloor(t *testing.T) {
	stored := policystate.StopsFloor{Tenant: "t1", Project: "A", Serial: 5, Digest: "head5"}
	for _, c := range []struct {
		name   string
		stored policystate.StopsFloor
		h      reaction.HeaderSigned
		want   error
	}{
		{"a floor with no serial takes any header", policystate.StopsFloor{Tenant: "t1", Project: "A"}, reaction.HeaderSigned{Serial: 9, Digest: "x"}, nil},
		{"the floor's own head", stored, reaction.HeaderSigned{Serial: 5, Digest: "head5", Previous: "head4"}, nil},
		{"the next head naming the floor's", stored, reaction.HeaderSigned{Serial: 6, Digest: "head6", Previous: "head5"}, nil},
		{"a later head naming the floor's", stored, reaction.HeaderSigned{Serial: 9, Digest: "head9", Previous: "head5"}, nil},
		{"one below", stored, reaction.HeaderSigned{Serial: 4, Digest: "head4"}, stoplist.ErrBelowFloor},
		{"the floor's serial, another head", stored, reaction.HeaderSigned{Serial: 5, Digest: "other"}, stoplist.ErrForked},
		{"one above, naming another previous", stored, reaction.HeaderSigned{Serial: 6, Digest: "head6", Previous: "other"}, stoplist.ErrChain},
		{"one above, naming none", stored, reaction.HeaderSigned{Serial: 6, Digest: "head6"}, stoplist.ErrChain},
	} {
		err := signedstops.Check(c.stored, c.h)
		if (c.want == nil && err != nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// TestADocumentCopiedToAnotherPlaneOfTheSameProjectIsRefused: two planes of
// tenant t1 and project A, under one roster; the route and the list the
// first plane's operators signed, copied to the second plane, are refused
// there, though every signature verifies and every grant holds.
func TestADocumentCopiedToAnotherPlaneOfTheSameProjectIsRefused(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	first := filepath.Join(f.base, "stops")
	r1 := f.routeFor(t, f.plane.RouteFile, first, reaction.VerifySignedRoute)
	if _, err := stopwrite.InitSigned(ctx, first, r1, now, alice(), 1); err != nil {
		t.Fatal(err)
	}
	f.dir(t, "second")
	secondRouteFile := filepath.Join(f.base, "second", "route.json")
	secondStops := f.dir(t, "second-stops")
	plane2, err := signedstops.PlaneOf("t1", "A", secondRouteFile, secondStops, stoplist.FileName)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := signedstops.NewRoster(f.roster, plane2)
	if err != nil {
		t.Fatal(err)
	}
	body, err := reaction.SignedRouteBody([]byte(routeDoc), keyID("dave"), f.plane.RouteFile)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(reaction.SignedRoutePayloadType, body, key("dave"))
	if err != nil {
		t.Fatal(err)
	}
	copied := reaction.Envelope{PayloadType: reaction.SignedRoutePayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: keyID("dave"), Signature: sig}}}
	if _, err := reaction.VerifySignedRoute(copied, v2); !errors.Is(err, reaction.ErrOtherFile) {
		t.Fatalf("the first plane's route at the second: %v", err)
	}

	raw, err := stoplist.Read(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secondStops, stoplist.FileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r2 := f.routeFor(t, f.plane.RouteFile, secondStops, reaction.VerifySignedRoute)
	if _, err := judged(t, secondStops, r2); !errors.Is(err, reaction.ErrOtherFile) {
		t.Fatalf("the first plane's list at the second: %v", err)
	}
	if _, err := judged(t, first, r1); err != nil {
		t.Fatalf("the list at its own plane: %v", err)
	}
}
