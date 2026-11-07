package stopwrite_test

import (
	"crypto/ed25519"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// operatorKey is the one key the voucher takes.
func operatorKey() ed25519.PrivateKey { return seededKey(0x6f) }

func operatorID() string { return policykey.KeyID(operatorKey().Public().(ed25519.PublicKey)) }

var errSign = errors.New("the key cannot sign")

// voucher takes any signature of operatorKey under the payload type of the
// kind asked about, for the plane whose stop list is in dir.
type voucher struct{ plane reaction.Plane }

func (v voucher) Plane() reaction.Plane { return v.plane }

func (v voucher) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	types := map[reaction.SignedKind]string{
		reaction.VouchRoute: reaction.SignedRoutePayloadType, reaction.VouchHeader: reaction.SignedHeaderPayloadType,
		reaction.VouchLift: reaction.SignedLiftPayloadType,
	}
	pub := operatorKey().Public().(ed25519.PublicKey)
	id := operatorID()
	sig := env.Signatures[0]
	if err := bundle.VerifyBytesAs(types[kind], env.Payload, sig.Signature, sig.KeyID, bundle.Keyring{id: pub}); err != nil {
		return reaction.Signer{}, err
	}
	return reaction.Signer{Subject: "alice", KeyID: id}, nil
}

// signedRouteIn is a v1alpha2 route of tenant acme and project shop at
// serial, taken for the plane whose stop list is in dir.
func signedRouteIn(t testing.TB, dir string, serial int) reaction.Route {
	t.Helper()
	key, id := operatorKey(), operatorID()
	doc := `{"kind":"reaction-route/v1alpha2","route_id":"refunds","serial":` + strconv.Itoa(serial) +
		`,"tenant_id":"acme","project_id":"shop","rules":[{"procedure_id":"refund","version":"1","digest":"` + refundDigest(t) +
		`","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run","expires_seconds":3600}]}`
	body, err := reaction.SignedRouteBody([]byte(doc), id, "/plane/route.json")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(reaction.SignedRoutePayloadType, body, key)
	if err != nil {
		t.Fatal(err)
	}
	env := reaction.Envelope{PayloadType: reaction.SignedRoutePayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: id, Signature: sig}}}
	v := voucher{plane: reaction.Plane{Tenant: "acme", Project: "shop", RouteFile: "/plane/route.json", ListFile: listPath(dir)}}
	r, err := reaction.VerifySignedRoute(env, v)
	if err != nil {
		t.Fatalf("VerifySignedRoute: %v", err)
	}
	return r
}

func signer() stopwrite.Signer {
	key := operatorKey()
	return stopwrite.Signer{KeyID: operatorID(), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key)
	}}
}

func signedStop(t testing.TB, finding, run, project string, created time.Time) reaction.Stop {
	t.Helper()
	s := stopOf(t, finding, run, created)
	s.ProjectID, s.Scope = project, reaction.ScopeRun
	return s
}

func TestInitSignedWritesAHeaderThePlaneTakes(t *testing.T) {
	dir := emptyDir(t)
	r := signedRouteIn(t, dir, 3)
	h, err := stopwrite.InitSigned(bg, dir, r, clock0, signer(), 4)
	if err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	if h.Signed.Serial != 4 || h.Signed.Previous != "" || h.Signed.File != listPath(dir) || h.Signed.ProjectID != "shop" || h.Signed.Digest == "" {
		t.Fatalf("the header: %+v", h.Signed)
	}
	l, err := reaction.Judge(r, reaction.Prefix{}, content(t, dir), clock0, poll)
	if err != nil || l.Header().Signed.Digest != h.Signed.Digest || l.Signer().Subject != "alice" {
		t.Fatalf("Judge: %v, %+v", err, l.Header().Signed)
	}
	if _, _, err := appendFinding(bg, dir, r, signedStop(t, "f-1", "run-1", "shop", clock0), clock0); err != nil {
		t.Fatalf("a stop of the route's project: %v", err)
	}
	if _, _, err := appendFinding(bg, dir, r, signedStop(t, "f-2", "run-2", "other", clock0), clock0); !errors.Is(err, stopwrite.ErrRefused) {
		t.Fatalf("a stop of another project: %v", err)
	}
}

func TestInitSignedRefusesWhatItCannotSign(t *testing.T) {
	failing := signer()
	failing.Sign = func(string, []byte) ([]byte, error) { return nil, errSign }
	for _, c := range []struct {
		name   string
		route  reaction.Route
		s      stopwrite.Signer
		serial int64
		want   error
	}{
		{"a v1alpha1 route", testRoute(t), signer(), 1, stopwrite.ErrRefused},
		{"no signing function", reaction.Route{}, stopwrite.Signer{KeyID: signer().KeyID}, 1, stopwrite.ErrSigner},
		{"no key id", reaction.Route{}, stopwrite.Signer{Sign: signer().Sign}, 1, stopwrite.ErrSigner},
		{"a key that cannot sign", reaction.Route{}, failing, 1, stopwrite.ErrSigner},
		{"serial 0", reaction.Route{}, signer(), 0, stopwrite.ErrRefused},
		{"a serial past the last", reaction.Route{}, signer(), policy.MaxSerial + 1, stopwrite.ErrRefused},
	} {
		d := emptyDir(t)
		route := c.route
		if route.Digest() == "" {
			route = signedRouteIn(t, d, 3)
		}
		if _, err := stopwrite.InitSigned(bg, d, route, clock0, c.s, c.serial); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	last := emptyDir(t)
	if _, err := stopwrite.InitSigned(bg, last, signedRouteIn(t, last, 3), clock0, signer(), policy.MaxSerial); err != nil {
		t.Errorf("the last serial: %v", err)
	}
}

// TestCarrySignedChainsTheNewHeaderToTheOld: the carry's header takes the
// next serial and names the old head, and its stop keeps its project.
func TestCarrySignedChainsTheNewHeaderToTheOld(t *testing.T) {
	from := emptyDir(t)
	fromRoute := signedRouteIn(t, from, 3)
	old, err := stopwrite.InitSigned(bg, from, fromRoute, clock0, signer(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := appendFinding(bg, from, fromRoute, signedStop(t, "f-1", "run-1", "shop", clock0), clock0); err != nil {
		t.Fatal(err)
	}
	into := emptyDir(t)
	route := signedRouteIn(t, into, 4)
	c, err := stopwrite.CarrySigned(bg, from, fromRoute, into, route, clock0, signer(), nil)
	if err != nil {
		t.Fatalf("CarrySigned: %v", err)
	}
	if c.Header.Signed.Serial != 8 || c.Header.Signed.Previous != old.Signed.Digest || c.Stops != 1 {
		t.Fatalf("carried: %+v, %d stops", c.Header.Signed, c.Stops)
	}
	l, err := reaction.Judge(route, reaction.Prefix{}, content(t, into), clock0, poll)
	if err != nil || len(l.Entries()) != 1 || l.Entries()[0].ProjectID != "shop" {
		t.Fatalf("the carried list: %v", err)
	}
}

// TestACarryBetweenTheFormatsOrPastTheLastSerialIsRefused: a 1.0 list is not
// carried into a 2.0 one, CarrySigned takes only v1alpha2 routes, and a list
// at the last serial has no next.
func TestACarryBetweenTheFormatsOrPastTheLastSerialIsRefused(t *testing.T) {
	for _, c := range []struct {
		name         string
		fromR, intoR func(dir string) reaction.Route
		carry        func(from string, fromR reaction.Route, into string, intoR reaction.Route) error
	}{
		{"a 1.0 list into a v1alpha2 route", func(string) reaction.Route { return testRoute(t) }, func(d string) reaction.Route { return signedRouteIn(t, d, 4) },
			func(f string, fr reaction.Route, i string, ir reaction.Route) error {
				_, err := stopwrite.Carry(bg, f, fr, i, ir, clock0)
				return err
			}},
		{"CarrySigned between v1alpha1 routes", func(string) reaction.Route { return testRoute(t) }, func(string) reaction.Route { return routeOf(t, 4, false) },
			func(f string, fr reaction.Route, i string, ir reaction.Route) error {
				_, err := stopwrite.CarrySigned(bg, f, fr, i, ir, clock0, signer(), nil)
				return err
			}},
	} {
		f := emptyDir(t)
		fr := c.fromR(f)
		if _, err := stopwrite.Init(bg, f, fr, clock0); err != nil {
			t.Fatal(err)
		}
		i := emptyDir(t)
		if err := c.carry(f, fr, i, c.intoR(i)); !errors.Is(err, stopwrite.ErrRefused) {
			t.Errorf("%s: %v, want ErrRefused", c.name, err)
		}
	}

	top := emptyDir(t)
	topRoute := signedRouteIn(t, top, 3)
	if _, err := stopwrite.InitSigned(bg, top, topRoute, clock0, signer(), policy.MaxSerial); err != nil {
		t.Fatal(err)
	}
	next := emptyDir(t)
	if _, err := stopwrite.CarrySigned(bg, top, topRoute, next, signedRouteIn(t, next, 4), clock0, signer(), nil); !errors.Is(err, stopwrite.ErrRefused) {
		t.Errorf("a carry from the last serial: %v", err)
	}
}
