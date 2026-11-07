package signedstops_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/trust"
)

func key(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("signedstops-test/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func public(name string) ed25519.PublicKey { return key(name).Public().(ed25519.PublicKey) }

func keyID(name string) string { return policykey.KeyID(public(name)) }

func rosterEntry(name, project, level string) map[string]any {
	return map[string]any{
		"keyId": keyID(name), "alg": "ed25519", "role": "operator", "subject": name,
		"publicKey": policykey.FormatPublic(public(name)),
		"grants":    []any{map[string]any{"tenant": "t1", "project": project, "level": level}},
	}
}

var now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// fixture is a plane of tenant t1 and project A: a roster in which dave is
// admin of A, alice operates A, bob only reads A and carol operates B; the
// operator ports over it; and the plane's files.
type fixture struct {
	authn  operators.Authenticator
	authz  operators.Authorizer
	roster trust.Document
	plane  reaction.Plane
	base   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := t.TempDir()
	body, err := canon.Canonicalize(map[string]any{
		"kind": trust.DocumentKind, "rosterId": "roster-a", "serial": int64(1),
		"issuedAt": "2026-10-30T00:00:00Z", "expiresAt": "2026-10-31T00:00:00Z",
		"keys": []any{rosterEntry("dave", "A", "admin"), rosterEntry("alice", "A", "operate"),
			rosterEntry("bob", "A", "read"), rosterEntry("carol", "B", "operate")},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(trust.PayloadType, body, key("root"))
	if err != nil {
		t.Fatal(err)
	}
	env := trust.Envelope{PayloadType: trust.PayloadType, Payload: body, Signatures: []trust.Signature{{KeyID: keyID("root"), Signature: sig}}}
	raw, err := trust.MarshalFile(env)
	if err != nil {
		t.Fatal(err)
	}
	rosterPath := filepath.Join(base, "roster.json")
	if err := os.WriteFile(rosterPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fixture{base: base}
	if f.roster, err = trust.VerifyDocument(env, public("root")); err != nil {
		t.Fatal(err)
	}
	authorityFloor := filepath.Join(base, "authority")
	if err := policystate.InitAuthority(t.Context(), authorityFloor, "roster-a"); err != nil {
		t.Fatal(err)
	}
	roster, err := trust.Open(t.Context(), trust.Config{Root: public("root"), RosterID: "roster-a", Path: rosterPath,
		FloorDir: authorityFloor, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if f.authn, err = operators.NewAuthenticator("", roster, operators.Bounds{}); err != nil {
		t.Fatal(err)
	}
	if f.authz, err = operators.NewAuthorizer("", roster, operators.Bounds{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "stops"), 0o700); err != nil {
		t.Fatal(err)
	}
	if f.plane, err = signedstops.PlaneOf("t1", "A", filepath.Join(base, "route.json"), filepath.Join(base, "stops"), stoplist.FileName); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) vouchers(t *testing.T) map[string]reaction.Voucher {
	t.Helper()
	ports, err := signedstops.NewPorts(f.authn, f.authz, f.plane)
	if err != nil {
		t.Fatal(err)
	}
	roster, err := signedstops.NewRoster(f.roster, f.plane)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]reaction.Voucher{"ports": ports, "roster": roster}
}

// statement is a canonical body naming the key called as, signed by the
// key called by under payloadType.
func statement(t *testing.T, payloadType, by, as string) reaction.Envelope {
	t.Helper()
	body, err := canon.Canonicalize(map[string]any{"alg": "ed25519", "keyId": keyID(as), "note": "x"})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(payloadType, body, key(by))
	if err != nil {
		t.Fatal(err)
	}
	return reaction.Envelope{PayloadType: payloadType, Payload: body, Signatures: []reaction.Signature{{KeyID: keyID(as), Signature: sig}}}
}

func TestThePayloadTypesAndTheBoundAreTheOperatorPorts(t *testing.T) {
	for _, c := range [][2]string{
		{reaction.SignedRoutePayloadType, operators.RoutePayloadType},
		{reaction.SignedHeaderPayloadType, operators.StopsHeaderPayloadType},
		{reaction.SignedLiftPayloadType, operators.LiftPayloadType},
	} {
		if c[0] != c[1] {
			t.Errorf("reaction's %q, operators' %q", c[0], c[1])
		}
	}
	if reaction.MaxSignedBytes != operators.MaxStatementBytes {
		t.Errorf("reaction.MaxSignedBytes %d, operators.MaxStatementBytes %d", reaction.MaxSignedBytes, operators.MaxStatementBytes)
	}
}

// TestOnlyAGrantAtTheActsLevelVouches: the route needs admin, the header and
// the lift operate, each over the plane's own project, from a key the roster
// names; both vouchers answer alike.
func TestOnlyAGrantAtTheActsLevelVouches(t *testing.T) {
	f := newFixture(t)
	kinds := map[reaction.SignedKind]string{
		reaction.VouchRoute: reaction.SignedRoutePayloadType, reaction.VouchHeader: reaction.SignedHeaderPayloadType,
		reaction.VouchLift: reaction.SignedLiftPayloadType,
	}
	for name, v := range f.vouchers(t) {
		for kind, payloadType := range kinds {
			checkGrants(t, name, v, kind, payloadType)
			if _, err := v.Vouch(kind, statement(t, payloadType, "mallory", "alice")); !errors.Is(err, signedstops.ErrUnauthenticated) {
				t.Errorf("%s, kind %d: mallory under alice's key id: %v", name, kind, err)
			}
			other := reaction.SignedLiftPayloadType
			if kind == reaction.VouchLift {
				other = reaction.SignedHeaderPayloadType
			}
			if _, err := v.Vouch(kind, statement(t, other, "dave", "dave")); !errors.Is(err, signedstops.ErrUnauthenticated) {
				t.Errorf("%s, kind %d: another act's payload type: %v", name, kind, err)
			}
		}
	}
}

// checkGrants asks v about a statement of kind each operator signed: dave
// is admin, alice operates, bob reads, carol operates another project and
// mallory is no operator.
func checkGrants(t *testing.T, name string, v reaction.Voucher, kind reaction.SignedKind, payloadType string) {
	t.Helper()
	alice := error(nil)
	if kind == reaction.VouchRoute {
		alice = signedstops.ErrUnauthorized
	}
	for _, c := range []struct {
		who  string
		want error
	}{
		{"dave", nil},
		{"alice", alice},
		{"bob", signedstops.ErrUnauthorized},
		{"carol", signedstops.ErrUnauthorized},
		{"mallory", signedstops.ErrUnauthenticated},
	} {
		s, err := v.Vouch(kind, statement(t, payloadType, c.who, c.who))
		switch {
		case c.want == nil && (err != nil || s.Subject != c.who || s.KeyID != keyID(c.who)):
			t.Errorf("%s, kind %d, %s: %+v, %v", name, kind, c.who, s, err)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%s, kind %d, %s: %v, want %v", name, kind, c.who, err, c.want)
		}
	}
}

type unavailable struct{}

func (unavailable) Authenticate(context.Context, operators.Act, operators.Envelope) operators.Authentication {
	return operators.Authentication{}
}

func (unavailable) Authorize(context.Context, operators.Authentication, operators.Request) operators.Permission {
	return operators.Permission{}
}

func (unavailable) Status() operators.Status { return operators.Status{} }

func TestPortsThatGiveNoAnswerAreUnavailableNotARefusal(t *testing.T) {
	f := newFixture(t)
	v, err := signedstops.NewPorts(unavailable{}, f.authz, f.plane)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Vouch(reaction.VouchHeader, statement(t, reaction.SignedHeaderPayloadType, "alice", "alice"))
	if !signedstops.IsUnavailable(err) || !errors.Is(err, reaction.ErrUnanswered) || errors.Is(err, signedstops.ErrUnauthenticated) {
		t.Fatalf("an authenticator with no answer: %v", err)
	}
	if v, err = signedstops.NewPorts(f.authn, unavailable{}, f.plane); err != nil {
		t.Fatal(err)
	}
	_, err = v.Vouch(reaction.VouchHeader, statement(t, reaction.SignedHeaderPayloadType, "alice", "alice"))
	if !signedstops.IsUnavailable(err) || !errors.Is(err, reaction.ErrUnanswered) || errors.Is(err, signedstops.ErrUnauthorized) {
		t.Fatalf("an authorizer with no answer: %v", err)
	}
	if _, err := signedstops.NewPorts(nil, f.authz, f.plane); !errors.Is(err, signedstops.ErrOptions) {
		t.Fatalf("no authenticator: %v", err)
	}
	if _, err := signedstops.NewRoster(f.roster, reaction.Plane{Tenant: "t1", Project: "A"}); !errors.Is(err, signedstops.ErrOptions) {
		t.Fatalf("a plane with no files: %v", err)
	}
}
