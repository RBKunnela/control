package reaction_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/reaction"
)

// editedBody is body's members with set applied, a nil value removing the
// member, in canonical form.
func editedBody(t testing.TB, body []byte, set map[string]any) []byte {
	t.Helper()
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for k, v := range set {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := canon.CanonicalizeJSON(raw)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return out
}

// operatorSigned is body signed by the operator under payloadType.
func operatorSigned(t testing.TB, payloadType string, body []byte) reaction.Envelope {
	t.Helper()
	return envelopeOf(t, payloadType, body, operatorKey(), keyIDOf(operatorKey()))
}

// headerLineAt is a header line of version holding env, written whatever
// its body says, as a writer that checks nothing would.
func headerLineAt(t testing.TB, version string, env reaction.Envelope) []byte {
	t.Helper()
	sig := env.Signatures[0]
	raw, err := json.Marshal(map[string]any{"kind": "header", "version": version, "envelope": map[string]any{
		"payloadType": env.PayloadType, "payload": base64.StdEncoding.EncodeToString(env.Payload),
		"signatures": []any{map[string]any{"keyid": sig.KeyID, "sig": base64.StdEncoding.EncodeToString(sig.Signature)}},
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	line, err := canon.CanonicalizeJSON(raw)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return line
}

// bindingCase is one signed document judged for the plane, and the refusal
// it gets; a nil want is the document the plane takes.
type bindingCase struct {
	name string
	run  func(t *testing.T) error
	want error
}

func TestEachSignedKindIsBoundToItsPlane(t *testing.T) {
	tables := map[reaction.SignedKind]func(t *testing.T) []bindingCase{
		reaction.VouchRoute: routeBindings, reaction.VouchHeader: headerBindings, reaction.VouchLift: liftBindings,
	}
	if len(tables) != len(reaction.SignedKinds()) {
		t.Fatalf("%d tables for %d signed kinds", len(tables), len(reaction.SignedKinds()))
	}
	for _, kind := range reaction.SignedKinds() {
		table, ok := tables[kind]
		if !ok {
			t.Fatalf("no binding table for signed kind %d", kind)
		}
		for _, c := range table(t) {
			err := c.run(t)
			if c.want == nil && err != nil {
				t.Errorf("kind %d, %s: %v, want it taken", kind, c.name, err)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("kind %d, %s: %v, want %v", kind, c.name, err, c.want)
			}
		}
	}
}

func routeBindings(t *testing.T) []bindingCase {
	base := planeRouteEnvelope(t, sPlane, sProject, sRouteFile, operatorKey())
	verify := func(env reaction.Envelope, v reaction.Voucher) func(*testing.T) error {
		return func(*testing.T) error {
			r, err := reaction.VerifySignedRoute(env, v)
			if err == nil && r.PlaneID() != sPlane {
				t.Errorf("the route taken names plane %q", r.PlaneID())
			}
			return err
		}
	}
	edited := func(set map[string]any) reaction.Envelope {
		return operatorSigned(t, reaction.SignedRoutePayloadType, editedBody(t, base.Payload, set))
	}
	noID := newVoucher()
	noID.plane.ID = ""
	return []bindingCase{
		{"the plane's own route", verify(base, newVoucher()), nil},
		{"another tenant", verify(edited(map[string]any{"tenant_id": "other"}), newVoucher()), reaction.ErrOtherPlane},
		{"another project", verify(planeRouteEnvelope(t, sPlane, "other", sRouteFile, operatorKey()), newVoucher()), reaction.ErrOtherPlane},
		{"another plane_id", verify(planeRouteEnvelope(t, "plane-b", sProject, sRouteFile, operatorKey()), newVoucher()), reaction.ErrOtherPlane},
		{"another file", verify(planeRouteEnvelope(t, sPlane, sProject, "/other/route.json", operatorKey()), newVoucher()), reaction.ErrOtherFile},
		{"no plane_id", verify(edited(map[string]any{"plane_id": nil}), newVoucher()), reaction.ErrRouteMember},
		{"an empty plane_id", verify(edited(map[string]any{"plane_id": ""}), newVoucher()), reaction.ErrRouteValue},
		{"a plane with no id", verify(base, noID), reaction.ErrOtherPlane},
	}
}

func headerBindings(t *testing.T) []bindingCase {
	judge := func(edit func(*fakeVoucher) []byte) func(*testing.T) error {
		return func(*testing.T) error {
			v := newVoucher()
			line := edit(v)
			_, err := reaction.Judge(vouchedRoute(t, v), reaction.Prefix{}, joinLines(line), sNow, 0)
			return err
		}
	}
	with := func(o headerOpts) func(*testing.T) error {
		return judge(func(_ *fakeVoucher) []byte {
			line, _ := signedHeaderLine(t, vouchedRoute(t, newVoucher()), o)
			return line
		})
	}
	body := func(set map[string]any) func(*testing.T) error {
		return judge(func(*fakeVoucher) []byte {
			r := vouchedRoute(t, newVoucher())
			h := reaction.Header{ListID: "lst-1", RouteID: r.ID(), RouteSerial: r.Serial(), RouteDigest: r.Digest(),
				Signed: reaction.HeaderSigned{KeyID: keyIDOf(operatorKey()), PlaneID: sPlane, TenantID: sTenant, ProjectID: sProject,
					File: sListFile, Serial: 1}}
			raw, err := reaction.HeaderBody(h)
			if err != nil {
				t.Fatalf("HeaderBody: %v", err)
			}
			return headerLineAt(t, reaction.SignedListVersionV3,
				operatorSigned(t, reaction.SignedHeaderPayloadType, editedBody(t, raw, set)))
		})
	}
	return []bindingCase{
		{"the plane's own header", with(headerOpts{}), nil},
		{"another tenant", with(headerOpts{tenant: "other"}), reaction.ErrHeaderOther},
		{"another project", with(headerOpts{project: "other"}), reaction.ErrHeaderOther},
		{"another plane_id", with(headerOpts{plane: "plane-b"}), reaction.ErrOtherPlane},
		{"another file", with(headerOpts{file: "/other/stops/stops.jsonl"}), reaction.ErrOtherFile},
		{"no plane_id", body(map[string]any{"plane_id": nil}), reaction.ErrLineMember},
		{"an empty plane_id", body(map[string]any{"plane_id": ""}), reaction.ErrLineValue},
		{"a plane with no id", judge(func(v *fakeVoucher) []byte {
			v.blankAfter = reaction.VouchRoute
			line, _ := signedHeaderLine(t, vouchedRoute(t, newVoucher()), headerOpts{})
			return line
		}), reaction.ErrOtherPlane},
	}
}

func liftBindings(t *testing.T) []bindingCase {
	judge := func(blank bool, lift func(head string) []byte) func(*testing.T) error {
		return func(*testing.T) error {
			v := newVoucher()
			r := vouchedRoute(t, v)
			header, head := signedHeaderLine(t, r, headerOpts{})
			if blank {
				v.blankAfter = reaction.VouchHeader
			}
			_, err := reaction.Judge(r, reaction.Prefix{}, joinLines(header, signedStop(t, sProject), lift(head)), sNow, 0)
			return err
		}
	}
	base := func(head string) reaction.SignedLiftV3 {
		return reaction.SignedLiftV3{KeyID: keyIDOf(operatorKey()), PlaneID: sPlane, ListHead: head, Scope: reaction.ScopeRun,
			Subject: "run-1", ThroughLine: 2, TenantID: sTenant, Project: sProject, File: sListFile}
	}
	with := func(edit func(*reaction.SignedLiftV3)) func(*testing.T) error {
		return judge(false, func(head string) []byte {
			l := base(head)
			edit(&l)
			return signedLiftLineOf(t, l, operatorKey(), "run-1", 2)
		})
	}
	body := func(set map[string]any) func(*testing.T) error {
		return judge(false, func(head string) []byte {
			raw, err := base(head).Payload()
			if err != nil {
				t.Fatalf("Payload: %v", err)
			}
			line, err := reaction.LiftLine{Scope: reaction.ScopeRun, Subject: "run-1", ThroughLine: 2,
				Envelope: operatorSigned(t, reaction.SignedLiftPayloadType, editedBody(t, raw, set))}.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			return line
		})
	}
	return []bindingCase{
		{"the plane's own lift", with(func(*reaction.SignedLiftV3) {}), nil},
		{"another tenant", with(func(l *reaction.SignedLiftV3) { l.TenantID = "other" }), reaction.ErrSignedLiftMismatch},
		{"another project", with(func(l *reaction.SignedLiftV3) { l.Project = "other" }), reaction.ErrSignedLiftMismatch},
		{"another plane_id", with(func(l *reaction.SignedLiftV3) { l.PlaneID = "plane-b" }), reaction.ErrOtherPlane},
		{"another file", with(func(l *reaction.SignedLiftV3) { l.File = "/other/stops/stops.jsonl" }), reaction.ErrOtherFile},
		{"no plane_id", body(map[string]any{"plane_id": nil}), reaction.ErrLiftMember},
		{"an empty plane_id", body(map[string]any{"plane_id": ""}), reaction.ErrLiftValue},
		{"a plane with no id", judge(true, func(head string) []byte {
			return signedLiftLineOf(t, base(head), operatorKey(), "run-1", 2)
		}), reaction.ErrOtherPlane},
	}
}

// TestAZeroRouteOrPlaneNeverJudgesClear: the zero Route, of no format, and a
// voucher of the zero Plane, or of a plane with every member but its id,
// never take a list or a route that the plane's own voucher takes.
func TestAZeroRouteOrPlaneNeverJudgesClear(t *testing.T) {
	v := newVoucher()
	r := vouchedRoute(t, v)
	header, _ := signedHeaderLine(t, r, headerOpts{})
	content := joinLines(header, signedStop(t, sProject))
	if _, err := reaction.Judge(r, reaction.Prefix{}, content, sNow, 0); err != nil {
		t.Fatalf("the plane's own list: %v", err)
	}
	var zero reaction.Route
	if zero.Format() != reaction.FormatNone {
		t.Fatalf("the zero route's format is %d", zero.Format())
	}
	if _, err := reaction.Judge(zero, reaction.Prefix{}, content, sNow, 0); err == nil {
		t.Fatal("the zero route judged a list")
	}
	if s := (reaction.Snapshot{}).Next(zero, content, sNow, time.Second); s.State() != reaction.Unknown {
		t.Fatalf("the zero route's snapshot is %v", s.State())
	}
	if err := zero.Permits(reaction.StopClaim{}); err == nil {
		t.Fatal("the zero route permits the zero claim")
	}
	env := routeEnvelope(t, sProject, sRouteFile, operatorKey())
	for _, p := range []reaction.Plane{{}, {Tenant: sTenant, Project: sProject, RouteFile: sRouteFile, ListFile: sListFile}} {
		zv := newVoucher()
		zv.plane = p
		if _, err := reaction.VerifySignedRoute(env, zv); !errors.Is(err, reaction.ErrOtherPlane) {
			t.Errorf("a voucher of plane %+v: %v, want %v", p, err, reaction.ErrOtherPlane)
		}
		if _, err := reaction.VerifySignedCarrySource(env, zv); !errors.Is(err, reaction.ErrOtherPlane) {
			t.Errorf("a carry source for plane %+v: %v, want %v", p, err, reaction.ErrOtherPlane)
		}
		if _, err := reaction.VerifySignedCarrySource(v2RouteEnvelope(t), zv); !errors.Is(err, reaction.ErrOtherPlane) {
			t.Errorf("a v1alpha2 carry source for plane %+v: %v, want %v", p, err, reaction.ErrOtherPlane)
		}
	}
}
