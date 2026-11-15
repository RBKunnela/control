package reaction_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

// v2RouteEnvelope is the plane's route as a 0.17 operator signed it:
// v1alpha2, naming no plane.
func v2RouteEnvelope(t testing.TB) reaction.Envelope {
	t.Helper()
	base := routeEnvelope(t, sProject, sRouteFile, operatorKey())
	return operatorSigned(t, reaction.SignedRoutePayloadType,
		editedBody(t, base.Payload, map[string]any{"kind": reaction.SignedRouteKind, "plane_id": nil}))
}

// v2List is a 2.0 list under r: its header names no plane, and its stop of
// run-1 no subject.
func v2List(t testing.TB, r reaction.Route) []byte {
	t.Helper()
	h := reaction.Header{ListID: "lst-1", RouteID: r.ID(), RouteSerial: r.Serial(), RouteDigest: r.Digest(),
		Signed: reaction.HeaderSigned{KeyID: keyIDOf(operatorKey()), TenantID: sTenant, ProjectID: sProject, File: sListFile, Serial: 1}}
	body, err := reaction.HeaderBody(h)
	if err != nil {
		t.Fatalf("HeaderBody: %v", err)
	}
	header, err := reaction.SignedHeaderLine(operatorSigned(t, reaction.SignedHeaderPayloadType, body))
	if err != nil {
		t.Fatalf("SignedHeaderLine: %v", err)
	}
	stop, err := reaction.Stop{
		EntryID: reaction.EntryID("f-1"), TenantID: sTenant, ProjectID: sProject, Scope: reaction.ScopeRun, RunID: "run-1",
		FindingID: "f-1", ProcedureID: "refund", ProcedureVersion: "3", ProcedureDigest: procDigest,
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: sCreated, ExpiresAt: sCreated.Add(30 * time.Minute),
	}.Marshal()
	if err != nil {
		t.Fatalf("Stop.Marshal: %v", err)
	}
	return joinLines(header, stop)
}

// expectUpgrade fails unless s is Unknown for another format version and
// names command whole, uncut.
func expectUpgrade(t *testing.T, what string, s reaction.Snapshot, command string) {
	t.Helper()
	if s.State() != reaction.Unknown || s.Cause() != reaction.CauseVersion {
		t.Errorf("%s: %v %q, want unknown with %q", what, s.State(), s.Cause(), reaction.CauseVersion)
	}
	if !strings.Contains(s.Detail(), command) || strings.HasSuffix(s.Detail(), "...") {
		t.Errorf("%s: the detail %q does not name %q whole", what, s.Detail(), command)
	}
}

// TestEveryServingEntryPointRefusesAV1alpha2Route: a v1alpha2 route validly
// signed for the plane's tenant, project and file still parses and is taken
// as a carry's source, but nothing a plane serves from takes it, and the
// refusal names route sign.
func TestEveryServingEntryPointRefusesAV1alpha2Route(t *testing.T) {
	env := v2RouteEnvelope(t)
	if r, err := reaction.ParseRoute(env.Payload); err != nil || r.Format() != reaction.FormatV1Alpha2Carry {
		t.Fatalf("ParseRoute of a v1alpha2 body: format %d, %v", r.Format(), err)
	}
	_, err := reaction.VerifySignedRoute(env, newVoucher())
	if !errors.Is(err, reaction.ErrRouteUpgrade) || !strings.Contains(err.Error(), "route sign") {
		t.Fatalf("VerifySignedRoute of a v1alpha2 route: %v, want %v", err, reaction.ErrRouteUpgrade)
	}
	from, err := reaction.VerifySignedCarrySource(env, newVoucher())
	noErr(t, err)
	old := v2List(t, from)
	if l, err := reaction.JudgeCarrySource(from, old, sNow); err != nil || len(l.Entries()) != 1 {
		t.Fatalf("JudgeCarrySource of a 2.0 list: %d entries, %v", len(l.Entries()), err)
	}
	ctx := context.Background()
	for name, err := range map[string]error{
		"Judge": func() error { _, err := reaction.Judge(from, reaction.Prefix{}, old, sNow, 0); return err }(),
		"JudgeFromContext": func() error {
			_, err := reaction.JudgeFromContext(ctx, from, reaction.List{}, old, sNow, 0)
			return err
		}(),
	} {
		if !errors.Is(err, reaction.ErrRouteUpgrade) {
			t.Errorf("%s under a v1alpha2 route: %v, want %v", name, err, reaction.ErrRouteUpgrade)
		}
	}
	expectUpgrade(t, "a snapshot under a v1alpha2 route", reaction.Snapshot{}.NextContext(ctx, from, old, sNow, time.Second), "route sign")
}

// TestA20ListAndAV1alpha2LiftAreRefusedUnderAV1alpha3Route: a 2.0 list and a
// v1alpha2 lift in a 3.0 list, each validly signed, are refused by the judge
// and the snapshot, naming stops init --carry.
func TestA20ListAndAV1alpha2LiftAreRefusedUnderAV1alpha3Route(t *testing.T) {
	ctx := context.Background()
	r := vouchedRoute(t, newVoucher())
	_, err := reaction.Judge(r, reaction.Prefix{}, v2List(t, r), sNow, 0)
	if !errors.Is(err, reaction.ErrListUpgrade) || !strings.Contains(err.Error(), "stops init --carry") {
		t.Errorf("Judge of a 2.0 list under a v1alpha3 route: %v, want %v", err, reaction.ErrListUpgrade)
	}
	expectUpgrade(t, "a 2.0 list's snapshot", reaction.Snapshot{}.NextContext(ctx, r, v2List(t, r), sNow, time.Second), "stops init --carry")

	header, head := signedHeaderLine(t, r, headerOpts{})
	v2Lift, err := reaction.SignedLift{KeyID: keyIDOf(operatorKey()), ListHead: head, RunID: "run-1", ThroughLine: 2,
		TenantID: sTenant, Project: sProject, File: sListFile}.Payload()
	noErr(t, err)
	lift, err := reaction.LiftLine{Scope: reaction.ScopeRun, Subject: "run-1", ThroughLine: 2,
		Envelope: operatorSigned(t, reaction.SignedLiftPayloadType, v2Lift)}.Marshal()
	noErr(t, err)
	withLift := joinLines(header, signedStop(t, sProject), lift)
	if _, err := reaction.Judge(r, reaction.Prefix{}, withLift, sNow, 0); !errors.Is(err, reaction.ErrLiftUpgrade) {
		t.Errorf("a v1alpha2 lift in a 3.0 list: %v, want %v", err, reaction.ErrLiftUpgrade)
	}
	expectUpgrade(t, "a v1alpha2 lift's snapshot", reaction.Snapshot{}.NextContext(ctx, r, withLift, sNow, time.Second), "stops init --carry")
}

// TestNothingSignsAV1alpha2Route: route sign's readers refuse a v1alpha2
// document, naming the kind and the member that replace it, and take the
// same document as v1alpha3.
func TestNothingSignsAV1alpha2Route(t *testing.T) {
	doc := strings.NewReplacer(`"kind":"reaction-route/v1alpha3","plane_id":"PLANE",`, `"kind":"reaction-route/v1alpha2",`,
		"PROJECT", sProject).Replace(signedRouteDoc)
	for name, err := range map[string]error{
		"SignedRouteBody": func() error {
			_, err := reaction.SignedRouteBody([]byte(doc), keyIDOf(operatorKey()), sRouteFile)
			return err
		}(),
		"ParseRouteDocument": func() error { _, err := reaction.ParseRouteDocument([]byte(doc)); return err }(),
	} {
		if !errors.Is(err, reaction.ErrRouteUpgrade) || !strings.Contains(err.Error(), reaction.SignedRouteKindV3) ||
			!strings.Contains(err.Error(), "plane_id") {
			t.Errorf("%s of a v1alpha2 document: %v, want %v", name, err, reaction.ErrRouteUpgrade)
		}
	}
	v3 := strings.NewReplacer("PLANE", sPlane, "PROJECT", sProject).Replace(signedRouteDoc)
	if r, err := reaction.ParseRouteDocument([]byte(v3)); err != nil || r.Format() != reaction.FormatV1Alpha3 {
		t.Fatalf("ParseRouteDocument of a v1alpha3 document: format %d, %v", r.Format(), err)
	}
}

// TestASignedBodyIsHeldToTheBoundOfItsVersion: a v1alpha3 route and a 3.0
// header are held to MaxSignedBytes, and their 0.17 forms, read only for a
// carry, to the 16384 bytes they were signed under; a 3.0 lift line's
// envelope holds a body of MaxSignedBytes, which a 2.0 lift line's does not.
func TestASignedBodyIsHeldToTheBoundOfItsVersion(t *testing.T) {
	if reaction.MaxSignedBytes != 20480 {
		t.Fatalf("MaxSignedBytes is %d", reaction.MaxSignedBytes)
	}
	base := routeEnvelope(t, sProject, sRouteFile, operatorKey()).Payload
	padded := func(kind string, plane any, size int) []byte {
		body := editedBody(t, base, map[string]any{"kind": kind, "plane_id": plane, "route_id": "r"})
		return editedBody(t, body, map[string]any{"route_id": "r" + strings.Repeat("x", size-len(body))})
	}
	for _, c := range []struct {
		name   string
		body   []byte
		tooBig bool
	}{
		{"a v1alpha2 route of 16384 bytes", padded(reaction.SignedRouteKind, nil, 16384), false},
		{"a v1alpha2 route of 16385 bytes", padded(reaction.SignedRouteKind, nil, 16385), true},
		{"a v1alpha3 route of 16385 bytes", padded(reaction.SignedRouteKindV3, sPlane, 16385), false},
		{"a v1alpha3 route of 20480 bytes", padded(reaction.SignedRouteKindV3, sPlane, 20480), false},
		{"a v1alpha3 route of 20481 bytes", padded(reaction.SignedRouteKindV3, sPlane, 20481), true},
	} {
		_, err := reaction.ParseRoute(c.body)
		if errors.Is(err, reaction.ErrRouteTooLarge) != c.tooBig {
			t.Errorf("%s (%d): %v, over its bound %v", c.name, len(c.body), err, c.tooBig)
		}
	}
	r := vouchedRoute(t, newVoucher())
	h := reaction.Header{ListID: "lst-1", RouteID: r.ID(), RouteSerial: r.Serial(), RouteDigest: r.Digest(),
		Signed: reaction.HeaderSigned{KeyID: keyIDOf(operatorKey()), TenantID: sTenant, ProjectID: sProject, File: sListFile, Serial: 1}}
	v2Header, err := reaction.HeaderBody(h)
	if err != nil {
		t.Fatalf("HeaderBody: %v", err)
	}
	headerOf := func(version string, plane any, size int) []byte {
		body := editedBody(t, v2Header, map[string]any{"plane_id": plane, "pad": ""})
		if version == reaction.SignedListVersionV3 {
			body = editedBody(t, body, map[string]any{"kind": reaction.SignedHeaderKindV3})
		}
		body = editedBody(t, body, map[string]any{"pad": strings.Repeat("x", size-len(body))})
		return headerLineAt(t, version, operatorSigned(t, reaction.SignedHeaderPayloadType, body))
	}
	for _, c := range []struct {
		name string
		line []byte
		want error
	}{
		// A body within its bound is read and refused for the member it
		// should not hold; one past it is refused for its size.
		{"a 2.0 header of 16384 bytes", headerOf(reaction.SignedListVersion, nil, 16384), reaction.ErrLineMember},
		{"a 2.0 header of 16385 bytes", headerOf(reaction.SignedListVersion, nil, 16385), reaction.ErrLineValue},
		{"a 3.0 header of 20480 bytes", headerOf(reaction.SignedListVersionV3, sPlane, 20480), reaction.ErrLineMember},
		{"a 3.0 header of 20481 bytes", headerOf(reaction.SignedListVersionV3, sPlane, 20481), reaction.ErrLineValue},
	} {
		_, err := reaction.ParseLine(c.line)
		expectOnly(t, c.name, err, c.want, lineRefusals())
	}
	big := operatorSigned(t, reaction.SignedLiftPayloadType, []byte(strings.Repeat("x", reaction.MaxSignedBytes)))
	three, err := reaction.LiftLine{Scope: reaction.ScopeRun, Subject: "run-1", ThroughLine: 2, Envelope: big}.Marshal()
	if err != nil {
		t.Fatalf("a 3.0 lift line holding a body of MaxSignedBytes: %v", err)
	}
	if _, err := reaction.ParseLine(three); err != nil {
		t.Fatalf("ParseLine of that line: %v", err)
	}
	if _, err := (reaction.LiftLine{RunID: "run-1", ThroughLine: 2, Envelope: big}).Marshal(); !errors.Is(err, reaction.ErrLineValue) {
		t.Fatalf("a 2.0 lift line holding a body of MaxSignedBytes: %v, want %v", err, reaction.ErrLineValue)
	}
}

func noErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestAListOfAnotherVersionIsNamedForWhatItIs: only a 2.0 list under a
// v1alpha3 route is told to carry; a 2.0 list under a v1alpha1 route and a
// 2.0 line within a 3.0 list are lines of another version, and their refusal
// names no carry.
func TestAListOfAnotherVersionIsNamedForWhatItIs(t *testing.T) {
	v1 := listRoute(t)
	r := vouchedRoute(t, newVoucher())
	header, _ := signedHeaderLine(t, r, headerOpts{})
	old := v2List(t, r)
	mixed := joinLines(header, bytes.SplitN(old, []byte{'\n'}, 3)[1])
	for _, c := range []struct {
		name    string
		route   reaction.Route
		content []byte
	}{
		{"a 2.0 list under a v1alpha1 route", v1, v2List(t, v1)},
		{"a 2.0 line in a 3.0 list", r, mixed},
	} {
		_, err := reaction.Judge(c.route, reaction.Prefix{}, c.content, sNow, 0)
		if !errors.Is(err, reaction.ErrListVersion) || errors.Is(err, reaction.ErrListUpgrade) || strings.Contains(err.Error(), "carry") {
			t.Errorf("%s: %v, want %v naming no carry", c.name, err, reaction.ErrListVersion)
		}
	}
	if _, err := reaction.Judge(r, reaction.Prefix{}, mixed, sNow, 0); err == nil || !strings.Contains(err.Error(), "whose header is 3.0") {
		t.Errorf("a 2.0 line in a 3.0 list: %v, want it named a line of another version than its header", err)
	}
}
