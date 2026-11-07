package reaction_test

import (
	"errors"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

var sNow = sCreated.Add(time.Minute)

func TestASignedListAnOperatorWroteIsTakenAndItsLiftEndsTheStop(t *testing.T) {
	v := newVoucher()
	r := vouchedRoute(t, v)
	expectBound(t, r)
	header, head := signedHeaderLine(t, r, headerOpts{})
	list, err := reaction.Judge(r, reaction.Prefix{}, joinLines(header, signedStop(t, sProject)), sNow, 0)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if len(list.Entries()) != 1 || list.Header().Signed.Digest != head || list.Signer().Subject != "alice" {
		t.Fatalf("entries %d head %q signer %+v, want 1 entry, head %q, alice", len(list.Entries()), list.Header().Signed.Digest, list.Signer(), head)
	}
	lifted, err := reaction.Judge(r, reaction.Prefix{}, joinLines(header, signedStop(t, sProject), signedLiftLine(t, head, sProject, operatorKey())), sNow, 0)
	if err != nil {
		t.Fatalf("Judge with the lift: %v", err)
	}
	if n := len(lifted.Entries()); n != 0 {
		t.Fatalf("%d entries after the lift, want 0", n)
	}
	if v.asked[reaction.VouchRoute] != 1 || v.asked[reaction.VouchHeader] != 2 || v.asked[reaction.VouchLift] != 1 {
		t.Fatalf("the voucher was asked %v", v.asked)
	}
}

// expectBound fails unless r is a signed route of the plane's project and
// route file, signed by alice.
func expectBound(t *testing.T, r reaction.Route) {
	t.Helper()
	if !r.Signed() || r.ProjectID() != sProject || r.File() != sRouteFile || r.Signer().Subject != "alice" {
		t.Fatalf("route: signed %v project %q file %q signer %+v", r.Signed(), r.ProjectID(), r.File(), r.Signer())
	}
}

func TestASignedRouteIsRefusedWithItsCause(t *testing.T) {
	two := routeEnvelope(t, sProject, sRouteFile, operatorKey())
	two.Signatures = append(two.Signatures, two.Signatures[0])
	otherKeyID := routeEnvelope(t, sProject, sRouteFile, operatorKey())
	otherKeyID.Signatures[0].KeyID = keyIDOf(strangerKey())
	v1Type := routeEnvelope(t, sProject, sRouteFile, operatorKey())
	v1Type.PayloadType = reaction.RoutePayloadType
	denied := newVoucher()
	denied.deny[reaction.VouchRoute] = true
	for _, c := range []struct {
		name string
		env  reaction.Envelope
		v    reaction.Voucher
		want error
	}{
		{"another project", routeEnvelope(t, "other", sRouteFile, operatorKey()), newVoucher(), reaction.ErrOtherPlane},
		{"another plane's route file", routeEnvelope(t, sProject, "/other/route.json", operatorKey()), newVoucher(), reaction.ErrOtherFile},
		{"a signer the voucher does not take", routeEnvelope(t, sProject, sRouteFile, strangerKey()), newVoucher(), reaction.ErrUnvouched},
		{"an operator with no admin grant", routeEnvelope(t, sProject, sRouteFile, operatorKey()), denied, reaction.ErrUnvouched},
		{"two signatures", two, newVoucher(), reaction.ErrSignedShape},
		{"a signature naming another key than the body", otherKeyID, newVoucher(), reaction.ErrSignerKey},
		{"the v1alpha1 payload type", v1Type, newVoucher(), reaction.ErrSignedShape},
		{"no voucher", routeEnvelope(t, sProject, sRouteFile, operatorKey()), nil, reaction.ErrNoVoucher},
	} {
		_, err := reaction.VerifySignedRoute(c.env, c.v)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

func TestAV1alpha2RouteIsNeverReadUnderARouteKey(t *testing.T) {
	env := routeEnvelope(t, sProject, sRouteFile, operatorKey())
	env.PayloadType = reaction.RoutePayloadType
	env = envelopeOf(t, reaction.RoutePayloadType, env.Payload, routeKey(), keyIDOf(routeKey()))
	if _, err := reaction.VerifyRoute(env, pubOf(routeKey())); !errors.Is(err, reaction.ErrRouteKind) {
		t.Fatalf("VerifyRoute of a v1alpha2 body: %v, want %v", err, reaction.ErrRouteKind)
	}
	r, err := reaction.ParseRoute(env.Payload)
	if err != nil {
		t.Fatalf("ParseRoute: %v", err)
	}
	if _, err := reaction.SignRoute(r, routeKey()); !errors.Is(err, reaction.ErrRouteKind) {
		t.Fatalf("SignRoute of a v1alpha2 route: %v, want %v", err, reaction.ErrRouteKind)
	}
}

func TestAV1alpha2RouteNoVoucherTookJudgesNoListAsClear(t *testing.T) {
	r, err := reaction.ParseRoute(routeEnvelope(t, sProject, sRouteFile, operatorKey()).Payload)
	if err != nil {
		t.Fatalf("ParseRoute: %v", err)
	}
	header, _ := signedHeaderLine(t, r, headerOpts{})
	if _, err := reaction.Judge(r, reaction.Prefix{}, joinLines(header), sNow, 0); !errors.Is(err, reaction.ErrNoVoucher) {
		t.Fatalf("Judge: %v, want %v", err, reaction.ErrNoVoucher)
	}
	snap := reaction.Snapshot{}.Next(r, joinLines(header), sNow, time.Second)
	if snap.State() != reaction.Unknown || snap.Cause() != reaction.CauseUnsigned {
		t.Fatalf("snapshot %v %q, want unknown with %q", snap.State(), snap.Cause(), reaction.CauseUnsigned)
	}
}

func TestASignedListIsRefusedAndNeverReadAsNoStops(t *testing.T) {
	r := vouchedRoute(t, newVoucher())
	header, head := signedHeaderLine(t, r, headerOpts{})
	oneZeroHeader, err := reaction.HeaderFor(r, "lst-1").Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	otherFile, _ := signedHeaderLine(t, r, headerOpts{file: "/other/stops/stops.jsonl"})
	otherProject, _ := signedHeaderLine(t, r, headerOpts{project: "other"})
	stranger, _ := signedHeaderLine(t, r, headerOpts{key: strangerKey()})
	oneZeroStop, err := reaction.Stop{
		EntryID: reaction.EntryID("f-1"), TenantID: sTenant, RunID: "run-1", FindingID: "f-1", ProcedureID: "refund",
		ProcedureVersion: "3", ProcedureDigest: procDigest, RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1",
		CreatedAt: sCreated, ExpiresAt: sCreated.Add(30 * time.Minute),
	}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	otherCovered, err := reaction.Covered{FindingID: "f-2", TenantID: sTenant, RunID: "run-1", ProjectID: "other", CreatedAt: sCreated}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, c := range []struct {
		name    string
		content []byte
		want    error
		cause   reaction.Cause
	}{
		{"a 1.0 header", joinLines(oneZeroHeader), reaction.ErrListVersion, reaction.CauseVersion},
		{"a header for another plane's stop list", joinLines(otherFile), reaction.ErrOtherFile, reaction.CauseOtherPlane},
		{"a header of another project", joinLines(otherProject), reaction.ErrHeaderOther, reaction.CauseOtherPlane},
		{"a header no operator signed", joinLines(stranger), reaction.ErrHeaderUnsigned, reaction.CauseUnsigned},
		{"a stop of another project", joinLines(header, signedStop(t, "other")), reaction.ErrClaimProject, reaction.CauseNotPermitted},
		{"a 1.0 stop", joinLines(header, oneZeroStop), reaction.ErrListVersion, reaction.CauseVersion},
		{"a covered line of another project", joinLines(header, otherCovered), reaction.ErrCoveredRun, reaction.CauseMalformed},
		{"a lift no operator signed", joinLines(header, signedStop(t, sProject), signedLiftLine(t, head, sProject, strangerKey())),
			reaction.ErrSignedLiftUnvouched, reaction.CauseLift},
		{"a lift of another project", joinLines(header, signedStop(t, sProject), signedLiftLine(t, head, "other", operatorKey())),
			reaction.ErrSignedLiftMismatch, reaction.CauseLift},
		{"a lift signed for another run", joinLines(header, signedStop(t, sProject), liftLineAs(t, head, sProject, operatorKey(), "run-2", 2)),
			reaction.ErrSignedLiftMismatch, reaction.CauseLift},
		{"a lift signed for another line", joinLines(header, signedStop(t, sProject), liftLineAs(t, head, sProject, operatorKey(), "run-1", 1)),
			reaction.ErrSignedLiftMismatch, reaction.CauseLift},
		{"a lift naming a later line than it was signed for", joinLines(header, signedStop(t, sProject), signedStopOf(t, sProject, "f-2"),
			liftLineAs(t, head, sProject, operatorKey(), "run-1", 3)), reaction.ErrSignedLiftMismatch, reaction.CauseLift},
	} {
		_, err := reaction.Judge(r, reaction.Prefix{}, c.content, sNow, 0)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
			continue
		}
		snap := reaction.Snapshot{}.Next(r, c.content, sNow, time.Second)
		if snap.State() != reaction.Unknown || snap.Cause() != c.cause {
			t.Errorf("%s: snapshot %v %q, want unknown with %q", c.name, snap.State(), snap.Cause(), c.cause)
		}
	}
}

// TestAVoucherThatCannotAnswerIsItsOwnCause: a header judged while the
// voucher cannot answer is refused, and the snapshot names the ports, not a
// header that does not verify.
func TestAVoucherThatCannotAnswerIsItsOwnCause(t *testing.T) {
	v := newVoucher()
	r := vouchedRoute(t, v)
	header, _ := signedHeaderLine(t, r, headerOpts{})
	v.unanswered = true
	if _, err := reaction.Judge(r, reaction.Prefix{}, joinLines(header), sNow, 0); !errors.Is(err, reaction.ErrUnanswered) {
		t.Fatalf("a header judged while the voucher cannot answer: %v", err)
	}
	snap := reaction.Snapshot{}.Next(r, joinLines(header), sNow, time.Second)
	if snap.State() != reaction.Unknown || snap.Cause() != reaction.CauseUnanswered {
		t.Fatalf("the snapshot: %v %q, want unknown with %q", snap.State(), snap.Cause(), reaction.CauseUnanswered)
	}
}

func TestALiftForOneListHeadIsRefusedOnAnother(t *testing.T) {
	r := vouchedRoute(t, newVoucher())
	headerA, headA := signedHeaderLine(t, r, headerOpts{})
	// B is the list carried from A: the same plane, a new list id and serial.
	h := reaction.Header{ListID: "lst-2", RouteID: r.ID(), RouteSerial: r.Serial(), RouteDigest: r.Digest(),
		Signed: reaction.HeaderSigned{KeyID: keyIDOf(operatorKey()), TenantID: sTenant, ProjectID: sProject, File: sListFile, Serial: 2, Previous: headA}}
	body, err := reaction.HeaderBody(h)
	if err != nil {
		t.Fatalf("HeaderBody: %v", err)
	}
	headerB, err := reaction.SignedHeaderLine(envelopeOf(t, reaction.SignedHeaderPayloadType, body, operatorKey(), keyIDOf(operatorKey())))
	if err != nil {
		t.Fatalf("SignedHeaderLine: %v", err)
	}
	liftA := signedLiftLine(t, headA, sProject, operatorKey())
	if _, err := reaction.Judge(r, reaction.Prefix{}, joinLines(headerA, signedStop(t, sProject), liftA), sNow, 0); err != nil {
		t.Fatalf("the lift on its own list: %v", err)
	}
	_, err = reaction.Judge(r, reaction.Prefix{}, joinLines(headerB, signedStop(t, sProject), liftA), sNow, 0)
	if !errors.Is(err, reaction.ErrSignedLiftMismatch) {
		t.Fatalf("list A's lift on list B: %v, want %v", err, reaction.ErrSignedLiftMismatch)
	}
}

func TestAVersionOneLiftIsRefusedInASignedList(t *testing.T) {
	r := vouchedRoute(t, newVoucher())
	header, _ := signedHeaderLine(t, r, headerOpts{})
	body, err := reaction.Lift{Version: reaction.LiftVersion, ListID: "lst-1", RouteDigest: r.Digest(), RunID: "run-1", ThroughLine: 2}.Payload()
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	env := envelopeOf(t, reaction.LiftPayloadType, body, operatorKey(), keyIDOf(operatorKey()))
	line, err := reaction.LiftLine{RunID: "run-1", ThroughLine: 2, Envelope: env}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := reaction.Judge(r, reaction.Prefix{}, joinLines(header, signedStop(t, sProject), line), sNow, 0); !errors.Is(err, reaction.ErrListVersion) {
		t.Fatalf("a 1.0 lift line in a 2.0 list: %v, want %v", err, reaction.ErrListVersion)
	}
}

func TestASignedLineIsRefusedUnderAV1alpha1Route(t *testing.T) {
	r := validRoute(t)
	line := signedStop(t, sProject)
	h, err := reaction.HeaderFor(r, "lst-1").Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := reaction.Judge(r, reaction.Prefix{}, joinLines(h, line), sNow, 0); !errors.Is(err, reaction.ErrListVersion) {
		t.Fatalf("a 2.0 stop in a 1.0 list: %v, want %v", err, reaction.ErrListVersion)
	}
}

// TestASignedRoutePermitsOnlyAStopOfItsProjectAndScope: the claim of the
// route's tenant, project, rule and scope is permitted; another project,
// no project and another scope are each refused.
func TestASignedRoutePermitsOnlyAStopOfItsProjectAndScope(t *testing.T) {
	r := vouchedRoute(t, newVoucher())
	claim := reaction.StopClaim{TenantID: sTenant, ProjectID: sProject, Scope: reaction.ScopeRun,
		ProcedureID: "refund", ProcedureVersion: "3", ProcedureDigest: procDigest,
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: sCreated, ExpiresAt: sCreated.Add(time.Minute)}
	if err := r.Permits(claim); err != nil {
		t.Fatalf("the route's own claim: %v", err)
	}
	for _, c := range []struct {
		name string
		edit func(*reaction.StopClaim)
		want error
	}{
		{"another project", func(c *reaction.StopClaim) { c.ProjectID = "other" }, reaction.ErrClaimProject},
		{"no project", func(c *reaction.StopClaim) { c.ProjectID = "" }, reaction.ErrClaimProject},
		{"another scope", func(c *reaction.StopClaim) { c.Scope = "tree" }, reaction.ErrClaimScope},
		{"no scope", func(c *reaction.StopClaim) { c.Scope = "" }, reaction.ErrClaimScope},
	} {
		edited := claim
		c.edit(&edited)
		if err := r.Permits(edited); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}
