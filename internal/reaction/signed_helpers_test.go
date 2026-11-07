package reaction_test

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/reaction"
)

// The plane every signed test judges for.
const (
	sTenant    = "acme"
	sProject   = "shop"
	sRouteFile = "/plane/route.json"
	sListFile  = "/plane/stops/stops.jsonl"
)

var (
	errDenied  = errors.New("the fake voucher denies the act")
	errUnknown = errors.New("the fake voucher knows no such key")
)

// operatorKey is the operator key the fake voucher knows; strangerKey one
// it does not.
func operatorKey() ed25519.PrivateKey { return seededKey(0x6f) }
func strangerKey() ed25519.PrivateKey { return seededKey(0x73) }

// fakeVoucher verifies a signature under the one operator key it knows,
// with the payload type of the kind asked about, and denies each kind deny
// names, as an operator with no grant for it.
type fakeVoucher struct {
	plane      reaction.Plane
	deny       map[reaction.SignedKind]bool
	asked      map[reaction.SignedKind]int
	unanswered bool
}

func newVoucher() *fakeVoucher {
	return &fakeVoucher{
		plane: reaction.Plane{Tenant: sTenant, Project: sProject, RouteFile: sRouteFile, ListFile: sListFile},
		deny:  map[reaction.SignedKind]bool{}, asked: map[reaction.SignedKind]int{},
	}
}

func (f *fakeVoucher) Plane() reaction.Plane { return f.plane }

func (f *fakeVoucher) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	f.asked[kind]++
	if f.unanswered {
		return reaction.Signer{}, fmt.Errorf("%w: the fake voucher's ports are down", reaction.ErrUnanswered)
	}
	if f.deny[kind] {
		return reaction.Signer{}, errDenied
	}
	types := map[reaction.SignedKind]string{
		reaction.VouchRoute:  "application/vnd.agent-reaction-route.v1alpha2+json",
		reaction.VouchHeader: "application/vnd.agent-stop-list-header+json",
		reaction.VouchLift:   "application/vnd.agent-reaction-lift.v1alpha2+json",
	}
	sig := env.Signatures[0]
	id := keyIDOf(operatorKey())
	if sig.KeyID != id {
		return reaction.Signer{}, errUnknown
	}
	if err := bundle.VerifyBytesAs(types[kind], env.Payload, sig.Signature, id, bundle.Keyring{id: pubOf(operatorKey())}); err != nil {
		return reaction.Signer{}, err
	}
	return reaction.Signer{Subject: "alice", KeyID: id}, nil
}

// signedRouteDoc is a v1alpha2 route as an operator writes it, with PROJECT
// in place of the project.
const signedRouteDoc = `{"kind":"reaction-route/v1alpha2","route_id":"refunds","serial":7,"tenant_id":"acme",
 "project_id":"PROJECT","rules":[{"procedure_id":"refund","version":"3","digest":"` + procDigest + `",
 "rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run","expires_seconds":3600}]}`

// envelopeOf is body signed by key under payloadType, the signature naming
// keyID.
func envelopeOf(t testing.TB, payloadType string, body []byte, key ed25519.PrivateKey, keyID string) reaction.Envelope {
	t.Helper()
	sig, err := bundle.SignBytesAs(payloadType, body, key)
	if err != nil {
		t.Fatalf("SignBytesAs: %v", err)
	}
	return reaction.Envelope{PayloadType: payloadType, Payload: body, Signatures: []reaction.Signature{{KeyID: keyID, Signature: sig}}}
}

// routeEnvelope is the route of project bound to file, signed by key.
func routeEnvelope(t testing.TB, project, file string, key ed25519.PrivateKey) reaction.Envelope {
	t.Helper()
	body, err := reaction.SignedRouteBody([]byte(strings.ReplaceAll(signedRouteDoc, "PROJECT", project)), keyIDOf(key), file)
	if err != nil {
		t.Fatalf("SignedRouteBody: %v", err)
	}
	return envelopeOf(t, reaction.SignedRoutePayloadType, body, key, keyIDOf(key))
}

func vouchedRoute(t testing.TB, v reaction.Voucher) reaction.Route {
	t.Helper()
	r, err := reaction.VerifySignedRoute(routeEnvelope(t, sProject, sRouteFile, operatorKey()), v)
	if err != nil {
		t.Fatalf("VerifySignedRoute: %v", err)
	}
	return r
}

// headerOpts varies a signed header from the one the plane takes.
type headerOpts struct {
	project, file string
	key           ed25519.PrivateKey
}

// signedHeaderLine is a 2.0 header line under r, and the head digest its
// body has.
func signedHeaderLine(t testing.TB, r reaction.Route, o headerOpts) ([]byte, string) {
	t.Helper()
	if o.project == "" {
		o.project = sProject
	}
	if o.file == "" {
		o.file = sListFile
	}
	if o.key == nil {
		o.key = operatorKey()
	}
	h := reaction.Header{ListID: "lst-1", RouteID: r.ID(), RouteSerial: r.Serial(), RouteDigest: r.Digest(),
		Signed: reaction.HeaderSigned{KeyID: keyIDOf(o.key), TenantID: sTenant, ProjectID: o.project, File: o.file, Serial: 1}}
	body, err := reaction.HeaderBody(h)
	if err != nil {
		t.Fatalf("HeaderBody: %v", err)
	}
	line, err := reaction.SignedHeaderLine(envelopeOf(t, reaction.SignedHeaderPayloadType, body, o.key, keyIDOf(o.key)))
	if err != nil {
		t.Fatalf("SignedHeaderLine: %v", err)
	}
	return line, bundle.Digest(body)
}

var sCreated = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// signedStop is a 2.0 stop of run-1 for finding f-1, of project.
func signedStop(t testing.TB, project string) []byte {
	t.Helper()
	return signedStopOf(t, project, "f-1")
}

func signedStopOf(t testing.TB, project, finding string) []byte {
	t.Helper()
	line, err := reaction.Stop{
		EntryID: reaction.EntryID(finding), TenantID: sTenant, ProjectID: project, Scope: reaction.ScopeRun,
		RunID: "run-1", FindingID: finding, ProcedureID: "refund", ProcedureVersion: "3", ProcedureDigest: procDigest,
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: sCreated, ExpiresAt: sCreated.Add(30 * time.Minute),
	}.Marshal()
	if err != nil {
		t.Fatalf("Stop.Marshal: %v", err)
	}
	return line
}

// signedLiftLine is a lift of run-1 through line 2 naming head, signed by
// key, of project.
func signedLiftLine(t testing.TB, head, project string, key ed25519.PrivateKey) []byte {
	t.Helper()
	return liftLineAs(t, head, project, key, "run-1", 2)
}

// liftLineAs is signedLiftLine whose signed body names run-1 through line 2
// and whose line names run through line through.
func liftLineAs(t testing.TB, head, project string, key ed25519.PrivateKey, run string, through int64) []byte {
	t.Helper()
	l := reaction.SignedLift{KeyID: keyIDOf(key), ListHead: head, RunID: "run-1", ThroughLine: 2,
		TenantID: sTenant, Project: project, File: sListFile}
	body, err := l.Payload()
	if err != nil {
		t.Fatalf("SignedLift.Payload: %v", err)
	}
	env := envelopeOf(t, reaction.SignedLiftPayloadType, body, key, keyIDOf(key))
	line, err := reaction.LiftLine{RunID: run, ThroughLine: through, Envelope: env}.Marshal()
	if err != nil {
		t.Fatalf("LiftLine.Marshal: %v", err)
	}
	return line
}

func joinLines(lines ...[]byte) []byte {
	var out []byte
	for _, l := range lines {
		out = append(append(out, l...), '\n')
	}
	return out
}
