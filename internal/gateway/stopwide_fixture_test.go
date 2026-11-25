package gateway_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/supervise"
)

// The plane a list of agent and principal stops is signed for.
const (
	widePlane     = "plane-1"
	wideProject   = "proj-1"
	wideRouteFile = "/plane/route.json"
	wideListFile  = "/plane/stops/stops.jsonl"
)

// wideOperator is the one operator key wideVoucher takes.
func wideOperator() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6f}, ed25519.SeedSize))
}

func wideKeyID() string { return policykey.KeyID(wideOperator().Public().(ed25519.PublicKey)) }

// wideVoucher takes any one signature of wideOperator, for the plane of
// tenant.
type wideVoucher struct{ tenant string }

func (v wideVoucher) Plane() reaction.Plane {
	return reaction.Plane{ID: widePlane, Tenant: v.tenant, Project: wideProject, RouteFile: wideRouteFile, ListFile: wideListFile}
}

func (wideVoucher) Vouch(_ reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	if len(env.Signatures) != 1 {
		return reaction.Signer{}, errors.New("the fake voucher takes one signature")
	}
	sig := env.Signatures[0]
	keys := bundle.Keyring{wideKeyID(): wideOperator().Public().(ed25519.PublicKey)}
	if err := bundle.VerifyBytesAs(env.PayloadType, env.Payload, sig.Signature, sig.KeyID, keys); err != nil {
		return reaction.Signer{}, err
	}
	return reaction.Signer{Subject: "alice", KeyID: wideKeyID()}, nil
}

// wideRoute is a v1alpha3 route of tenant over the refund procedure whose
// STEP_OUTSIDE_PROCEDURE stops a run, REPEATED_DENIAL an agent and, under
// wideVersion's version for a principal, a principal, each for an hour.
func wideRoute(t *testing.T, tenant string) reaction.Route {
	t.Helper()
	p := stopProcedure(t)
	rule := func(id, version, scope string) string {
		return `{"procedure_id":"` + p.ID() + `","version":"` + wideVersion(p, scope) + `","digest":"` + p.Digest() + `","rule_id":"` + id +
			`","rule_version":"` + version + `","scope":"` + scope + `","expires_seconds":3600}`
	}
	doc := `{"kind":"reaction-route/v1alpha3","plane_id":"` + widePlane + `","route_id":"refunds","serial":1,"tenant_id":"` + tenant +
		`","project_id":"` + wideProject + `","rules":[` + rule("STEP_OUTSIDE_PROCEDURE", "1", "run") + "," +
		rule("REPEATED_DENIAL", "2", "agent") + "," + rule("REPEATED_DENIAL", "2", "principal") + `]}`
	body, err := reaction.SignedRouteBody([]byte(doc), wideKeyID(), wideRouteFile)
	if err != nil {
		t.Fatalf("SignedRouteBody: %v", err)
	}
	r, err := reaction.VerifySignedRoute(wideEnvelope(t, reaction.SignedRoutePayloadType, body), wideVoucher{tenant})
	if err != nil {
		t.Fatalf("VerifySignedRoute: %v", err)
	}
	return r
}

// wideVersion is the procedure version wideRoute's rule of scope names: a
// route names a rule once per procedure, so the principal's rule is of a
// second version.
func wideVersion(p *supervise.Procedure, scope string) string {
	if scope == reaction.ScopePrincipal {
		return p.Version() + "-principal"
	}
	return p.Version()
}

func wideEnvelope(t *testing.T, payloadType string, body []byte) reaction.Envelope {
	t.Helper()
	sig, err := bundle.SignBytesAs(payloadType, body, wideOperator())
	if err != nil {
		t.Fatalf("SignBytesAs: %v", err)
	}
	return reaction.Envelope{PayloadType: payloadType, Payload: body, Signatures: []reaction.Signature{{KeyID: wideKeyID(), Signature: sig}}}
}

// wideList is a 3.0 stop list of one tenant written line by line.
type wideList struct {
	t      *testing.T
	tenant string
	route  reaction.Route
	proc   *supervise.Procedure
	head   string
	lines  [][]byte
}

func newWideList(t *testing.T, tenant string) *wideList {
	t.Helper()
	l := &wideList{t: t, tenant: tenant, route: wideRoute(t, tenant), proc: stopProcedure(t)}
	h := reaction.Header{ListID: "list-1", RouteID: l.route.ID(), RouteSerial: l.route.Serial(), RouteDigest: l.route.Digest(),
		Signed: reaction.HeaderSigned{KeyID: wideKeyID(), PlaneID: widePlane, TenantID: tenant, ProjectID: wideProject,
			File: wideListFile, Serial: 1}}
	body, err := reaction.HeaderBody(h)
	if err != nil {
		t.Fatalf("HeaderBody: %v", err)
	}
	l.head = bundle.Digest(body)
	l.add(reaction.SignedHeaderLine(wideEnvelope(t, reaction.SignedHeaderPayloadType, body)))
	return l
}

func (l *wideList) add(line []byte, err error) int64 {
	l.t.Helper()
	if err != nil {
		l.t.Fatalf("line %d: %v", len(l.lines)+1, err)
	}
	l.lines = append(l.lines, line)
	return int64(len(l.lines))
}

// stop appends a stop of scope and subject made from a finding about
// run-a, created at the second of base() and lasting an hour.
func (l *wideList) stop(scope, subject string) int64 {
	l.t.Helper()
	id, version := "STEP_OUTSIDE_PROCEDURE", "1"
	if scope != reaction.ScopeRun {
		id, version = "REPEATED_DENIAL", "2"
	}
	finding := "finding-" + strconv.Itoa(len(l.lines))
	created := base().Truncate(time.Second)
	return l.add(reaction.Stop{
		EntryID: reaction.EntryID(finding), TenantID: l.tenant, ProjectID: wideProject, Scope: scope, Subject: subject,
		RunID: "run-a", FindingID: finding, ProcedureID: l.proc.ID(), ProcedureVersion: wideVersion(l.proc, scope),
		ProcedureDigest: l.proc.Digest(), RuleID: id, RuleVersion: version, CreatedAt: created, ExpiresAt: created.Add(time.Hour),
	}.Marshal())
}

// lift appends an operator's lift of scope and subject through line.
func (l *wideList) lift(scope, subject string, through int64) {
	l.t.Helper()
	body, err := reaction.SignedLiftV3{KeyID: wideKeyID(), PlaneID: widePlane, ListHead: l.head, Scope: scope, Subject: subject,
		ThroughLine: through, TenantID: l.tenant, Project: wideProject, File: wideListFile}.Payload()
	if err != nil {
		l.t.Fatalf("SignedLiftV3.Payload: %v", err)
	}
	env := wideEnvelope(l.t, reaction.SignedLiftPayloadType, body)
	l.add(reaction.LiftLine{Scope: scope, Subject: subject, ThroughLine: through, Envelope: env}.Marshal())
}

// readAt is the snapshot a plane reads of the list at at; the list has to be
// one the judge accepts.
func (l *wideList) readAt(at time.Time) reaction.Snapshot {
	l.t.Helper()
	var content []byte
	for _, line := range l.lines {
		content = append(append(content, line...), '\n')
	}
	s := reaction.Snapshot{}.Next(l.route, content, at, stopInterval)
	if s.State() == reaction.Unknown {
		l.t.Fatalf("the stop list read as unknown: %s: %s", s.Cause(), s.Detail())
	}
	return s
}
