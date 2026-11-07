package signedpause_test

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
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/pause/signedpause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/trust"
)

func key(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("signedpause-test/" + name))
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

// plane is a plane of tenant t1 and project A: a roster in which alice
// operates A, bob only reads A and carol operates B; the operator ports over
// it; and a pause floor of its own.
type plane struct {
	authn  operators.Authenticator
	authz  operators.Authorizer
	roster trust.Document
	floor  string
	// file is the plane's pause file and bound the path a document for it
	// names.
	file, bound string
}

// writeRoster writes the roster the root signed into base and returns its
// path and the document it verifies as.
func writeRoster(t *testing.T, base string) (string, trust.Document) {
	t.Helper()
	body, err := canon.Canonicalize(map[string]any{
		"kind": trust.DocumentKind, "rosterId": "roster-a", "serial": int64(1),
		"issuedAt": "2026-10-30T00:00:00Z", "expiresAt": "2026-10-31T00:00:00Z",
		"keys": []any{rosterEntry("alice", "A", "operate"), rosterEntry("bob", "A", "read"), rosterEntry("carol", "B", "operate")},
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
	path := filepath.Join(base, "roster.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := trust.VerifyDocument(env, public("root"))
	if err != nil {
		t.Fatal(err)
	}
	return path, doc
}

func newPlane(t *testing.T) *plane {
	t.Helper()
	base := t.TempDir()
	rosterPath, doc := writeRoster(t, base)
	authorityFloor := filepath.Join(base, "authority")
	if err := policystate.InitAuthority(t.Context(), authorityFloor, "roster-a"); err != nil {
		t.Fatal(err)
	}
	roster, err := trust.Open(t.Context(), trust.Config{Root: public("root"), RosterID: "roster-a", Path: rosterPath,
		FloorDir: authorityFloor, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	p := &plane{roster: doc, floor: filepath.Join(base, "pausefloor"), file: filepath.Join(base, "pause", "pause.json")}
	if err := os.Mkdir(filepath.Dir(p.file), 0o700); err != nil {
		t.Fatal(err)
	}
	if p.bound, err = pause.BindingOf(p.file); err != nil {
		t.Fatal(err)
	}
	if p.authn, err = operators.NewAuthenticator("", roster, operators.Bounds{}); err != nil {
		t.Fatal(err)
	}
	if p.authz, err = operators.NewAuthorizer("", roster, operators.Bounds{}); err != nil {
		t.Fatal(err)
	}
	if err := policystate.InitPause(t.Context(), p.floor, "t1", "A"); err != nil {
		t.Fatal(err)
	}
	return p
}

// judge is a judge of p, as a plane started now would hold it.
func (p *plane) judge(t *testing.T) *signedpause.Authority {
	t.Helper()
	j, err := signedpause.New(p.authn, p.authz, "t1", "A", p.file, p.floor)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

var global = pause.Document{Entries: []pause.Entry{{ID: "g", Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: now}}}

// signed is a document of tenant and project at serial over d, signed by the
// key called by under the key id of the key called as.
func (p *plane) signed(t *testing.T, by, as, tenant, project string, serial int64, d pause.Document) pause.Signed {
	t.Helper()
	return signedFor(t, by, as, tenant, project, p.bound, serial, d)
}

// signedFor is signed for the pause file at file.
func signedFor(t *testing.T, by, as, tenant, project, file string, serial int64, d pause.Document) pause.Signed {
	t.Helper()
	h := pause.Header{KeyID: keyID(as), Tenant: tenant, Project: project, File: file, Serial: serial}
	body, err := pause.MarshalSigned(h, d)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(operators.PausePayloadType, body, key(by))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := pause.ParseSigned(body)
	if err != nil {
		t.Fatal(err)
	}
	return pause.Signed{
		Envelope: policy.StatementEnvelope{PayloadType: operators.PausePayloadType, Payload: body,
			Signatures: []policy.StatementSignature{{KeyID: keyID(as), Signature: sig}}},
		Body: parsed,
	}
}

func (p *plane) byAlice(serial int64, d pause.Document) func(*testing.T) pause.Signed {
	return func(t *testing.T) pause.Signed { return p.signed(t, "alice", "alice", "t1", "A", serial, d) }
}

func wantRefused(t *testing.T, what string, by pause.SignedBy, err error, want pause.Error) {
	t.Helper()
	if !errors.Is(err, want) || by != (pause.SignedBy{}) {
		t.Errorf("%s = %+v, %v; want %v", what, by, err, want)
	}
}

func TestThePayloadTypeAndTheBoundAreTheOperatorPorts(t *testing.T) {
	if pause.PayloadType != operators.PausePayloadType {
		t.Errorf("pause.PayloadType %q, operators.PausePayloadType %q", pause.PayloadType, operators.PausePayloadType)
	}
	if pause.MaxSignedBodyBytes != operators.MaxStatementBytes {
		t.Errorf("pause.MaxSignedBodyBytes %d, operators.MaxStatementBytes %d", pause.MaxSignedBodyBytes, operators.MaxStatementBytes)
	}
}

func TestAPermittedOperatorsPauseIsTakenAndRaisesTheFloor(t *testing.T) {
	p := newPlane(t)
	by, err := p.judge(t).Judge(t.Context(), p.byAlice(1, global)(t))
	if err != nil || by != (pause.SignedBy{Subject: "alice", KeyID: keyID("alice"), Serial: 1, Floor: 1}) {
		t.Fatalf("alice's pause = %+v, %v", by, err)
	}
	if f, err := policystate.ReadPause(p.floor, "t1", "A"); err != nil || f.Serial != 1 {
		t.Errorf("the floor = %+v, %v; want serial 1", f, err)
	}
}

// TestNoOneButAPermittedOperatorPausesOrLifts: each refusal leaves the floor
// as it was.
func TestNoOneButAPermittedOperatorPausesOrLifts(t *testing.T) {
	p := newPlane(t)
	j := p.judge(t)
	for _, c := range []struct {
		name string
		f    pause.Signed
		want pause.Error
	}{
		{"bob, who only reads A", p.signed(t, "bob", "bob", "t1", "A", 1, pause.Document{}), pause.ErrUnauthorized},
		{"carol, who operates B", p.signed(t, "carol", "carol", "t1", "A", 1, pause.Document{}), pause.ErrUnauthorized},
		{"alice for another tenant", p.signed(t, "alice", "alice", "t2", "A", 1, pause.Document{}), pause.ErrOtherScope},
		{"carol for her own project", p.signed(t, "carol", "carol", "t1", "B", 1, pause.Document{}), pause.ErrOtherScope},
		{"a key the roster does not name", p.signed(t, "mallory", "mallory", "t1", "A", 1, pause.Document{}), pause.ErrUnauthenticated},
		{"mallory under alice's key id", p.signed(t, "mallory", "alice", "t1", "A", 1, pause.Document{}), pause.ErrUnauthenticated},
	} {
		by, err := j.Judge(t.Context(), c.f)
		wantRefused(t, c.name, by, err, c.want)
	}
	if _, err := j.Judge(t.Context(), p.byAlice(1, pause.Document{})(t)); err != nil {
		t.Fatalf("the control, a body alice signed: %v", err)
	}
	tampered := p.byAlice(2, global)(t)
	tampered.Envelope.Payload = p.byAlice(2, pause.Document{})(t).Envelope.Payload
	by, err := j.Judge(t.Context(), tampered)
	wantRefused(t, "a paused body swapped for a clear one under the same signature", by, err, pause.ErrUnauthenticated)
	if f, err := policystate.ReadPause(p.floor, "t1", "A"); err != nil || f.Serial != 1 {
		t.Errorf("the refusals moved the floor to %+v, %v", f, err)
	}
}

// TestAnOlderSignedPauseIsRefusedAfterARestart: a judge started over the
// same floor, as a restarted plane holds it, refuses a document the first
// one was past, and a second document under a taken serial.
func TestAnOlderSignedPauseIsRefusedAfterARestart(t *testing.T) {
	p := newPlane(t)
	first := p.judge(t)
	older := p.byAlice(1, pause.Document{})(t)
	for _, f := range []pause.Signed{older, p.byAlice(2, global)(t)} {
		if _, err := first.Judge(t.Context(), f); err != nil {
			t.Fatal(err)
		}
	}
	restarted := p.judge(t)
	by, err := restarted.Judge(t.Context(), older)
	wantRefused(t, "serial 1 replayed after a restart", by, err, pause.ErrBelowFloor)
	by, err = restarted.Judge(t.Context(), p.byAlice(2, pause.Document{})(t))
	wantRefused(t, "another document under serial 2", by, err, pause.ErrForked)
	if by, err := restarted.Judge(t.Context(), p.byAlice(2, global)(t)); err != nil || by.Floor != 2 {
		t.Errorf("the document at the floor read again = %+v, %v", by, err)
	}
}

// unavailable answers every statement and request with the zero answers,
// which are unavailable.
type unavailable struct{}

func (unavailable) Authenticate(context.Context, operators.Act, operators.Envelope) operators.Authentication {
	return operators.Authentication{}
}

func (unavailable) Authorize(context.Context, operators.Authentication, operators.Request) operators.Permission {
	return operators.Permission{}
}

func (unavailable) Status() operators.Status { return operators.Status{} }

func TestAPortOrAFloorThatGivesNoAnswerRefuses(t *testing.T) {
	p := newPlane(t)
	f := p.byAlice(1, global)(t)
	for _, c := range []struct {
		name  string
		authn operators.Authenticator
		authz operators.Authorizer
		floor string
		want  pause.Error
	}{
		{"an authenticator with no answer", unavailable{}, p.authz, p.floor, pause.ErrAuthority},
		{"an authorizer with no answer", p.authn, unavailable{}, p.floor, pause.ErrAuthority},
		{"a missing floor directory", p.authn, p.authz, filepath.Join(t.TempDir(), "missing"), pause.ErrFloor},
	} {
		j, err := signedpause.New(c.authn, c.authz, "t1", "A", p.file, c.floor)
		if err != nil {
			t.Fatal(err)
		}
		by, err := j.Judge(t.Context(), f)
		wantRefused(t, c.name, by, err, c.want)
	}
	for name, args := range map[string][4]string{
		"no tenant": {"", "A", p.file, p.floor}, "no project": {"t1", "", p.file, p.floor},
		"no file": {"t1", "A", "", p.floor}, "no floor": {"t1", "A", p.file, ""},
	} {
		if _, err := signedpause.New(p.authn, p.authz, args[0], args[1], args[2], args[3]); !errors.Is(err, pause.ErrOptions) {
			t.Errorf("New with %s = %v, want ErrOptions", name, err)
		}
	}
	if _, err := signedpause.New(nil, p.authz, "t1", "A", p.file, p.floor); !errors.Is(err, pause.ErrOptions) {
		t.Errorf("New with no authenticator = %v", err)
	}
	if _, err := signedpause.New(p.authn, nil, "t1", "A", p.file, p.floor); !errors.Is(err, pause.ErrOptions) {
		t.Errorf("New with no authorizer = %v", err)
	}
}
