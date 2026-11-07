package signedruns_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
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
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/runs/signedruns"
	"github.com/guardana/control/internal/trust"
)

func key(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("signedruns-test/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func public(name string) ed25519.PublicKey { return key(name).Public().(ed25519.PublicKey) }

func keyID(name string) string { return policykey.KeyID(public(name)) }

func signer(name string) runs.Signer {
	return runs.Signer{KeyID: keyID(name), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key(name))
	}}
}

func rosterEntry(name, project, level string) map[string]any {
	return map[string]any{
		"keyId": keyID(name), "alg": "ed25519", "role": "operator", "subject": name,
		"publicKey": policykey.FormatPublic(public(name)),
		"grants":    []any{map[string]any{"tenant": "t1", "project": project, "level": level}},
	}
}

var now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// world is a roster in which alice operates A, bob only reads A and carol
// operates B, both judges of a plane of tenant t1 and project A over it, and
// a signed runs directory.
type world struct {
	authn  operators.Authenticator
	authz  operators.Authorizer
	ports  *signedruns.Authority
	roster signedruns.Roster
	dir    string
	admin  *runs.Admin
}

func newWorld(t *testing.T) *world {
	t.Helper()
	base := t.TempDir()
	body, err := canon.Canonicalize(map[string]any{
		"kind": trust.DocumentKind, "rosterId": "roster-a", "serial": int64(1),
		"issuedAt": "2026-10-30T00:00:00Z", "expiresAt": "2026-10-31T00:00:00Z",
		"keys": []any{rosterEntry("alice", "A", "operate"), rosterEntry("bob", "A", "read"), rosterEntry("carol", "B", "operate")},
	})
	if err != nil {
		t.Fatal(err)
	}
	rosterPath := filepath.Join(base, "roster.json")
	env := writeRoster(t, rosterPath, body)
	floor := filepath.Join(base, "authority")
	if err := policystate.InitAuthority(t.Context(), floor, "roster-a"); err != nil {
		t.Fatal(err)
	}
	roster, err := trust.Open(t.Context(), trust.Config{Root: public("root"), RosterID: "roster-a", Path: rosterPath,
		FloorDir: floor, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	authn, err := operators.NewAuthenticator("", roster, operators.Bounds{})
	if err != nil {
		t.Fatal(err)
	}
	authz, err := operators.NewAuthorizer("", roster, operators.Bounds{})
	if err != nil {
		t.Fatal(err)
	}
	w := &world{dir: filepath.Join(base, "runs"), authn: authn, authz: authz}
	if w.ports, err = signedruns.New(authn, authz, "t1", "A"); err != nil {
		t.Fatal(err)
	}
	doc, err := trust.VerifyDocument(env, public("root"))
	if err != nil {
		t.Fatal(err)
	}
	w.roster = signedruns.Roster{Document: doc}
	if err := os.Mkdir(w.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if w.admin, err = runs.InitSignedAdmin(t.Context(), w.dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.admin.Close() })
	return w
}

// writeRoster signs body with the root key and writes it at path.
func writeRoster(t *testing.T, path string, body []byte) trust.Envelope {
	t.Helper()
	sig, err := bundle.SignBytesAs(trust.PayloadType, body, key("root"))
	if err != nil {
		t.Fatal(err)
	}
	env := trust.Envelope{PayloadType: trust.PayloadType, Payload: body, Signatures: []trust.Signature{{KeyID: keyID("root"), Signature: sig}}}
	raw, err := trust.MarshalFile(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return env
}

func who(project string) runs.Identity {
	return runs.Identity{ProjectID: project, TenantID: "t1", PrincipalType: "user", PrincipalID: "p", AgentID: "a"}
}

// open opens a root run of project signed by the key called by, through a
// judge that takes any record, so a record the judges under test refuse is
// written all the same.
func (w *world) open(t *testing.T, by, project string) (runs.Record, string) {
	t.Helper()
	return w.openAs(t, by, who(project))
}

func (w *world) openAs(t *testing.T, by string, id runs.Identity) (runs.Record, string) {
	t.Helper()
	rec, token, err := w.admin.OpenSigned(t.Context(), runs.OpenRequest{Who: id, TTL: time.Hour, Now: now}, signer(by),
		judgeFunc(func(runs.SignedRecord) {}))
	if err != nil {
		t.Fatalf("OpenSigned by %s: %v", by, err)
	}
	return rec, token
}

func (w *world) stored(t *testing.T, id string) runs.SignedRecord {
	t.Helper()
	var got runs.SignedRecord
	p, err := runs.OpenSignedPlane(w.dir, runs.SignedOptions{Judge: judgeFunc(func(r runs.SignedRecord) { got = r }), PlaneOwned: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	if _, err := p.Lookup(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	return got
}

// judgeFunc hands a judge the record it is asked of and takes it.
type judgeFunc func(runs.SignedRecord)

func (f judgeFunc) Judge(_ context.Context, r runs.SignedRecord) (runs.SignedBy, error) {
	f(r)
	return runs.SignedBy{}, nil
}

func TestTheRecordPayloadTypeIsTheRunActs(t *testing.T) {
	if runs.RecordPayloadType != operators.RunPayloadType {
		t.Fatalf("runs signs under %q, the run act takes %q", runs.RecordPayloadType, operators.RunPayloadType)
	}
}

// TestBothJudgesTakeOnlyAnOperatorOfThePlanesProject: alice's record of A is
// taken by the ports of a plane of A and by the roster; a reader's, an
// operator of another project's, an unknown key's and a record of another
// project or of another tenant are each refused with their own cause, by
// both judges.
func TestBothJudgesTakeOnlyAnOperatorOfThePlanesProject(t *testing.T) {
	w := newWorld(t)
	scoped := signedruns.Roster{Document: w.roster.Document, Tenant: "t1", Project: "A"}
	cases := []struct {
		name, by, project string
		want              error
	}{
		{"alice in A", "alice", "A", nil},
		{"bob, who reads A", "bob", "A", runs.ErrUnauthorized},
		{"carol, who operates B, in A", "carol", "A", runs.ErrUnauthorized},
		{"carol in B", "carol", "B", runs.ErrOtherScope},
		{"a key the roster lacks", "mallory", "A", runs.ErrUnauthenticated},
	}
	for _, c := range cases {
		rec, _ := w.open(t, c.by, c.project)
		sr := w.stored(t, rec.ID)
		for name, j := range map[string]runs.Judge{"ports": w.ports, "roster": scoped} {
			by, err := j.Judge(t.Context(), sr)
			switch {
			case c.want == nil && (err != nil || by.Subject != c.by || by.KeyID != keyID(c.by)):
				t.Errorf("%s, %s: %+v, %v; want taken from %s", c.name, name, by, err, c.by)
			case c.want != nil && !errors.Is(err, c.want):
				t.Errorf("%s, %s: %v; want %v", c.name, name, err, c.want)
			}
		}
	}
	rec, _ := w.open(t, "carol", "B")
	if _, err := w.roster.Judge(t.Context(), w.stored(t, rec.ID)); err != nil {
		t.Errorf("the unscoped roster judge refuses carol's record of B: %v", err)
	}
	other := who("A")
	other.TenantID = "t2"
	rec, _ = w.openAs(t, "alice", other)
	sr := w.stored(t, rec.ID)
	for name, j := range map[string]runs.Judge{"ports": w.ports, "roster": scoped} {
		if _, err := j.Judge(t.Context(), sr); !errors.Is(err, runs.ErrOtherScope) {
			t.Errorf("alice's record of tenant t2, project A, %s: %v; want %v", name, err, runs.ErrOtherScope)
		}
	}
}

// TestASignatureOfAnotherRecordIsRefused: alice's signature over one record
// set on another of hers verifies under neither judge.
func TestASignatureOfAnotherRecordIsRefused(t *testing.T) {
	w := newWorld(t)
	first, _ := w.open(t, "alice", "A")
	second, token := w.open(t, "alice", "A")
	path := func(id string) string { return filepath.Join(w.dir, "records", id+".run.json") }
	var a, b map[string]json.RawMessage
	for _, x := range []struct {
		id string
		m  *map[string]json.RawMessage
	}{{first.ID, &a}, {second.ID, &b}} {
		raw, err := os.ReadFile(path(x.id))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, x.m); err != nil {
			t.Fatal(err)
		}
	}
	b["signatures"] = a["signatures"]
	forged, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path(second.ID), forged, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, j := range map[string]runs.Judge{"ports": w.ports, "roster": w.roster} {
		p, err := runs.OpenSignedPlane(w.dir, runs.SignedOptions{Judge: j, PlaneOwned: true})
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Resolve(t.Context(), token, who("A"), now.Add(time.Minute))
		_ = p.Close()
		var r *runs.Refusal
		if !errors.As(err, &r) || r.Cause != runs.CauseUnreadable || !errors.Is(err, runs.ErrUnauthenticated) {
			t.Errorf("%s: Resolve of a record under another's signature = %v, want unreadable, ErrUnauthenticated", name, err)
		}
	}
}

// TestNewRefusesAJudgeOfNothing: a judge with a port, the tenant or the
// project missing is no judge.
func TestNewRefusesAJudgeOfNothing(t *testing.T) {
	w := newWorld(t)
	if _, err := signedruns.New(nil, nil, "t1", "A"); !errors.Is(err, runs.ErrUnjudged) {
		t.Errorf("New with no ports = %v, want ErrUnjudged", err)
	}
	if _, err := signedruns.New(w.authn, nil, "t1", "A"); !errors.Is(err, runs.ErrUnjudged) {
		t.Errorf("New with no authorizer = %v, want ErrUnjudged", err)
	}
	for _, scope := range [][2]string{{"", "A"}, {"t1", ""}} {
		if _, err := signedruns.New(w.authn, w.authz, scope[0], scope[1]); !errors.Is(err, runs.ErrUnjudged) {
			t.Errorf("New for %q = %v, want ErrUnjudged", scope, err)
		}
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

// TestARecordNoPortCanJudgeRefusesItsCall: a plane whose authenticator or
// authorizer gives no answer refuses alice's run as unreadable through
// Resolve, and so does Lookup; the control, the plane's own ports, resolves
// it.
func TestARecordNoPortCanJudgeRefusesItsCall(t *testing.T) {
	w := newWorld(t)
	rec, token := w.open(t, "alice", "A")
	for _, c := range []struct {
		name  string
		authn operators.Authenticator
		authz operators.Authorizer
		want  error
	}{
		{"the control, the plane's ports", w.authn, w.authz, nil},
		{"an authenticator with no answer", unavailable{}, w.authz, runs.ErrAuthority},
		{"an authorizer with no answer", w.authn, unavailable{}, runs.ErrAuthority},
	} {
		resolveErr, lookupErr := w.askWith(t, c.authn, c.authz, token, rec.ID)
		var r *runs.Refusal
		switch {
		case c.want == nil && (resolveErr != nil || lookupErr != nil):
			t.Errorf("%s: Resolve = %v, Lookup = %v; want the run", c.name, resolveErr, lookupErr)
		case c.want != nil && (!errors.As(resolveErr, &r) || r.Cause != runs.CauseUnreadable || !errors.Is(resolveErr, c.want)):
			t.Errorf("%s: Resolve = %v, want unreadable and %v", c.name, resolveErr, c.want)
		case c.want != nil && !errors.Is(lookupErr, c.want):
			t.Errorf("%s: Lookup = %v, want %v", c.name, lookupErr, c.want)
		}
	}
}

// askWith resolves token and looks up id on a plane of t1/A judging with
// authn and authz, and returns both answers' errors.
func (w *world) askWith(t *testing.T, authn operators.Authenticator, authz operators.Authorizer, token, id string) (error, error) {
	t.Helper()
	j, err := signedruns.New(authn, authz, "t1", "A")
	if err != nil {
		t.Fatal(err)
	}
	p, err := runs.OpenSignedPlane(w.dir, runs.SignedOptions{Judge: j, PlaneOwned: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	_, resolveErr := p.Resolve(t.Context(), token, who("A"), now.Add(time.Minute))
	_, lookupErr := p.Lookup(t.Context(), id)
	return resolveErr, lookupErr
}
