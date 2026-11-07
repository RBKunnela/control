//go:build unix

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/trust"
)

// signedPauseTree is signedPlaneTree with a pause file signed by alice for
// acme/orders in a directory of its own, and its pause floor.
func signedPauseTree(t *testing.T) tree {
	t.Helper()
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	if err := os.Mkdir(filepath.Join(tr.dir, "pause"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := policystate.InitPause(t.Context(), filepath.Join(tr.dir, "pausefloor"), "acme", "orders"); err != nil {
		t.Fatal(err)
	}
	s := aliceSigner()
	if err := pause.InitSigned(t.Context(), filepath.Join(tr.dir, "pause", "pause.json"),
		pause.Header{KeyID: s.KeyID, Tenant: "acme", Project: "orders", Serial: 1}, s); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, tr.config, append(raw, []byte("\npause:\n  file: pause/pause.json\n  floor_dir: pausefloor\n")...))
	return tr
}

// signerOf signs as the key called name, taking every file a write starts
// from: what a writer with no roster to judge by would do.
func signerOf(name string) pause.Signer {
	key := signedTestKey(name)
	return pause.Signer{KeyID: policykey.KeyID(signedTestPublic(name)), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key)
	}, Accept: func(pause.Signed) error { return nil }}
}

// aliceSigner signs as the operator alice of signedPlaneTree.
func aliceSigner() pause.Signer { return signerOf("alice") }

// buildOneAccount builds tr's plane as dev does, with a start check that
// passes and a pause file its own account owns, which a served plane refuses.
func buildOneAccount(t *testing.T, tr tree) (*plane, error) {
	t.Helper()
	p, err := buildChecked(tr.load(t), slog.New(slog.DiscardHandler), time.Now(), roleServe, "", func(*gatewayconfig.Config) error { return nil })
	if err == nil {
		t.Cleanup(func() { _ = p.close() })
	}
	return p, err
}

// TestASignedStartRefusesAPauseFileThePlanesAccountMayWrite: a pause file or
// directory the plane's account may write refuses the start, naming the key;
// placed apart, a file its own account owns is refused at the first read;
// on one account, as dev runs, the plane serves alice's signed file and its
// health answer names the signer, the serial and the floor.
func TestASignedStartRefusesAPauseFileThePlanesAccountMayWrite(t *testing.T) {
	tr := signedPauseTree(t)
	placedApart(t, "pause.json")
	if _, err := buildSigned(t, tr); err == nil || !strings.Contains(err.Error(), "pause.file: under the signed authority the plane's own account may not be able to change it") {
		t.Fatalf("build over a plane-writable pause file = %v", err)
	}
	placedApart(t)
	if _, err := buildSigned(t, tr); !errors.Is(err, pause.ErrNotServable) || !strings.Contains(err.Error(), string(pause.CausePlaneOwned)) {
		t.Fatalf("build over a pause file the plane's account owns = %v", err)
	}
	p, err := buildOneAccount(t, tr)
	if err != nil {
		t.Fatalf("build on one account = %v", err)
	}
	snap := p.poller.Current()
	if snap.State() != pause.Clear {
		t.Fatalf("the pause state = %s, %q: %s", snap.State(), snap.Cause(), snap.Detail())
	}
	got := p.pauseAnswer(snap, time.Now()).Signed
	if got == nil || *got != (pauseSigned{Subject: "operator-a", KeyID: got.KeyID, Serial: 1, Floor: 1}) || got.KeyID == "" {
		t.Errorf("the health page's signed pause = %+v", got)
	}
}

// TestASignedPlaneTakesOnlyAPermittedNewerPause: a pause by a key the roster
// does not name, and the replay of an older document, are unknown and
// block; a restart over the replay is refused by the floor.
func TestASignedPlaneTakesOnlyAPermittedNewerPause(t *testing.T) {
	tr := signedPauseTree(t)
	file := filepath.Join(tr.dir, "pause", "pause.json")
	p, err := buildOneAccount(t, tr)
	if err != nil {
		t.Fatal(err)
	}
	older, err := os.ReadFile(file) //nolint:gosec // G304: a file under the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	global := pause.Entry{ID: "g", Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: time.Now().UTC()}
	if _, err := pause.AddSigned(t.Context(), file, global, aliceSigner()); err != nil {
		t.Fatal(err)
	}
	polled(t, p, "alice's pause", pause.Paused, "")
	if _, err := pause.RemoveSigned(t.Context(), file, "g", signerOf("mallory")); err != nil {
		t.Fatal(err)
	}
	polled(t, p, "mallory's lift", pause.Unknown, pause.CauseUnauthenticated)
	writeTestFile(t, file, older)
	polled(t, p, "serial 1 replayed", pause.Unknown, pause.CauseBelowFloor)
	if err := p.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := buildOneAccount(t, tr); !errors.Is(err, pause.ErrNotServable) || !strings.Contains(err.Error(), string(pause.CauseBelowFloor)) {
		t.Errorf("a restart over serial 1 replayed = %v", err)
	}
}

// polled polls p's pause file and fails unless it reads as state with cause.
func polled(t *testing.T, p *plane, what string, state pause.State, cause pause.Cause) {
	t.Helper()
	if s := p.poller.Poll(); s.State() != state || s.Cause() != cause {
		t.Errorf("%s polled = %s, %q: %s; want %s, %q", what, s.State(), s.Cause(), s.Detail(), state, cause)
	}
}

// TestDoctorJudgesASignedPauseAsThePlaneWould: the signer's key, its grant
// and the scope, refused as the authenticator and the authorizer refuse.
func TestDoctorJudgesASignedPauseAsThePlaneWould(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	entry := func(name, level string) map[string]any {
		return map[string]any{
			"keyId": policykey.KeyID(signedTestPublic(name)), "alg": "ed25519", "role": "operator", "subject": name,
			"publicKey": policykey.FormatPublic(signedTestPublic(name)),
			"grants":    []any{map[string]any{"tenant": "acme", "project": "orders", "level": level}},
		}
	}
	body, err := canon.Canonicalize(map[string]any{
		"kind": trust.DocumentKind, "rosterId": "roster-a", "serial": 1,
		"issuedAt": now.Add(-time.Hour).Format(time.RFC3339), "expiresAt": now.Add(time.Hour).Format(time.RFC3339),
		"keys": []any{entry("alice", "operate"), entry("bob", "read")},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(trust.PayloadType, body, signedTestKey("root"))
	if err != nil {
		t.Fatal(err)
	}
	roster, err := trust.VerifyDocument(trust.Envelope{PayloadType: trust.PayloadType, Payload: body,
		Signatures: []trust.Signature{{KeyID: policykey.KeyID(signedTestPublic("root")), Signature: sig}}}, signedTestPublic("root"))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "pause.json")
	bound, err := pause.BindingOf(file)
	if err != nil {
		t.Fatal(err)
	}
	signedBy := func(signer, as, project, boundTo string) pause.Signed {
		h := pause.Header{KeyID: policykey.KeyID(signedTestPublic(as)), Tenant: "acme", Project: project, File: boundTo, Serial: 1}
		body, err := pause.MarshalSigned(h, pause.Document{})
		if err != nil {
			t.Fatal(err)
		}
		sig, err := bundle.SignBytesAs(operators.PausePayloadType, body, signedTestKey(signer))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := pause.ParseSigned(body)
		if err != nil {
			t.Fatal(err)
		}
		return pause.Signed{Body: parsed, Envelope: policy.StatementEnvelope{PayloadType: operators.PausePayloadType, Payload: body,
			Signatures: []policy.StatementSignature{{KeyID: h.KeyID, Signature: sig}}}}
	}
	if subject, err := pauseSigner(roster, signedBy("alice", "alice", "orders", bound), "acme", "orders", file); err != nil || subject != "alice" {
		t.Fatalf("alice's pause = %q, %v", subject, err)
	}
	for _, c := range []struct {
		name, signer, as, project, file string
		want                            pause.Error
	}{
		{"a pause of another project", "alice", "alice", "other", bound, pause.ErrOtherScope},
		{"a pause of another plane's file", "alice", "alice", "orders", "/srv/other/pause.json", pause.ErrOtherFile},
		{"mallory under alice's key id", "mallory", "alice", "orders", bound, pause.ErrUnauthenticated},
		{"a key the roster does not name", "mallory", "mallory", "orders", bound, pause.ErrUnauthenticated},
		{"bob, who only reads orders", "bob", "bob", "orders", bound, pause.ErrUnauthorized},
	} {
		if _, err := pauseSigner(roster, signedBy(c.signer, c.as, c.project, c.file), "acme", "orders", file); !errors.Is(err, c.want) {
			t.Errorf("%s = %v, want %v", c.name, err, c.want)
		}
	}
}

// TestTheHealthPageNamesThePausesSerialAndFloorOnly: GET /healthz's member
// carries the serial and the floor and no operator's name or key, which only
// health.socket's whole answer gives, and is left out where no signed
// document stands behind the state.
func TestTheHealthPageNamesThePausesSerialAndFloorOnly(t *testing.T) {
	whole := healthAnswer{Pause: pauseAnswer{UnlistedOnly: []string{}, Signed: signedAnswer(pause.SignedBy{Subject: "alice", KeyID: "ed25519:ab", Serial: 3, Floor: 3}, true)}}
	raw, err := json.Marshal(whole.counted())
	if err != nil {
		t.Fatal(err)
	}
	if want := `"signed":{"serial":3,"floor":3}`; !strings.Contains(string(raw), want) || strings.Contains(string(raw), "alice") || strings.Contains(string(raw), "ed25519:ab") {
		t.Errorf("the counted answer = %s, want %s", raw, want)
	}
	if raw, err = json.Marshal(whole); err != nil {
		t.Fatal(err)
	}
	if want := `"signed":{"subject":"alice","key_id":"ed25519:ab","serial":3,"floor":3}`; !strings.Contains(string(raw), want) {
		t.Errorf("the whole answer = %s, want %s", raw, want)
	}
	if whole.Pause.Signed.Subject != "alice" {
		t.Error("counted changed the whole answer's pause member")
	}
	if raw, _ := json.Marshal(pauseAnswer{Signed: signedAnswer(pause.SignedBy{Subject: "alice"}, false)}); strings.Contains(string(raw), "signed") {
		t.Errorf("an unsigned state's answer = %s", raw)
	}
}
