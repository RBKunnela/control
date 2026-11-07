package operators_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/trust"
)

func wantAuth(t *testing.T, what string, got operators.Authentication, state operators.AuthState, cause operators.Cause) {
	t.Helper()
	if got.State() != state || got.Cause() != cause {
		t.Errorf("%s = state %d cause %q, want state %d cause %q", what, got.State(), got.Cause(), state, cause)
	}
	if state != operators.AuthAuthenticated && (got.Subject() != "" || got.Issuer() != "" || got.KeyID() != "" || got.Body() != nil) {
		t.Errorf("%s names %q %q %q though not authenticated", what, got.Issuer(), got.Subject(), got.KeyID())
	}
}

func TestAnOperatorsSignedAnswerIsAuthenticated(t *testing.T) {
	w := newWorld(t, standard())
	env := answer(t, "alice")
	got := authenticator(t, w.roster, operators.Bounds{}).Authenticate(t.Context(), operators.ActApprove, env)
	wantAuth(t, "alice's answer", got, operators.AuthAuthenticated, operators.CauseNone)
	if got.Issuer() != "roster/roster-a" || got.Subject() != "alice" || got.KeyID() != idOf("alice") || got.Act() != operators.ActApprove {
		t.Errorf("the authentication = %q %q %q %q", got.Issuer(), got.Subject(), got.KeyID(), got.Act())
	}
	if !bytes.Equal(got.Body(), env.Payload) {
		t.Errorf("the body = %s, want %s", got.Body(), env.Payload)
	}
}

// otherPayloadTypes is every other DSSE payload type a key of this project
// signs, spelled here rather than taken from the packages that own them.
var otherPayloadTypes = []string{
	"application/vnd.agent-policy+json",
	"application/vnd.agent-policy-freshness+json",
	"application/vnd.agent-reaction-route+json",
	"application/vnd.agent-reaction-lift+json",
	"application/vnd.agent-trust-roster+json",
}

func TestAnEnvelopeOfAnotherPayloadTypeIsNeverAnAnswer(t *testing.T) {
	w := newWorld(t, standard())
	a := authenticator(t, w.roster, operators.Bounds{})
	body := answer(t, "alice").Payload
	for _, other := range otherPayloadTypes {
		env := sign(t, other, body, "alice", idOf("alice"))
		wantAuth(t, "an envelope of "+other, a.Authenticate(t.Context(), operators.ActApprove, env), operators.AuthRefused, operators.CausePayloadType)
		env.PayloadType = operators.AnswerPayloadType
		wantAuth(t, "a signature over "+other+" relabelled", a.Authenticate(t.Context(), operators.ActApprove, env), operators.AuthRefused, operators.CauseSignature)
	}
	roster := sign(t, trust.PayloadType, rosterBody(t, 1, standard()), "root", idOf("root"))
	roster.PayloadType = operators.AnswerPayloadType
	wantAuth(t, "the roster itself relabelled as an answer", a.Authenticate(t.Context(), operators.ActApprove, roster), operators.AuthRefused, operators.CauseUnknownKey)
	if operators.AnswerPayloadType != "application/vnd.agent-approval-answer+json" {
		t.Errorf("AnswerPayloadType = %q", operators.AnswerPayloadType)
	}
}

func TestAStatementCannotChooseHowItIsVerified(t *testing.T) {
	w := newWorld(t, standard())
	a := authenticator(t, w.roster, operators.Bounds{})
	cases := []struct {
		name    string
		members map[string]any
		want    operators.Cause
	}{
		{"an algorithm other than the key's", map[string]any{"alg": "ecdsa-p256", "keyId": idOf("alice")}, operators.CauseAlg},
		{"an algorithm in another case", map[string]any{"alg": "Ed25519", "keyId": idOf("alice")}, operators.CauseAlg},
		{"no algorithm", map[string]any{"keyId": idOf("alice")}, operators.CauseAlg},
		{"an algorithm that is not a string", map[string]any{"alg": nil, "keyId": idOf("alice")}, operators.CauseAlg},
		{"another key's id in the body", map[string]any{"alg": "ed25519", "keyId": idOf("bob")}, operators.CauseKeyID},
		{"no key id in the body", map[string]any{"alg": "ed25519"}, operators.CauseKeyID},
	}
	for _, c := range cases {
		wantAuth(t, c.name, a.Authenticate(t.Context(), operators.ActApprove, answerWith(t, "alice", c.members)), operators.AuthRefused, c.want)
	}
	spaced := answer(t, "alice")
	body := append([]byte(" "), spaced.Payload...)
	wantAuth(t, "a body that is not its canonical form", a.Authenticate(t.Context(), operators.ActApprove, sign(t, operators.AnswerPayloadType, body, "alice", idOf("alice"))), operators.AuthRefused, operators.CauseBody)
	array := sign(t, operators.AnswerPayloadType, []byte(`["alg","ed25519"]`), "alice", idOf("alice"))
	wantAuth(t, "a body that is not an object", a.Authenticate(t.Context(), operators.ActApprove, array), operators.AuthRefused, operators.CauseBody)
}

func TestOnlyTheRostersKeyUnderItsOwnIDSignsAnAnswer(t *testing.T) {
	w := newWorld(t, standard())
	a := authenticator(t, w.roster, operators.Bounds{})
	forged := sign(t, operators.AnswerPayloadType, answer(t, "alice").Payload, "mallory", idOf("alice"))
	wantAuth(t, "another key's signature under alice's id", a.Authenticate(t.Context(), operators.ActApprove, forged), operators.AuthRefused, operators.CauseSignature)
	wantAuth(t, "a key the roster does not name", a.Authenticate(t.Context(), operators.ActApprove, answer(t, "mallory")), operators.AuthRefused, operators.CauseUnknownKey)
	wantAuth(t, "the root's own answer", a.Authenticate(t.Context(), operators.ActApprove, answer(t, "root")), operators.AuthRefused, operators.CauseUnknownKey)
	noID := answer(t, "alice")
	noID.Signatures[0].KeyID = ""
	wantAuth(t, "an empty key id", a.Authenticate(t.Context(), operators.ActApprove, noID), operators.AuthRefused, operators.CauseUnknownKey)
	twice := answer(t, "alice")
	twice.Signatures = append(twice.Signatures, twice.Signatures[0])
	wantAuth(t, "two signatures", a.Authenticate(t.Context(), operators.ActApprove, twice), operators.AuthRefused, operators.CauseSignatures)
	wantAuth(t, "an act this build lacks", a.Authenticate(t.Context(), "unknown", answer(t, "alice")), operators.AuthRefused, operators.CauseAct)
}

// swappingRoster answers every lookup with the key it names instead, as a
// roster port in error would.
type swappingRoster struct {
	trust.Roster
	instead string
}

func (s swappingRoster) Lookup(ctx context.Context, _ string) trust.Answer {
	return s.Roster.Lookup(ctx, s.instead)
}

func TestAKeyAnsweredUnderAnotherIDIsRefused(t *testing.T) {
	w := newWorld(t, standard())
	a := authenticator(t, swappingRoster{Roster: w.roster, instead: idOf("bob")}, operators.Bounds{})
	body := answerWith(t, "bob", map[string]any{"alg": "ed25519", "keyId": idOf("bob")}).Payload
	env := sign(t, operators.AnswerPayloadType, body, "bob", idOf("alice"))
	wantAuth(t, "bob's key answered for alice's id", a.Authenticate(t.Context(), operators.ActApprove, env), operators.AuthRefused, operators.CauseKeyID)
	control := sign(t, operators.AnswerPayloadType, body, "bob", idOf("bob"))
	wantAuth(t, "the control, bob's key under bob's id", a.Authenticate(t.Context(), operators.ActApprove, control), operators.AuthAuthenticated, operators.CauseNone)
}

func TestAStatementBodyIsBounded(t *testing.T) {
	w := newWorld(t, standard())
	a := authenticator(t, w.roster, operators.Bounds{})
	base := len(answerWith(t, "alice", map[string]any{"alg": "ed25519", "keyId": idOf("alice"), "pad": ""}).Payload)
	at := answerWith(t, "alice", map[string]any{"alg": "ed25519", "keyId": idOf("alice"), "pad": strings.Repeat("x", operators.MaxStatementBytes-base)})
	if len(at.Payload) != operators.MaxStatementBytes {
		t.Fatalf("the body at the bound is %d bytes", len(at.Payload))
	}
	wantAuth(t, "a body of MaxStatementBytes", a.Authenticate(t.Context(), operators.ActApprove, at), operators.AuthAuthenticated, operators.CauseNone)
	over := answerWith(t, "alice", map[string]any{"alg": "ed25519", "keyId": idOf("alice"), "pad": strings.Repeat("x", operators.MaxStatementBytes-base+1)})
	wantAuth(t, "a body a byte over", a.Authenticate(t.Context(), operators.ActApprove, over), operators.AuthRefused, operators.CauseTooLarge)
}

func TestAnAuthenticatorWithNoRosterAnswerIsUnavailable(t *testing.T) {
	quick := operators.Bounds{Timeout: 50 * time.Millisecond}
	cases := []struct {
		name   string
		roster *fakeRoster
		want   operators.Cause
	}{
		{"a roster that is unavailable", &fakeRoster{answer: trust.Unavailable(trust.CauseExpired)}, operators.CauseRosterUnavailable},
		{"a roster that answers the zero answer", &fakeRoster{}, operators.CauseRosterUnavailable},
		{"a roster that answers late", &fakeRoster{answer: trust.Unavailable(trust.CauseNone), release: make(chan struct{})}, operators.CauseLate},
		{"a roster that never answers", &fakeRoster{release: make(chan struct{}), deaf: true}, operators.CauseLate},
	}
	for _, c := range cases {
		a := authenticator(t, c.roster, quick)
		wantAuth(t, c.name, a.Authenticate(t.Context(), operators.ActApprove, answer(t, "alice")), operators.AuthUnavailable, c.want)
		if c.roster.release != nil {
			close(c.roster.release)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	w := newWorld(t, standard())
	wantAuth(t, "a cancelled call", authenticator(t, w.roster, quick).Authenticate(ctx, operators.ActApprove, answer(t, "alice")), operators.AuthUnavailable, operators.CauseCanceled)
	var zero operators.Authentication
	wantAuth(t, "the zero authentication", zero, operators.AuthUnavailable, operators.CauseNone)
}

func TestAnAuthenticatorHoldsItsCallsToItsBound(t *testing.T) {
	stuck := &fakeRoster{release: make(chan struct{}), deaf: true}
	defer close(stuck.release)
	a := authenticator(t, stuck, operators.Bounds{Timeout: 20 * time.Millisecond, InFlight: 1})
	wantAuth(t, "the first call", a.Authenticate(t.Context(), operators.ActApprove, answer(t, "alice")), operators.AuthUnavailable, operators.CauseLate)
	wantAuth(t, "a call while the first still holds its slot", a.Authenticate(t.Context(), operators.ActApprove, answer(t, "alice")), operators.AuthUnavailable, operators.CauseBusy)
	if s := a.Status(); s.Kind != "roster" || s.Counts[operators.CauseLate] != 1 || s.Counts[operators.CauseBusy] != 1 {
		t.Errorf("Status = %+v", s)
	}
}

func TestTheAuthenticatorsConfigurationIsChecked(t *testing.T) {
	w := newWorld(t, standard())
	cases := []struct {
		name   string
		kind   operators.AuthenticatorKind
		roster trust.Roster
		bounds operators.Bounds
		want   error
	}{
		{"an unknown kind", "api", w.roster, operators.Bounds{}, operators.ErrUnknownKind},
		{"no roster", "roster", nil, operators.Bounds{}, operators.ErrConfig},
		{"a timeout past MaxTimeout", "roster", w.roster, operators.Bounds{Timeout: operators.MaxTimeout + time.Second}, operators.ErrConfig},
		{"more calls than MaxInFlight", "roster", w.roster, operators.Bounds{InFlight: operators.MaxInFlight + 1}, operators.ErrConfig},
	}
	for _, c := range cases {
		if _, err := operators.NewAuthenticator(c.kind, c.roster, c.bounds); !errors.Is(err, c.want) {
			t.Errorf("%s = %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := operators.NewAuthenticator("roster", w.roster, operators.Bounds{Timeout: operators.MaxTimeout, InFlight: operators.MaxInFlight}); err != nil {
		t.Errorf("the bounds at their limits: %v", err)
	}
}
