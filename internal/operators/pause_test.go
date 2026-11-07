package operators_test

import (
	"testing"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/operators"
)

// pauseStatement is a pause document body signed by the key called signer
// under the pause payload type.
func pauseStatement(t *testing.T, signer string) operators.Envelope {
	t.Helper()
	body, err := canon.Canonicalize(map[string]any{"alg": "ed25519", "keyId": idOf(signer), "schema_version": "3"})
	if err != nil {
		t.Fatal(err)
	}
	return sign(t, operators.PausePayloadType, body, signer, idOf(signer))
}

// TestThePauseActTakesOnlyItsOwnPayloadType: an approval answer is no pause
// and a pause is no approval answer, whoever signed either.
func TestThePauseActTakesOnlyItsOwnPayloadType(t *testing.T) {
	w := newWorld(t, standard())
	a := authenticator(t, w.roster, operators.Bounds{})
	got := a.Authenticate(t.Context(), operators.ActPause, pauseStatement(t, "alice"))
	if got.State() != operators.AuthAuthenticated || got.Act() != operators.ActPause || got.Subject() != "alice" {
		t.Fatalf("alice's pause = state %d cause %q act %q", got.State(), got.Cause(), got.Act())
	}
	wantAuth(t, "an approval answer offered as a pause", a.Authenticate(t.Context(), operators.ActPause, answer(t, "alice")), operators.AuthRefused, operators.CausePayloadType)
	wantAuth(t, "a pause offered as an approval answer", a.Authenticate(t.Context(), operators.ActApprove, pauseStatement(t, "alice")), operators.AuthRefused, operators.CausePayloadType)
	relabelled := pauseStatement(t, "alice")
	relabelled.PayloadType = operators.AnswerPayloadType
	wantAuth(t, "a pause relabelled as an answer", a.Authenticate(t.Context(), operators.ActApprove, relabelled), operators.AuthRefused, operators.CauseSignature)
}

// TestThePauseActNeedsOperateOverTheProject: a reader may not pause, and an
// authentication for one act permits no other.
func TestThePauseActNeedsOperateOverTheProject(t *testing.T) {
	w := newWorld(t, standard())
	a, z := authenticator(t, w.roster, operators.Bounds{}), authorizer(t, w.roster, operators.Bounds{})
	pauseOn := func(project string) operators.Request {
		return operators.Request{Act: operators.ActPause, Tenant: "t1", Project: project}
	}
	alice := a.Authenticate(t.Context(), operators.ActPause, pauseStatement(t, "alice"))
	bob := a.Authenticate(t.Context(), operators.ActPause, pauseStatement(t, "bob"))
	wantPerm(t, "alice pausing A", z.Authorize(t.Context(), alice, pauseOn("A")), operators.PermPermitted, operators.CauseNone)
	wantPerm(t, "bob, who reads A, pausing A", z.Authorize(t.Context(), bob, pauseOn("A")), operators.PermDenied, operators.CauseNoGrant)
	wantPerm(t, "alice pausing B", z.Authorize(t.Context(), alice, pauseOn("B")), operators.PermDenied, operators.CauseNoGrant)
	wantPerm(t, "alice's answer used to pause", z.Authorize(t.Context(), authenticated(t, w, "alice"), pauseOn("A")), operators.PermDenied, operators.CauseAct)
	wantPerm(t, "alice's pause used to approve", z.Authorize(t.Context(), alice, approve("t1", "A")), operators.PermDenied, operators.CauseAct)
}
