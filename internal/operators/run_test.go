package operators_test

import (
	"testing"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/operators"
)

// runStatement is a run record body signed by the key called signer
// under the run record payload type.
func runStatement(t *testing.T, signer string) operators.Envelope {
	t.Helper()
	body, err := canon.Canonicalize(map[string]any{"alg": "ed25519", "keyId": idOf(signer), "schema_version": "3.0"})
	if err != nil {
		t.Fatal(err)
	}
	return sign(t, operators.RunPayloadType, body, signer, idOf(signer))
}

// TestTheRunActTakesOnlyItsOwnPayloadType: an approval answer or a pause is
// no run record and a run record is neither, whoever signed it.
func TestTheRunActTakesOnlyItsOwnPayloadType(t *testing.T) {
	w := newWorld(t, standard())
	a := authenticator(t, w.roster, operators.Bounds{})
	got := a.Authenticate(t.Context(), operators.ActRun, runStatement(t, "alice"))
	if got.State() != operators.AuthAuthenticated || got.Act() != operators.ActRun || got.Subject() != "alice" {
		t.Fatalf("alice's run = state %d cause %q act %q", got.State(), got.Cause(), got.Act())
	}
	wantAuth(t, "an approval answer offered as a run record", a.Authenticate(t.Context(), operators.ActRun, answer(t, "alice")), operators.AuthRefused, operators.CausePayloadType)
	wantAuth(t, "a pause offered as a run record", a.Authenticate(t.Context(), operators.ActRun, pauseStatement(t, "alice")), operators.AuthRefused, operators.CausePayloadType)
	wantAuth(t, "a run record offered as a pause", a.Authenticate(t.Context(), operators.ActPause, runStatement(t, "alice")), operators.AuthRefused, operators.CausePayloadType)
	wantAuth(t, "a run record offered as an approval answer", a.Authenticate(t.Context(), operators.ActApprove, runStatement(t, "alice")), operators.AuthRefused, operators.CausePayloadType)
	relabelled := runStatement(t, "alice")
	relabelled.PayloadType = operators.AnswerPayloadType
	wantAuth(t, "a run record relabelled as an answer", a.Authenticate(t.Context(), operators.ActApprove, relabelled), operators.AuthRefused, operators.CauseSignature)
}

// TestTheRunActNeedsOperateOverTheProject: a reader may not open or close a
// run, and an authentication for one act permits no other.
func TestTheRunActNeedsOperateOverTheProject(t *testing.T) {
	w := newWorld(t, standard())
	a, z := authenticator(t, w.roster, operators.Bounds{}), authorizer(t, w.roster, operators.Bounds{})
	runOn := func(project string) operators.Request {
		return operators.Request{Act: operators.ActRun, Tenant: "t1", Project: project}
	}
	alice := a.Authenticate(t.Context(), operators.ActRun, runStatement(t, "alice"))
	bob := a.Authenticate(t.Context(), operators.ActRun, runStatement(t, "bob"))
	wantPerm(t, "alice opening a run in A", z.Authorize(t.Context(), alice, runOn("A")), operators.PermPermitted, operators.CauseNone)
	wantPerm(t, "bob, who reads A, opening a run in A", z.Authorize(t.Context(), bob, runOn("A")), operators.PermDenied, operators.CauseNoGrant)
	wantPerm(t, "alice opening a run in B", z.Authorize(t.Context(), alice, runOn("B")), operators.PermDenied, operators.CauseNoGrant)
	wantPerm(t, "alice's answer used to open a run", z.Authorize(t.Context(), authenticated(t, w, "alice"), runOn("A")), operators.PermDenied, operators.CauseAct)
	wantPerm(t, "alice's run used to approve", z.Authorize(t.Context(), alice, approve("t1", "A")), operators.PermDenied, operators.CauseAct)
}
