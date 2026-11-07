package reaction_test

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/reaction"
)

// rosterVoucher answers as operator ports over a roster that can change
// between polls: alice signs the route and the header, bob the lift, and a
// key it revoked, or ports that are down, answer as the ports would.
type rosterVoucher struct {
	keys    map[string]operator
	revoked map[string]bool
	down    bool
	asked   int
}

type operator struct {
	subject string
	pub     ed25519.PublicKey
}

func newRosterVoucher() *rosterVoucher {
	return &rosterVoucher{revoked: map[string]bool{}, keys: map[string]operator{
		keyIDOf(operatorKey()): {"alice", pubOf(operatorKey())},
		keyIDOf(strangerKey()): {"bob", pubOf(strangerKey())},
	}}
}

func (v *rosterVoucher) Plane() reaction.Plane {
	return reaction.Plane{Tenant: sTenant, Project: sProject, RouteFile: sRouteFile, ListFile: sListFile}
}

func (v *rosterVoucher) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	v.asked++
	if v.down {
		return reaction.Signer{}, fmt.Errorf("%w: the roster cannot be read", reaction.ErrUnanswered)
	}
	payloadType := map[reaction.SignedKind]string{
		reaction.VouchRoute: reaction.SignedRoutePayloadType, reaction.VouchHeader: reaction.SignedHeaderPayloadType,
		reaction.VouchLift: reaction.SignedLiftPayloadType,
	}[kind]
	id := env.Signatures[0].KeyID
	k, ok := v.keys[id]
	if !ok || v.revoked[id] {
		return reaction.Signer{}, errUnknown
	}
	if err := bundle.VerifyBytesAs(payloadType, env.Payload, env.Signatures[0].Signature, id, bundle.Keyring{id: k.pub}); err != nil {
		return reaction.Signer{}, err
	}
	return reaction.Signer{Subject: k.subject, KeyID: id}, nil
}

// liftedByBob is a signed list alice's header opens, holding a stop of
// run-1 that bob's lift ends, judged and Clear under v.
func liftedByBob(t *testing.T, v *rosterVoucher) (reaction.Route, []byte, reaction.Snapshot) {
	t.Helper()
	r := vouchedRoute(t, v)
	header, head := signedHeaderLine(t, r, headerOpts{})
	content := joinLines(header, signedStop(t, sProject), liftLineAs(t, head, sProject, strangerKey(), "run-1", 2))
	s := reaction.Snapshot{}.Next(r, content, sNow, time.Second)
	if s.State() != reaction.Clear || len(s.Entries()) != 0 {
		t.Fatalf("the lifted list: %v %q %s", s.State(), s.Cause(), s.Detail())
	}
	return r, content, s
}

func expectUnknown(t *testing.T, what string, s reaction.Snapshot, cause reaction.Cause) {
	t.Helper()
	if s.State() != reaction.Unknown || s.Cause() != cause {
		t.Errorf("%s: %v %q (%s), want unknown with %q", what, s.State(), s.Cause(), s.Detail(), cause)
	}
	if st, _ := s.ForCall("run-1", sTenant, sNow.Add(2*time.Second), time.Time{}); st != reaction.Unknown {
		t.Errorf("%s: a call of the stopped run is %v", what, st)
	}
}

// TestARosterThatRevokesALiftsSignerTakesTheClearAway: a stop and bob's
// lift accepted, a roster that revokes bob and keeps alice makes the next
// poll of the same list, and of the list grown by a covered line, unknown;
// a roster that names bob again makes it Clear again.
func TestARosterThatRevokesALiftsSignerTakesTheClearAway(t *testing.T) {
	v := newRosterVoucher()
	r, content, s := liftedByBob(t, v)
	v.revoked[keyIDOf(strangerKey())] = true
	expectUnknown(t, "the same list after bob is revoked", s.Next(r, content, sNow.Add(time.Second), time.Second), reaction.CauseLift)
	covered, err := reaction.Covered{FindingID: "f-2", TenantID: sTenant, RunID: "run-1", ProjectID: sProject, CreatedAt: sCreated}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	grown := append(append([]byte{}, content...), joinLines(covered)...)
	expectUnknown(t, "the grown list after bob is revoked", s.Next(r, grown, sNow.Add(time.Second), time.Second), reaction.CauseLift)
	delete(v.revoked, keyIDOf(strangerKey()))
	if again := s.Next(r, content, sNow.Add(time.Second), time.Second); again.State() != reaction.Clear {
		t.Errorf("the same list once bob is named again: %v %q %s", again.State(), again.Cause(), again.Detail())
	}
}

// TestARosterThatRevokesTheHeadersSignerTakesTheClearAway: bob's header
// under alice's route and lift, bob revoked after the list was accepted,
// makes the next poll unknown.
func TestARosterThatRevokesTheHeadersSignerTakesTheClearAway(t *testing.T) {
	v := newRosterVoucher()
	r := vouchedRoute(t, v)
	header, head := signedHeaderLine(t, r, headerOpts{key: strangerKey()})
	content := joinLines(header, signedStop(t, sProject), liftOf(t, head, operatorKey(), 2))
	s := reaction.Snapshot{}.Next(r, content, sNow, time.Second)
	if s.State() != reaction.Clear {
		t.Fatalf("the list: %v %q %s", s.State(), s.Cause(), s.Detail())
	}
	v.revoked[keyIDOf(strangerKey())] = true
	expectUnknown(t, "the same list after bob is revoked", s.Next(r, content, sNow.Add(time.Second), time.Second), reaction.CauseUnsigned)
}

// TestPortsThatStopAnsweringAfterAcceptanceTakeTheClearAway: ports that
// cannot answer at a later poll make it unknown with their own cause.
func TestPortsThatStopAnsweringAfterAcceptanceTakeTheClearAway(t *testing.T) {
	v := newRosterVoucher()
	r, content, s := liftedByBob(t, v)
	v.down = true
	expectUnknown(t, "the same list while the ports are down", s.Next(r, content, sNow.Add(time.Second), time.Second), reaction.CauseUnanswered)
}

// liftOf is a lift of run-1 through line through naming head, signed by key.
func liftOf(t *testing.T, head string, key ed25519.PrivateKey, through int64) []byte {
	t.Helper()
	body, err := reaction.SignedLift{KeyID: keyIDOf(key), ListHead: head, RunID: "run-1", ThroughLine: through,
		TenantID: sTenant, Project: sProject, File: sListFile}.Payload()
	if err != nil {
		t.Fatal(err)
	}
	line, err := reaction.LiftLine{RunID: "run-1", ThroughLine: through,
		Envelope: envelopeOf(t, reaction.SignedLiftPayloadType, body, key, keyIDOf(key))}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// TestAPollAsksAgainAboutEachSignerOnce: a list whose lifts alice signed
// once and bob twice is asked about again once for its route, once for its
// header and once for each lift's signer; bob revoked, or named under another subject, behind
// alice's earlier lift, makes the poll unknown.
func TestAPollAsksAgainAboutEachSignerOnce(t *testing.T) {
	v := newRosterVoucher()
	r := vouchedRoute(t, v)
	header, head := signedHeaderLine(t, r, headerOpts{})
	content := joinLines(header, signedStop(t, sProject), liftOf(t, head, operatorKey(), 2),
		signedStopOf(t, sProject, "f-2"), liftOf(t, head, strangerKey(), 4),
		signedStopOf(t, sProject, "f-3"), liftOf(t, head, strangerKey(), 6))
	s := reaction.Snapshot{}.Next(r, content, sNow, time.Second)
	if s.State() != reaction.Clear {
		t.Fatalf("the list: %v %q %s", s.State(), s.Cause(), s.Detail())
	}
	v.asked = 0
	if again := s.Next(r, content, sNow.Add(time.Second), time.Second); again.State() != reaction.Clear || v.asked != 4 {
		t.Errorf("the same list again: %v %q, the voucher asked %d times, want clear after 4", again.State(), again.Cause(), v.asked)
	}
	bob := keyIDOf(strangerKey())
	v.revoked[bob] = true
	expectUnknown(t, "bob revoked behind alice's lift", s.Next(r, content, sNow.Add(time.Second), time.Second), reaction.CauseLift)
	delete(v.revoked, bob)
	v.keys[bob] = operator{"mallory", pubOf(strangerKey())}
	expectUnknown(t, "bob's key named for mallory", s.Next(r, content, sNow.Add(time.Second), time.Second), reaction.CauseLift)
}
