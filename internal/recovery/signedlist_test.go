package recovery_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/recovery"
	"github.com/guardana/control/internal/runs"
)

var operatorKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6f}, ed25519.SeedSize))

func operatorID() string { return policykey.KeyID(operatorKey.Public().(ed25519.PublicKey)) }

// operatorVoucher takes any signature of operatorKey under the payload type
// of the kind asked about, for one plane.
type operatorVoucher struct{ plane reaction.Plane }

func (v operatorVoucher) Plane() reaction.Plane { return v.plane }

func (v operatorVoucher) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	types := map[reaction.SignedKind]string{
		reaction.VouchRoute: reaction.SignedRoutePayloadType, reaction.VouchHeader: reaction.SignedHeaderPayloadType,
		reaction.VouchLift: reaction.SignedLiftPayloadType,
	}
	sig := env.Signatures[0]
	keys := bundle.Keyring{operatorID(): operatorKey.Public().(ed25519.PublicKey)}
	if err := bundle.VerifyBytesAs(types[kind], env.Payload, sig.Signature, sig.KeyID, keys); err != nil {
		return reaction.Signer{}, err
	}
	return reaction.Signer{Subject: "alice", KeyID: operatorID()}, nil
}

// signedLists is a signed plane's v1alpha2 route, taken for its list file,
// the route a carry judges the old list against, and the plane's stop list
// floor.
type signedLists struct {
	p         *plane
	route     reaction.Route
	fromRoute reaction.Route
	floor     signedstops.Floor
}

func newSignedLists(t *testing.T, p *plane) signedLists {
	t.Helper()
	doc := `{"kind":"reaction-route/v1alpha2","route_id":"refunds","serial":1,"tenant_id":"acme","project_id":"orders",` +
		`"rules":[{"procedure_id":"refund","version":"1","digest":"` + route(t).Rules()[0].ProcedureDigest +
		`","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run","expires_seconds":3600}]}`
	body, err := reaction.SignedRouteBody([]byte(doc), operatorID(), p.path("route/route.json"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(reaction.SignedRoutePayloadType, body, operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	env := reaction.Envelope{PayloadType: reaction.SignedRoutePayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: operatorID(), Signature: sig}}}
	v := operatorVoucher{plane: reaction.Plane{Tenant: "acme", Project: "orders", RouteFile: p.path("route/route.json"),
		ListFile: p.path("stops/" + stoplist.FileName)}}
	s := signedLists{p: p}
	if s.route, err = reaction.VerifySignedRoute(env, v); err != nil {
		t.Fatalf("VerifySignedRoute: %v", err)
	}
	if s.fromRoute, err = reaction.VerifySignedCarrySource(env, v); err != nil {
		t.Fatalf("VerifySignedCarrySource: %v", err)
	}
	if s.floor, err = signedstops.NewFloor(p.path("stopsfloor"), "acme", "orders"); err != nil {
		t.Fatal(err)
	}
	return s
}

func operatorSigner() stopwrite.Signer {
	return stopwrite.Signer{KeyID: operatorID(), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, operatorKey)
	}}
}

// judged is the plane's list in dir as the plane judges it, and its bytes.
func (s signedLists) judged(t *testing.T, dir string) (reaction.List, []byte) {
	t.Helper()
	raw, err := stoplist.Read(s.p.path(dir))
	if err != nil {
		t.Fatal(err)
	}
	l, err := reaction.Judge(s.route, reaction.Prefix{}, raw, t0, 0)
	if err != nil {
		t.Fatalf("Judge %s: %v", dir, err)
	}
	return l, raw
}

// take is the plane taking its list in dir into its stop list floor f.
func (s signedLists) take(t *testing.T, f signedstops.Floor, dir string) error {
	t.Helper()
	l, raw := s.judged(t, dir)
	_, err := f.Take(t.Context(), l, raw)
	return err
}

func (s signedLists) addStop(t *testing.T, finding, run string) {
	t.Helper()
	rule := s.route.Rules()[0]
	stopAt := func(now time.Time) (reaction.Stop, error) {
		return reaction.Stop{EntryID: reaction.EntryID(finding), TenantID: "acme", ProjectID: "orders", Scope: reaction.ScopeRun,
			RunID: run, FindingID: finding, ProcedureID: rule.ProcedureID, ProcedureVersion: rule.ProcedureVersion,
			ProcedureDigest: rule.ProcedureDigest, RuleID: rule.RuleID, RuleVersion: rule.RuleVersion,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, nil
	}
	if _, _, _, err := stopwrite.AppendFinding(t.Context(), s.p.path("stops"), s.route, func() time.Time { return t0 }, stopAt); err != nil {
		t.Fatalf("a stop of %s: %v", run, err)
	}
}

// lift is an operator's lift of run through line, signed for the list whose
// head is head.
func (s signedLists) lift(t *testing.T, head, run string, through int64) reaction.LiftLine {
	t.Helper()
	body, err := reaction.SignedLift{KeyID: operatorID(), ListHead: head, RunID: run, ThroughLine: through, TenantID: "acme",
		Project: "orders", File: s.p.path("stops/" + stoplist.FileName)}.Payload()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(reaction.SignedLiftPayloadType, body, operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	return reaction.LiftLine{RunID: run, ThroughLine: through, Envelope: reaction.Envelope{PayloadType: reaction.SignedLiftPayloadType,
		Payload: body, Signatures: []reaction.Signature{{KeyID: operatorID(), Signature: sig}}}}
}

// carry moves the plane's list to kept and carries it into the plane's list
// file under the next serial, as an operator does.
func (s signedLists) carry(t *testing.T, kept string) {
	t.Helper()
	if err := os.Rename(s.p.path("stops"), s.p.path(kept)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.p.path("stops"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := stopwrite.CarrySigned(t.Context(), s.p.path(kept), s.fromRoute, s.p.path("stops"), s.route, t0, operatorSigner(), nil); err != nil {
		t.Fatalf("CarrySigned: %v", err)
	}
}

// signedListPlane is a signed plane whose list, serial 1, stops run-a and
// run-b, backed up. After the backup the list is carried to serial 2, which
// takes a stop of run-c and a lift of run-a, and to serial 3; the plane took
// each. old is a lift of run-b bound to the first list's head, and list1 the
// first list's bytes.
func signedListPlane(t *testing.T) (s signedLists, dir string, old reaction.LiftLine, list1 []byte) {
	t.Helper()
	p, dir, _ := signedPlaneOf(t, signedBlock+signedStopsBlock, func(p *plane, _ runs.Record) {
		p.setStopsFloor(t, policystate.StopsFloor{})
		if err := os.Mkdir(p.path("stops"), 0o700); err != nil {
			t.Fatal(err)
		}
		s = newSignedLists(t, p)
		if _, err := stopwrite.InitSigned(t.Context(), p.path("stops"), s.route, t0, operatorSigner(), 1); err != nil {
			t.Fatalf("InitSigned: %v", err)
		}
		s.addStop(t, "f-a", "run-a")
		s.addStop(t, "f-b", "run-b")
		if err := s.take(t, s.floor, "stops"); err != nil {
			t.Fatalf("the plane took the first list: %v", err)
		}
	})
	first, list1 := s.judged(t, "stops")
	old = s.lift(t, first.Header().Signed.Digest, "run-b", 3)
	if _, _, err := reaction.VerifySignedLiftLine(old, first.Header(), s.route); err != nil {
		t.Fatalf("the old lift in its own list: %v", err)
	}
	s.carry(t, "stops-1")
	s.addStop(t, "f-c", "run-c")
	second, _ := s.judged(t, "stops")
	if _, err := stopwrite.AppendLift(t.Context(), p.path("stops"), s.route, s.lift(t, second.Header().Signed.Digest, "run-a", 2), t0); err != nil {
		t.Fatalf("a lift in the second list: %v", err)
	}
	if err := s.take(t, s.floor, "stops"); err != nil {
		t.Fatalf("the plane took the second list: %v", err)
	}
	s.carry(t, "stops-2")
	if err := s.take(t, s.floor, "stops"); err != nil {
		t.Fatalf("the plane took the third list: %v", err)
	}
	return s, dir, old, list1
}

// requireStopsFloor holds the plane's stop list floor at the serial and head
// of the list in dir.
func (s signedLists) requireStopsFloor(t *testing.T, what string, serial int64, dir string) {
	t.Helper()
	l, _ := s.judged(t, dir)
	if f := s.p.stopsFloor(t); f.Serial != serial || f.Digest != l.Header().Signed.Digest {
		t.Fatalf("%s: stop list floor = %+v, want serial %d and the head of %s", what, f, serial, dir)
	}
}

// TestSignedRestoreWithSignedListsAndLifts: after the backup the list was
// carried twice, took a stop and a lift, and the state was lost. A stop list
// floor that survived is not lowered to the backup's, which then refuses the
// backup's copy of the list; the lift bound to the first list's head
// verifies against no later list.
func TestSignedRestoreWithSignedListsAndLifts(t *testing.T) {
	s, dir, old, list1 := signedListPlane(t)
	for _, lost := range []string{"floors", "pausefloor", "trust/floors"} {
		if err := os.RemoveAll(s.p.path(lost)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := recovery.Restore(t.Context(), s.p.cfg, dir, restoreAt); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	s.requireStopsFloor(t, "after the restore", 3, "stops")
	if err := s.take(t, s.floor, "stops"); err != nil {
		t.Fatalf("the newest list after the restore: %v", err)
	}
	third, _ := s.judged(t, "stops")
	if _, _, err := reaction.VerifySignedLiftLine(old, third.Header(), s.route); !errors.Is(err, reaction.ErrSignedLiftMismatch) {
		t.Fatalf("the old lift against the newest list: %v, want ErrSignedLiftMismatch", err)
	}
	if _, err := stopwrite.AppendLift(t.Context(), s.p.path("stops"), s.route, old, restoreAt); !errors.Is(err, stopwrite.ErrRefused) {
		t.Fatalf("the old lift appended to the newest list: %v, want ErrRefused", err)
	}
	first, err := reaction.Judge(s.route, reaction.Prefix{}, list1, t0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.floor.Take(t.Context(), first, list1); !errors.Is(err, stoplist.ErrBelowFloor) {
		t.Fatalf("the backup's list put back: %v, want ErrBelowFloor", err)
	}
	s.requireStopsFloor(t, "after the refusals", 3, "stops")
}

// TestSignedRestoreOfALostStopListFloor: with the stop list floor lost, the
// restore puts back the backup's, at the first list's serial and head. A
// list two serials above it names a head the floor never held and is
// refused. Two ways back reach the newest list: the plane takes each list of
// the chain in serial order, or a floor directory `stops floor init` makes
// anew takes it.
func TestSignedRestoreOfALostStopListFloor(t *testing.T) {
	s, dir, old, _ := signedListPlane(t)
	for _, lost := range []string{"floors", "stopsfloor"} {
		if err := os.RemoveAll(s.p.path(lost)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := recovery.Restore(t.Context(), s.p.cfg, dir, restoreAt); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	s.requireStopsFloor(t, "after the restore", 1, "stops-1")
	if err := s.take(t, s.floor, "stops"); !errors.Is(err, stoplist.ErrChain) {
		t.Fatalf("the newest list over the backup's floor: %v, want ErrChain", err)
	}

	if err := policystate.InitStops(t.Context(), s.p.path("stopsfloor-new"), "acme", "orders"); err != nil {
		t.Fatal(err)
	}
	fresh, err := signedstops.NewFloor(s.p.path("stopsfloor-new"), "acme", "orders")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.take(t, fresh, "stops"); err != nil {
		t.Fatalf("the newest list into a new floor directory: %v", err)
	}

	if err := s.take(t, s.floor, "stops-2"); err != nil {
		t.Fatalf("the second list over the backup's floor: %v", err)
	}
	if err := s.take(t, s.floor, "stops"); err != nil {
		t.Fatalf("the newest list after the second: %v", err)
	}
	s.requireStopsFloor(t, "along the chain", 3, "stops")
	third, _ := s.judged(t, "stops")
	if _, _, err := reaction.VerifySignedLiftLine(old, third.Header(), s.route); !errors.Is(err, reaction.ErrSignedLiftMismatch) {
		t.Fatalf("the old lift against the newest list: %v, want ErrSignedLiftMismatch", err)
	}
}
