package stopwrite_test

import (
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// strangerKey is a key the voucher does not take.
func strangerKey() ed25519.PrivateKey { return seededKey(0x73) }

func envelopeBy(t *testing.T, key ed25519.PrivateKey, payloadType string, body []byte) reaction.Envelope {
	t.Helper()
	id := policykey.KeyID(key.Public().(ed25519.PublicKey))
	sig, err := bundle.SignBytesAs(payloadType, body, key)
	if err != nil {
		t.Fatal(err)
	}
	return reaction.Envelope{PayloadType: payloadType, Payload: body, Signatures: []reaction.Signature{{KeyID: id, Signature: sig}}}
}

// appendRaw appends line to the list in dir as a writer of the directory
// can, past every check of the writer.
func appendRaw(t *testing.T, dir string, line []byte) {
	t.Helper()
	f, err := os.OpenFile(listPath(dir), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestACarryJudgesTheOldListsHeaderAndLiftsAsThePlaneDoes: a list whose
// header the voucher does not take is not carried, and a lift it does not
// take is left out with the line after the last stop, so the stop it would
// end is carried.
func TestACarryJudgesTheOldListsHeaderAndLiftsAsThePlaneDoes(t *testing.T) {
	strangerID := policykey.KeyID(strangerKey().Public().(ed25519.PublicKey))
	forged := emptyDir(t)
	r := signedRouteIn(t, forged, 3)
	body, err := reaction.HeaderBody(reaction.Header{ListID: "lst-forged", RouteID: r.ID(), RouteSerial: r.Serial(), RouteDigest: r.Digest(),
		Signed: reaction.HeaderSigned{KeyID: strangerID, TenantID: "acme", ProjectID: "shop", File: listPath(forged), Serial: 1}})
	if err != nil {
		t.Fatal(err)
	}
	line, err := reaction.SignedHeaderLine(envelopeBy(t, strangerKey(), reaction.SignedHeaderPayloadType, body))
	if err != nil {
		t.Fatal(err)
	}
	appendRaw(t, forged, line)
	into := emptyDir(t)
	if _, err := stopwrite.CarrySigned(bg, forged, r, into, signedRouteIn(t, into, 4), clock0, signer(), nil); !errors.Is(err, stopwrite.ErrRefused) ||
		!errors.Is(err, reaction.ErrHeaderUnsigned) {
		t.Fatalf("a carry of a header the voucher does not take: %v", err)
	}
	expectForgedLiftLeftOut(t, strangerID)

}

// expectForgedLiftLeftOut carries a list whose stop a lift signed by
// strangerID would end, and expects the stop kept and the lift left out.
func expectForgedLiftLeftOut(t *testing.T, strangerID string) {
	t.Helper()
	from := emptyDir(t)
	fromRoute := signedRouteIn(t, from, 3)
	h, err := stopwrite.InitSigned(bg, from, fromRoute, clock0, signer(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := appendFinding(bg, from, fromRoute, signedStop(t, "f-1", "run-1", "shop", clock0), clock0); err != nil {
		t.Fatal(err)
	}
	lift := reaction.SignedLift{KeyID: strangerID, ListHead: h.Signed.Digest, RunID: "run-1", ThroughLine: 2,
		TenantID: "acme", Project: "shop", File: listPath(from)}
	liftBody, err := lift.Payload()
	if err != nil {
		t.Fatal(err)
	}
	liftLine, err := reaction.LiftLine{RunID: "run-1", ThroughLine: 2, Envelope: envelopeBy(t, strangerKey(), reaction.SignedLiftPayloadType, liftBody)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	appendRaw(t, from, liftLine)
	into := emptyDir(t)
	c, err := stopwrite.CarrySigned(bg, from, fromRoute, into, signedRouteIn(t, into, 4), clock0, signer(), nil)
	if err != nil {
		t.Fatalf("a carry of a list with a lift the voucher does not take: %v", err)
	}
	if c.Stops != 1 || c.LeftOut != 1 || !errors.Is(c.Refused, reaction.ErrSignedLiftUnvouched) {
		t.Fatalf("carried %d stops, left out %d lines for %v; want the stop kept and the lift left out", c.Stops, c.LeftOut, c.Refused)
	}
}
