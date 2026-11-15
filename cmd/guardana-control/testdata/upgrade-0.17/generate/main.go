// Command generate writes the 0.17 signed plane the upgrade test starts from.
// Run inside an export of v0.17.0: copy this directory to cmd/generate there
// and run `go run ./cmd/generate <empty dir>`, then copy the result here.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// The plane's files as its signed documents name them.
const (
	routeFile = "/srv/plane/route.json"
	listFile  = "/srv/plane/stops/" + stoplist.FileName
	digest    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var t0 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

func seeded(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

var dave, alice = seeded(0x44), seeded(0x41)

func keyID(k ed25519.PrivateKey) string { return policykey.KeyID(k.Public().(ed25519.PublicKey)) }

// voucher takes dave's and alice's signatures for the plane of acme/orders.
type voucher struct{}

func (voucher) Plane() reaction.Plane {
	return reaction.Plane{Tenant: "acme", Project: "orders", RouteFile: routeFile, ListFile: listFile}
}

func (voucher) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	types := map[reaction.SignedKind]string{reaction.VouchRoute: reaction.SignedRoutePayloadType,
		reaction.VouchHeader: reaction.SignedHeaderPayloadType, reaction.VouchLift: reaction.SignedLiftPayloadType}
	ring := bundle.Keyring{keyID(dave): dave.Public().(ed25519.PublicKey), keyID(alice): alice.Public().(ed25519.PublicKey)}
	sig := env.Signatures[0]
	if err := bundle.VerifyBytesAs(types[kind], env.Payload, sig.Signature, sig.KeyID, ring); err != nil {
		return reaction.Signer{}, err
	}
	return reaction.Signer{Subject: map[string]string{keyID(dave): "dave", keyID(alice): "alice"}[sig.KeyID], KeyID: sig.KeyID}, nil
}

func envelope(payloadType string, body []byte, k ed25519.PrivateKey) reaction.Envelope {
	sig, err := bundle.SignBytesAs(payloadType, body, k)
	must(err)
	return reaction.Envelope{PayloadType: payloadType, Payload: body, Signatures: []reaction.Signature{{KeyID: keyID(k), Signature: sig}}}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func stopOf(route reaction.Route, finding, run string) func(time.Time) (reaction.Stop, error) {
	rule := route.Rules()[0]
	return func(now time.Time) (reaction.Stop, error) {
		return reaction.Stop{EntryID: reaction.EntryID(finding), TenantID: "acme", ProjectID: "orders", Scope: reaction.ScopeRun,
			RunID: run, FindingID: finding, ProcedureID: rule.ProcedureID, ProcedureVersion: rule.ProcedureVersion,
			ProcedureDigest: rule.ProcedureDigest, RuleID: rule.RuleID, RuleVersion: rule.RuleVersion,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, nil
	}
}

func main() {
	out := os.Args[1]
	ctx := context.Background()
	doc := `{"kind":"reaction-route/v1alpha2","route_id":"refund-stops","serial":1,"tenant_id":"acme","project_id":"orders",` +
		`"rules":[{"procedure_id":"refund","version":"1","digest":"` + digest + `",` +
		`"rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run","expires_seconds":3600}]}`
	body, err := reaction.SignedRouteBody([]byte(doc), keyID(dave), routeFile)
	must(err)
	env := envelope(reaction.SignedRoutePayloadType, body, dave)
	raw, err := reaction.MarshalRouteFile(env)
	must(err)
	must(os.WriteFile(filepath.Join(out, "route.json"), raw, 0o600))
	route, err := reaction.VerifySignedRoute(env, voucher{})
	must(err)

	stops := filepath.Join(out, "stops")
	must(os.Mkdir(stops, 0o700))
	signer := stopwrite.Signer{KeyID: keyID(alice), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, alice)
	}}
	h, err := stopwrite.InitSigned(ctx, stops, route, t0, signer, 4)
	must(err)
	clock := func() time.Time { return t0 }
	for _, s := range [][2]string{{"f-1", "run-1"}, {"f-2", "run-2"}, {"f-3", "run-1"}} {
		_, _, _, err := stopwrite.AppendFinding(ctx, stops, route, clock, stopOf(route, s[0], s[1]))
		must(err)
	}
	lift, err := reaction.SignedLift{KeyID: keyID(alice), ListHead: h.Signed.Digest, RunID: "run-2", ThroughLine: 3,
		TenantID: "acme", Project: "orders", File: listFile}.Payload()
	must(err)
	_, err = stopwrite.AppendLift(ctx, stops, route, reaction.LiftLine{RunID: "run-2", ThroughLine: 3,
		Envelope: envelope(reaction.SignedLiftPayloadType, lift, alice)}, t0.Add(time.Minute))
	must(err)

	routeFloor, stopsFloor := filepath.Join(out, "routefloor"), filepath.Join(out, "stopsfloor")
	must(policystate.InitRoute(ctx, routeFloor, route.ID()))
	_, err = policystate.RaiseRoute(ctx, routeFloor, route.ID(), route.Serial(), route.Digest())
	must(err)
	must(policystate.InitStops(ctx, stopsFloor, "acme", "orders"))
	content, err := os.ReadFile(filepath.Join(stops, stoplist.FileName))
	must(err)
	l, err := reaction.Judge(route, reaction.Prefix{}, content, t0.Add(2*time.Minute), 0)
	must(err)
	f, err := signedstops.NewFloor(stopsFloor, "acme", "orders")
	must(err)
	_, err = f.Take(ctx, l, content)
	must(err)
}
