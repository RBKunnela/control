package reaction_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/guardana/control/internal/reaction"
)

// procDigest is a procedure digest as a finding record spells it: 64
// lower-case hex digits, no algorithm prefix.
const procDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// docDigest is a route's or a statement's digest: "sha256:" and 64 lower-case
// hex digits.
const docDigest = "sha256:" + procDigest

// routeTemplate is a route as an operator writes it, with LIFTKEY in place
// of the lift key's line.
const routeTemplate = `{
  "kind": "reaction-route/v1alpha1",
  "route_id": "refunds",
  "serial": 7,
  "tenant_id": "acme",
  "scope": "run",
  "lift_public_key": "LIFTKEY",
  "rules": [
    {"procedure_id": "refund", "version": "3", "digest": "` + procDigest + `",
     "rule_id": "STEP_OUTSIDE_PROCEDURE", "rule_version": "1", "expires_seconds": 3600},
    {"procedure_id": "refund", "version": "3", "digest": "` + procDigest + `",
     "rule_id": "RESOURCE_OUTSIDE_RUN", "rule_version": "1"}
  ]
}`

// routeCanonical is routeTemplate's canonical form, written out by hand:
// members sorted, no white space.
const routeCanonical = `{"kind":"reaction-route/v1alpha1","lift_public_key":"LIFTKEY","route_id":"refunds",` +
	`"rules":[{"digest":"` + procDigest + `","expires_seconds":3600,"procedure_id":"refund","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","version":"3"},` +
	`{"digest":"` + procDigest + `","procedure_id":"refund","rule_id":"RESOURCE_OUTSIDE_RUN","rule_version":"1","version":"3"}],` +
	`"scope":"run","serial":7,"tenant_id":"acme"}`

// seededKey derives a key from a seed of one repeated byte at run time, so
// no key text is in the tree.
func seededKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte(strings.Repeat(string([]byte{b}), ed25519.SeedSize)))
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey {
	return k.Public().(ed25519.PublicKey)
}

// liftKey and routeKey are the two keys most tests use.
func liftKey() ed25519.PrivateKey  { return seededKey(0x4c) }
func routeKey() ed25519.PrivateKey { return seededKey(0x52) }

// keyLine is the public key line, standard base64 of the 32 bytes, computed
// here rather than by the package under test.
func keyLine(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(pubOf(k))
}

// keyIDOf is "ed25519-" and the first 16 hex digits of SHA-256 over the
// public key, computed here rather than by the package under test.
func keyIDOf(k ed25519.PrivateKey) string {
	sum := sha256.Sum256(pubOf(k))
	return "ed25519-" + hex.EncodeToString(sum[:8])
}

func withLift(doc string) string {
	return strings.ReplaceAll(doc, "LIFTKEY", keyLine(liftKey()))
}

func validRoute(t testing.TB) reaction.Route {
	t.Helper()
	r, err := reaction.ParseRoute([]byte(withLift(routeTemplate)))
	if err != nil {
		t.Fatalf("ParseRoute: %v", err)
	}
	return r
}

// expectOnly fails unless err matches want and no other sentinel of set.
func expectOnly(t testing.TB, what string, err, want error, set []error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: accepted, want %q", what, want)
		return
	}
	for _, s := range set {
		if got, wanted := errors.Is(err, s), errors.Is(s, want); got != wanted {
			t.Errorf("%s: errors.Is(%q, %q) = %v, want %v", what, err, s, got, wanted)
		}
	}
}

func routeRefusals() []error {
	return []error{
		reaction.ErrRouteTooLarge, reaction.ErrRouteJSON, reaction.ErrRouteRepeated, reaction.ErrRouteKind,
		reaction.ErrRouteMember, reaction.ErrRouteValue, reaction.ErrRouteSerial, reaction.ErrRouteScope,
		reaction.ErrRouteRules, reaction.ErrRouteRuleRepeated, reaction.ErrRouteLifetime, reaction.ErrRouteNotCanonical,
	}
}

func liftRefusals() []error {
	return []error{
		reaction.ErrLiftTooLarge, reaction.ErrLiftJSON, reaction.ErrLiftRepeated, reaction.ErrLiftKind,
		reaction.ErrLiftMember, reaction.ErrLiftValue, reaction.ErrLiftVersion, reaction.ErrLiftLine,
		reaction.ErrLiftNotCanonical,
	}
}

func envelopeRefusals() []error {
	return []error{
		reaction.ErrRoutePayloadType, reaction.ErrRouteSignatures, reaction.ErrRouteKey, reaction.ErrRouteSignature,
		reaction.ErrLiftPayloadType, reaction.ErrLiftSignatures, reaction.ErrLiftKey, reaction.ErrLiftSignature,
		reaction.ErrRouteTooLarge, reaction.ErrLiftTooLarge, reaction.ErrRouteNotCanonical, reaction.ErrLiftNotCanonical,
		reaction.ErrSigningKey, reaction.ErrKeysEqual, reaction.ErrKeySize, reaction.ErrRouteRuleStops,
	}
}
