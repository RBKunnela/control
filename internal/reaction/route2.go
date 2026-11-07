package reaction

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/strictjson"
)

// SignedRouteKind is the kind of a route an operator signs under the signed
// authority: a route of one tenant's one project, bound to its route file,
// with a scope per rule and no lift key, since a lift is an operator's too.
const SignedRouteKind = "reaction-route/v1alpha2"

// MaxProjectIDBytes bounds a signed route's project_id.
const MaxProjectIDBytes = 256

const memberProjectID = "project_id"

// signedRouteMembers is every member of a v1alpha2 route, each required.
var signedRouteMembers = []string{
	memberKind, memberAlg, memberKeyID, memberRouteID, memberSerial, memberTenantID, memberProjectID, memberFile, memberRules,
}

// parseSignedRoute reads a v1alpha2 route body: one strict JSON object of at
// most MaxSignedBytes holding every member of signedRouteMembers and no
// other, alg ed25519, a key id, a project, a bound file and from one to
// MaxRules rules, each naming scope ScopeRun, no two alike.
func parseSignedRoute(raw []byte) (Route, error) {
	if n := len(raw); n > MaxSignedBytes {
		return Route{}, fmt.Errorf("%w: %d bytes, limit %d", ErrRouteTooLarge, n, MaxSignedBytes)
	}
	o, err := readDoc(raw, SignedRouteKind, routeRefusals(), signedRouteMembers, signedRouteMembers)
	if err != nil {
		return Route{}, err
	}
	r, err := signedRouteValues(o)
	if err != nil {
		return Route{}, err
	}
	if r.rules, err = readRules(o[memberRules], true); err != nil {
		return Route{}, err
	}
	if r.canonical, err = canonicalOf(raw, ErrRouteJSON); err != nil {
		return Route{}, err
	}
	r.digest = bundle.Digest(r.canonical)
	return r, nil
}

func signedRouteValues(o strictjson.Object) (Route, error) {
	r := Route{signed: true}
	var ok bool
	if r.id, ok = strictjson.String(o[memberRouteID]); !ok || !policy.ValidID(r.id) {
		return Route{}, fmt.Errorf("%w: %s", ErrRouteValue, memberRouteID)
	}
	if r.serial, ok = integer(o[memberSerial], 1, policy.MaxSerial); !ok {
		return Route{}, ErrRouteSerial
	}
	if r.tenantID, ok = identifier(o[memberTenantID], MaxTenantIDBytes); !ok {
		return Route{}, fmt.Errorf("%w: %s", ErrRouteValue, memberTenantID)
	}
	if r.projectID, ok = identifier(o[memberProjectID], MaxProjectIDBytes); !ok {
		return Route{}, fmt.Errorf("%w: %s", ErrRouteValue, memberProjectID)
	}
	if r.file, ok = boundFile(o[memberFile]); !ok {
		return Route{}, fmt.Errorf("%w: %s", ErrRouteValue, memberFile)
	}
	if r.keyID, ok = identifier(o[memberKeyID], MaxListIDBytes); !ok {
		return Route{}, fmt.Errorf("%w: %s", ErrRouteValue, memberKeyID)
	}
	if alg, isString := strictjson.String(o[memberAlg]); !isString || alg != signedAlg {
		return Route{}, fmt.Errorf("%w: %s", ErrRouteValue, memberAlg)
	}
	return r, nil
}

// SignedRouteBody is the body of the v1alpha2 route document doc, signed by
// key keyID for the route file file: doc's members with alg, keyId and file
// set to the signer's, in canonical form, refused unless it reads back as a
// v1alpha2 route.
func SignedRouteBody(doc []byte, keyID, file string) ([]byte, error) {
	o, err := readObject(doc, routeRefusals())
	if err != nil {
		return nil, err
	}
	if kind, _ := strictjson.String(o[memberKind]); kind != SignedRouteKind {
		return nil, ErrRouteKind
	}
	set := map[string]json.RawMessage{}
	for k, v := range o {
		set[k] = v
	}
	for k, v := range map[string]string{memberAlg: signedAlg, memberKeyID: keyID, memberFile: file} {
		quoted, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrRouteValue, k)
		}
		set[k] = quoted
	}
	joined, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRouteJSON, err)
	}
	body, err := canonicalOf(joined, ErrRouteJSON)
	if err != nil {
		return nil, err
	}
	if _, err := parseSignedRoute(body); err != nil {
		return nil, err
	}
	return body, nil
}

// VerifySignedRoute reads env as a v1alpha2 route an operator signed for the
// plane v judges for, and returns it bound to v, which judges its list's
// header and lifts. The checks run in this order, the first that fails
// returned: one signature of SignedRoutePayloadType over a canonical body of
// at most MaxSignedBytes naming the signature's key; the body is a v1alpha2
// route; its tenant and project are the plane's and its file the plane's
// route file; v vouches for the signer under the route act; every rule may
// stop a run (CheckStopping).
func VerifySignedRoute(env Envelope, v Voucher) (Route, error) {
	r, err := openSignedRoute(env, v)
	if err != nil {
		return Route{}, err
	}
	if err := CheckStopping(r); err != nil {
		return Route{}, err
	}
	return r, nil
}

// VerifySignedCarrySource is VerifySignedRoute for the route a list is
// carried from, held to CheckCarrySource in place of CheckStopping.
func VerifySignedCarrySource(env Envelope, v Voucher) (Route, error) {
	r, err := openSignedRoute(env, v)
	if err != nil {
		return Route{}, err
	}
	if err := CheckCarrySource(r); err != nil {
		return Route{}, err
	}
	return r, nil
}

func openSignedRoute(env Envelope, v Voucher) (Route, error) {
	body, err := signedBody(env, SignedRoutePayloadType)
	if err != nil {
		return Route{}, fmt.Errorf("the route: %w", err)
	}
	r, err := ParseRoute(body)
	if err != nil {
		return Route{}, err
	}
	if !r.signed {
		return Route{}, ErrRouteKind
	}
	if !bytes.Equal(body, r.canonical) {
		return Route{}, ErrRouteNotCanonical
	}
	s, err := vouched(v, VouchRoute, env, r.tenantID, r.projectID, r.file)
	if err != nil {
		return Route{}, fmt.Errorf("the route: %w", err)
	}
	r.voucher, r.signer = v, s
	return r, nil
}

// ParseRouteDocument reads doc as a route document an operator is about to
// sign: a v1alpha1 route as ParseRoute reads it, and a v1alpha2 route as
// SignedRouteBody would make it for any key and file, which the signer sets.
func ParseRouteDocument(doc []byte) (Route, error) {
	if o, err := readObject(doc, routeRefusals()); err == nil {
		if kind, _ := strictjson.String(o[memberKind]); kind == SignedRouteKind {
			body, err := SignedRouteBody(doc, "unsigned", "/unsigned")
			if err != nil {
				return Route{}, err
			}
			return ParseRoute(body)
		}
	}
	return ParseRoute(doc)
}
