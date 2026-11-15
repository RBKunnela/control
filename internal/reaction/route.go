package reaction

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/pkg/contract"
)

const (
	// RouteKind is the one kind a route may name.
	RouteKind = "reaction-route/v1alpha1"
	// ScopeRun is the scope of a stop that holds one opened run's later
	// calls, the one scope a v1alpha1 or v1alpha2 route may name.
	ScopeRun = "run"
	// MaxRouteBytes bounds a route document, signed or not.
	MaxRouteBytes = 65536
	// MaxRules bounds the rules of one route.
	MaxRules = 256
	// MinLifetime is the shortest expires_seconds a rule may name.
	MinLifetime = time.Minute
	// MaxLifetime is the longest expires_seconds a rule may name: the
	// longest a run lives.
	MaxLifetime = 720 * time.Hour
	// MaxTenantIDBytes bounds the tenant_id, as a run record bounds its own.
	MaxTenantIDBytes = 256
)

const (
	memberRouteID   = "route_id"
	memberSerial    = "serial"
	memberTenantID  = "tenant_id"
	memberScope     = "scope"
	memberLiftKey   = "lift_public_key"
	memberRules     = "rules"
	memberProcedure = "procedure_id"
	memberVersion   = "version"
	memberDigest    = "digest"
	memberRuleID    = "rule_id"
	memberRuleVer   = "rule_version"
	memberExpires   = "expires_seconds"
)

func routeRefusals() docRefusals {
	return docRefusals{json: ErrRouteJSON, repeated: ErrRouteRepeated, kind: ErrRouteKind, member: ErrRouteMember}
}

// Rule is one finding a route allows to stop a run: a procedure as a finding
// record names it and a supervise rule.
type Rule struct {
	ProcedureID, ProcedureVersion, ProcedureDigest string
	RuleID, RuleVersion                            string
	// Scope is what a stop under the rule holds: ScopeRun, the one scope
	// served. A v1alpha1 route names it once for every rule, and v1alpha2
	// and v1alpha3 per rule.
	Scope string
	// Lifetime is the longest a stop under the rule may last. Zero sets no
	// bound of its own: the stop lasts as long as its run, and never longer
	// than MaxLifetime.
	Lifetime time.Duration
}

// key is what makes two rules one.
func (r Rule) key() [5]string {
	return [5]string{r.ProcedureID, r.ProcedureVersion, r.ProcedureDigest, r.RuleID, r.RuleVersion}
}

// Route is a route document that was read and checked. Only ParseRoute and
// VerifyRoute make one; the zero Route permits nothing and signs nothing.
type Route struct {
	id        string
	serial    int64
	tenantID  string
	liftKey   ed25519.PublicKey
	rules     []Rule
	canonical []byte
	digest    string
	format    RouteFormat
	// The members of a route an operator signed, zero in a v1alpha1 one: the
	// plane, which a v1alpha2 route does not name, the project, the bound
	// route file, the signing key, and, once a voucher took it, the voucher
	// its list's signatures are judged by, its signer and the envelope that
	// voucher is asked about again.
	planeID   string
	projectID string
	file      string
	keyID     string
	voucher   Voucher
	signer    Signer
	env       Envelope
}

// Format is the format the route was read in; FormatNone for the zero Route.
func (r Route) Format() RouteFormat { return r.format }

// PlaneID is the plane a v1alpha3 route names, and empty in any other.
func (r Route) PlaneID() string { return r.planeID }

// ProjectID is the project a route an operator signed names, and empty in a
// v1alpha1 one.
func (r Route) ProjectID() string { return r.projectID }

// File is the route file a route an operator signed is bound to.
func (r Route) File() string { return r.file }

// KeyID is the key id the body of a route an operator signed names.
func (r Route) KeyID() string { return r.keyID }

// Signer is who signed a route a voucher took, and the zero Signer
// otherwise.
func (r Route) Signer() Signer { return r.signer }

// Plane is the plane a route a voucher took is judged for, and the zero
// Plane otherwise.
func (r Route) Plane() Plane {
	if r.voucher == nil {
		return Plane{}
	}
	return r.voucher.Plane()
}

// ID is the route's route_id.
func (r Route) ID() string { return r.id }

// Serial is the route's serial.
func (r Route) Serial() int64 { return r.serial }

// TenantID is the one tenant whose runs the route may stop.
func (r Route) TenantID() string { return r.tenantID }

// LiftKey is a copy of the public key every lift under the route is signed
// with.
func (r Route) LiftKey() ed25519.PublicKey { return bytes.Clone(r.liftKey) }

// Rules is a copy of the route's rules, in the order the document lists them.
func (r Route) Rules() []Rule { return slices.Clone(r.rules) }

// Canonical is a copy of the route's canonical bytes, the bytes it is signed
// over.
func (r Route) Canonical() []byte { return bytes.Clone(r.canonical) }

// Digest is "sha256:" and the hex SHA-256 of the canonical bytes.
func (r Route) Digest() string { return r.digest }

// ParseRoute reads a route document, a v1alpha2 or v1alpha3 one as
// parseSignedRoute says, and a v1alpha1 one as follows: one strict JSON object of at most
// MaxRouteBytes holding kind RouteKind, route_id, serial, tenant_id, scope
// ScopeRun, lift_public_key in the one spelling policy.public_key takes and
// not of small order, and from one to MaxRules rules, no two alike. It reads
// no signature; VerifyRoute reads a signed one.
func ParseRoute(raw []byte) (Route, error) {
	if n := len(raw); n > MaxRouteBytes {
		return Route{}, fmt.Errorf("%w: %d bytes, limit %d", ErrRouteTooLarge, n, MaxRouteBytes)
	}
	if o, err := readObject(raw, routeRefusals()); err == nil {
		switch kind, _ := strictjson.String(o[memberKind]); kind {
		case SignedRouteKind:
			return parseSignedRoute(raw, FormatV1Alpha2Carry)
		case SignedRouteKindV3:
			return parseSignedRoute(raw, FormatV1Alpha3)
		}
	}
	names := []string{memberKind, memberRouteID, memberSerial, memberTenantID, memberScope, memberLiftKey, memberRules}
	o, err := readDoc(raw, RouteKind, routeRefusals(), names, names)
	if err != nil {
		return Route{}, err
	}
	r, err := routeValues(o)
	if err != nil {
		return Route{}, err
	}
	if r.rules, err = readRules(o[memberRules], FormatV1Alpha1); err != nil {
		return Route{}, err
	}
	if r.canonical, err = canonicalOf(raw, ErrRouteJSON); err != nil {
		return Route{}, err
	}
	r.digest = bundle.Digest(r.canonical)
	return r, nil
}

func routeValues(o strictjson.Object) (Route, error) {
	r := Route{format: FormatV1Alpha1}
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
	if scope, isString := strictjson.String(o[memberScope]); !isString || scope != ScopeRun {
		return Route{}, ErrRouteScope
	}
	line, isString := strictjson.String(o[memberLiftKey])
	key, err := policykey.ParsePublic(line)
	// ParsePublic takes the one newline a key file ends in; inside a document
	// that would be a second spelling of one key, and a second digest.
	if !isString || err != nil || policykey.FormatPublic(key) != line {
		return Route{}, fmt.Errorf("%w: %s", ErrRouteValue, memberLiftKey)
	}
	if bundle.WeakKey(key) {
		return Route{}, fmt.Errorf("%w: %s is a key of small order", ErrRouteValue, memberLiftKey)
	}
	r.liftKey = key
	return r, nil
}

// readRules reads the rules of a route of format f, each naming its scope
// unless f is FormatV1Alpha1.
func readRules(raw json.RawMessage, f RouteFormat) ([]Rule, error) {
	var items []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
		return nil, fmt.Errorf("%w: %s is not an array", ErrRouteValue, memberRules)
	}
	if n := len(items); n == 0 || n > MaxRules {
		return nil, fmt.Errorf("%w: %d rules, bounds 1 and %d", ErrRouteRules, n, MaxRules)
	}
	out := make([]Rule, 0, len(items))
	seen := make(map[[5]string]bool, len(items))
	for i, item := range items {
		rule, err := readRule(item, f)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		if seen[rule.key()] {
			return nil, fmt.Errorf("%w: rules[%d]", ErrRouteRuleRepeated, i)
		}
		seen[rule.key()] = true
		out = append(out, rule)
	}
	return out, nil
}

// readRuleIDs reads the procedure and the rule a route's rule names.
func readRuleIDs(o strictjson.Object, r *Rule) error {
	for _, f := range [...]struct {
		name string
		into *string
	}{
		{memberProcedure, &r.ProcedureID}, {memberVersion, &r.ProcedureVersion},
		{memberRuleID, &r.RuleID}, {memberRuleVer, &r.RuleVersion},
	} {
		v, ok := identifier(o[f.name], contract.MaxStringBytes)
		if !ok {
			return fmt.Errorf("%w: %s", ErrRouteValue, f.name)
		}
		*f.into = v
	}
	return nil
}

func readRule(raw json.RawMessage, f RouteFormat) (Rule, error) {
	required := []string{memberProcedure, memberVersion, memberDigest, memberRuleID, memberRuleVer}
	perRule := f != FormatV1Alpha1
	if perRule {
		required = append(required, memberScope)
	}
	o, err := readObject(raw, routeRefusals())
	if err != nil {
		return Rule{}, err
	}
	if err := members(o, routeRefusals(), append(slices.Clone(required), memberExpires), required); err != nil {
		return Rule{}, err
	}
	var r Rule
	if perRule {
		if r.Scope, err = ruleScope(o[memberScope], f); err != nil {
			return Rule{}, err
		}
	}
	if err := readRuleIDs(o, &r); err != nil {
		return Rule{}, err
	}
	digest, ok := strictjson.String(o[memberDigest])
	if !ok || !procedureDigest(digest) {
		return Rule{}, fmt.Errorf("%w: %s", ErrRouteValue, memberDigest)
	}
	r.ProcedureDigest = digest
	if raw, set := o[memberExpires]; set {
		seconds, ok := integer(raw, int64(MinLifetime/time.Second), int64(MaxLifetime/time.Second))
		if !ok {
			return Rule{}, ErrRouteLifetime
		}
		r.Lifetime = time.Duration(seconds) * time.Second
	}
	return r, nil
}

// procedureDigest reports whether s is a procedure digest as a finding record
// carries it: 64 lower-case hex digits with no algorithm prefix, unlike the
// digest of a route or a bundle.
func procedureDigest(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}

// ruleScope reads the scope of a rule of a route of format f: run alone in
// v1alpha2, and in v1alpha3 any scope the grammar names, each refused that
// this build does not serve.
func ruleScope(raw json.RawMessage, f RouteFormat) (string, error) {
	scope, ok := readScope(raw)
	switch {
	case !ok:
		return "", ErrRouteScope
	case f == FormatV1Alpha3:
		if err := scopeServed(scope); err != nil {
			return "", err
		}
		return scope, nil
	case f == FormatV1Alpha2Carry && scope == ScopeRun:
		return scope, nil
	}
	return "", ErrRouteScope
}
