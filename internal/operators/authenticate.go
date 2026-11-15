package operators

import (
	"bytes"
	"context"
	"fmt"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/internal/trust"
)

// Envelope is a DSSE envelope's parts.
type Envelope = trust.Envelope

// MaxStatementBytes bounds a statement's body: a body of an earlier format
// at its 16 KiB bound still fits once it names its plane, an identifier of
// at most 1024 bytes each of which its canonical form may escape.
const MaxStatementBytes = 20480

// issuerPrefix begins the issuer of an operator a roster vouches for, so a
// roster id never reads as another kind's issuer.
const issuerPrefix = "roster/"

// Authenticator is the operator authenticator port: which operator signed a
// statement made for an act.
type Authenticator interface {
	Authenticate(ctx context.Context, act Act, env Envelope) Authentication
	Status() Status
}

// AuthenticatorKind is how a plane authenticates operators. It is a closed
// set.
type AuthenticatorKind string

// AuthenticatorRoster verifies a statement with the key the trust roster
// names. It is the default.
const AuthenticatorRoster AuthenticatorKind = "roster"

// ParseAuthenticatorKind reads a configured kind: the empty kind is the
// default, and every kind this build lacks is ErrUnknownKind.
func ParseAuthenticatorKind(s string) (AuthenticatorKind, error) {
	switch AuthenticatorKind(s) {
	case "", AuthenticatorRoster:
		return AuthenticatorRoster, nil
	}
	return "", fmt.Errorf("%w: authenticator %q", ErrUnknownKind, s)
}

// NewAuthenticator starts the authenticator of kind over roster, its calls
// to the roster held to bounds.
func NewAuthenticator(kind AuthenticatorKind, roster trust.Roster, bounds Bounds) (Authenticator, error) {
	k, err := ParseAuthenticatorKind(string(kind))
	if err != nil {
		return nil, err
	}
	if roster == nil {
		return nil, fmt.Errorf("%w: the authenticator has no trust roster", ErrConfig)
	}
	c, err := newCaller(bounds)
	if err != nil {
		return nil, err
	}
	return &rosterAuthenticator{kind: k, roster: roster, caller: c}, nil
}

type rosterAuthenticator struct {
	kind   AuthenticatorKind
	roster trust.Roster
	*caller
}

func (a *rosterAuthenticator) Status() Status {
	return Status{Kind: string(a.kind), Counts: a.snapshot()}
}

// Authenticate checks, in this order, the first that fails answered: the act
// is known; the payload type is the act's; there is one signature; the body
// is at most MaxStatementBytes; the roster answers in time; it names the key
// the keyid selects, under that id, for the operator role; the signature
// verifies under that key's algorithm over the act's payload type; the body is
// a canonical JSON object whose alg and keyId are the key's.
func (a *rosterAuthenticator) Authenticate(ctx context.Context, act Act, env Envelope) Authentication {
	out := a.authenticate(ctx, act, env)
	a.count(out.cause)
	return out
}

func (a *rosterAuthenticator) authenticate(ctx context.Context, act Act, env Envelope) Authentication {
	rule, cause := shapeOf(act, env)
	if cause != CauseNone {
		return authRefused(cause)
	}
	sig := env.Signatures[0]
	if sig.KeyID == "" {
		return authRefused(CauseUnknownKey)
	}
	answer, cause := call(ctx, a.caller, func(ctx context.Context) trust.Answer { return a.roster.Lookup(ctx, sig.KeyID) })
	if cause != CauseNone {
		return authUnavailable(cause)
	}
	switch answer.State() {
	case trust.StateKey:
	case trust.StateUnknownKey:
		return authRefused(CauseUnknownKey)
	default:
		return authUnavailable(CauseRosterUnavailable)
	}
	key := answer.Key()
	switch {
	case key.ID() != sig.KeyID:
		return authRefused(CauseKeyID)
	case key.Role() != trust.RoleOperator:
		return authRefused(CauseRole)
	}
	body := bytes.Clone(env.Payload)
	if err := key.Verify(rule.payloadType, body, sig.Signature); err != nil {
		return authRefused(CauseSignature)
	}
	if cause := signerOf(body, key); cause != CauseNone {
		return authRefused(cause)
	}
	return Authentication{state: AuthAuthenticated, act: act, issuer: issuerPrefix + key.RosterID(), key: key, body: body}
}

// shapeOf refuses an act this build lacks, and an envelope of another payload
// type, of any number of signatures but one, or over MaxStatementBytes.
func shapeOf(act Act, env Envelope) (actRule, Cause) {
	rule, ok := acts[act]
	switch {
	case !ok:
		return actRule{}, CauseAct
	case env.PayloadType != rule.payloadType:
		return actRule{}, CausePayloadType
	case len(env.Signatures) != 1:
		return actRule{}, CauseSignatures
	case len(env.Payload) > MaxStatementBytes:
		return actRule{}, CauseTooLarge
	}
	return rule, CauseNone
}

// signerOf refuses a body that is not a canonical JSON object, and one whose
// alg or keyId is not the key's.
func signerOf(body []byte, key trust.Key) Cause {
	canonical, err := canon.CanonicalizeJSON(body)
	if err != nil || !bytes.Equal(canonical, body) {
		return CauseBody
	}
	members, err := strictjson.ReadObject(body)
	if err != nil {
		return CauseBody
	}
	alg, ok := strictjson.String(members["alg"])
	if !ok || trust.Alg(alg) != key.Alg() {
		return CauseAlg
	}
	id, ok := strictjson.String(members["keyId"])
	if !ok || id != key.ID() {
		return CauseKeyID
	}
	return CauseNone
}
