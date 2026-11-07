package reaction

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"slices"

	"github.com/guardana/control/internal/policy/strictjson"
)

// The DSSE payload types of the three formats an operator signs under the
// signed authority. They are operators' payload types for the route, the
// stop list header and the lift acts; this package links no operator port,
// and a test holds each pair equal.
const (
	SignedRoutePayloadType  = "application/vnd.agent-reaction-route.v1alpha2+json"
	SignedHeaderPayloadType = "application/vnd.agent-stop-list-header+json"
	SignedLiftPayloadType   = "application/vnd.agent-reaction-lift.v1alpha2+json"
)

// MaxSignedBytes bounds the body of each signed format at the operator
// authenticator's bound on any statement.
const MaxSignedBytes = 16384

// signedAlg is the one algorithm a signed body names: an operator key's.
const signedAlg = "ed25519"

// MaxFileBytes bounds the path of the route file or the stop list a signed
// body is bound to.
const MaxFileBytes = 1024

const (
	memberAlg   = "alg"
	memberKeyID = "keyId"
	memberFile  = "file"
)

// SignedKind is which signed format an operator's signature is asked about.
type SignedKind uint8

// The signed formats. A route is signed under the route act, at the admin
// level; a stop list header and a lift under their own acts, at operate.
const (
	VouchRoute SignedKind = iota + 1
	VouchHeader
	VouchLift
)

// Plane is the one plane signed documents are judged for: its tenant and
// project, and the route file and stop list each document is bound to, as
// absolute, clean paths with every link on the way to their directory
// resolved.
type Plane struct {
	Tenant, Project     string
	RouteFile, ListFile string
}

// Signer is the operator whose signature a Voucher took.
type Signer struct {
	Subject, KeyID string
}

// Voucher judges operator signatures for one plane. Vouch answers who signed
// env for kind, holding a grant over the plane's tenant and project at the
// level kind needs, or refuses; nothing it answers is read as a pass unless
// the error is nil. An error wrapping ErrUnanswered says it could not
// answer, which a plane reports apart from a refusal. It is asked only about
// a body whose tenant, project and file are the plane's. Once it took a
// document, what it answers about it depends only on the kind and the key
// that signed it, so a judge asks it again about one document of each.
type Voucher interface {
	Plane() Plane
	Vouch(kind SignedKind, env Envelope) (Signer, error)
}

// ContextVoucher is a Voucher that holds what it asks to ctx: a judge that
// asks again within a poll's deadline asks through it, and an ended ctx is
// an error wrapping ErrUnanswered.
type ContextVoucher interface {
	Voucher
	VouchContext(ctx context.Context, kind SignedKind, env Envelope) (Signer, error)
}

// The refusals of a signed document as a whole, whatever its format.
const (
	ErrNoVoucher  Error = "reaction: a signed format is judged with no voucher for its plane"
	ErrOtherPlane Error = "reaction: the signed document names another tenant or project than the plane's"
	ErrOtherFile  Error = "reaction: the signed document is bound to another file than the plane reads"
	ErrUnvouched  Error = "reaction: no operator granted the act signed the document"
	// ErrRouteUnvouched is a route a poll asked the voucher about again and
	// the voucher no longer takes from its signer.
	ErrRouteUnvouched Error = "reaction: no operator granted the route act signs the route any longer"
	ErrUnanswered     Error = "reaction: the voucher could not answer who signed the document"
	ErrSignedShape    Error = "reaction: the signed envelope is not one signature of its format's payload type within its bound"
	ErrSignerKey      Error = "reaction: the signed body names another key or algorithm than its signature"
)

// signedBody is the body of env when it is one signature of payloadType
// within MaxSignedBytes, canonical, and naming alg ed25519 and the
// signature's key id. Nothing here checks the signature.
func signedBody(env Envelope, payloadType string) ([]byte, error) {
	if env.PayloadType != payloadType || len(env.Signatures) != 1 || len(env.Payload) > MaxSignedBytes {
		return nil, ErrSignedShape
	}
	body := bytes.Clone(env.Payload)
	canonical, err := canonicalOf(body, ErrSignedShape)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, body) {
		return nil, fmt.Errorf("%w: the body is not its own canonical form", ErrSignedShape)
	}
	o, err := strictjson.ReadObject(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignedShape, err)
	}
	alg, okAlg := strictjson.String(o[memberAlg])
	id, okID := strictjson.String(o[memberKeyID])
	if !okAlg || !okID || alg != signedAlg || id == "" || id != env.Signatures[0].KeyID {
		return nil, ErrSignerKey
	}
	return body, nil
}

// vouched holds tenant, project and file to v's plane, the file to the
// route's or the list's as want names, and asks v who signed env for kind.
func vouched(v Voucher, kind SignedKind, env Envelope, tenant, project, file string) (Signer, error) {
	return vouchedWithin(context.Background(), v, kind, env, tenant, project, file)
}

// vouchedWithin is vouched held to ctx: an ended ctx, or an answer that came
// after it ended, is ErrUnanswered, and a ContextVoucher is asked under ctx.
func vouchedWithin(ctx context.Context, v Voucher, kind SignedKind, env Envelope, tenant, project, file string) (Signer, error) {
	if v == nil {
		return Signer{}, ErrNoVoucher
	}
	p := v.Plane()
	if tenant != p.Tenant || project != p.Project {
		return Signer{}, ErrOtherPlane
	}
	want := p.ListFile
	if kind == VouchRoute {
		want = p.RouteFile
	}
	if want == "" || file != want {
		return Signer{}, fmt.Errorf("%w: it names %q, and the plane reads %q", ErrOtherFile, file, want)
	}
	if err := ctx.Err(); err != nil {
		return Signer{}, fmt.Errorf("%w: %w: %w", ErrUnvouched, ErrUnanswered, err)
	}
	var s Signer
	var err error
	if cv, ok := v.(ContextVoucher); ok {
		s, err = cv.VouchContext(ctx, kind, env)
	} else {
		s, err = v.Vouch(kind, env)
	}
	if err == nil && ctx.Err() != nil {
		err = fmt.Errorf("%w: answered after %w", ErrUnanswered, ctx.Err())
	}
	if err != nil {
		return Signer{}, fmt.Errorf("%w: %w", ErrUnvouched, err)
	}
	return s, nil
}

// vouchedDoc is a signed document of a list a voucher took: its line, kind
// and envelope, the tenant, project and file its body names, and its signer.
type vouchedDoc struct {
	line                  int64
	kind                  SignedKind
	env                   Envelope
	tenant, project, file string
	signer                Signer
}

// took records d unless s holds a document of its kind and signer already.
func (s *seen) took(d vouchedDoc) {
	if !slices.ContainsFunc(s.vouched, func(o vouchedDoc) bool { return o.kind == d.kind && o.signer == d.signer }) {
		s.vouched = append(s.vouched, d)
	}
}

// vouchAgain asks a signed route's voucher again, within ctx, about the
// route and each document s holds, s nil holding none, and refuses the first
// it no longer takes from the same signer, or cannot answer about, as the
// route's or the line's refusal when it was first judged.
func vouchAgain(ctx context.Context, route Route, s *seen) error {
	if !route.signed {
		return nil
	}
	if err := sameSigner(ctx, route.voucher, vouchedDoc{kind: VouchRoute, env: route.env, tenant: route.tenantID,
		project: route.projectID, file: route.file, signer: route.signer}); err != nil {
		return fmt.Errorf("the route: %w: %w", ErrRouteUnvouched, err)
	}
	if s == nil {
		return nil
	}
	for _, d := range s.vouched {
		err := sameSigner(ctx, route.voucher, d)
		if err == nil {
			continue
		}
		refusal := ErrSignedLiftUnvouched
		if d.kind == VouchHeader {
			refusal = ErrHeaderUnsigned
		}
		return &LineError{Line: d.line, Err: fmt.Errorf("%w: %w", refusal, err)}
	}
	return nil
}

// sameSigner refuses d unless v, asked within ctx, takes it from its signer.
func sameSigner(ctx context.Context, v Voucher, d vouchedDoc) error {
	who, err := vouchedWithin(ctx, v, d.kind, d.env, d.tenant, d.project, d.file)
	if err == nil && who != d.signer {
		err = fmt.Errorf("%w: the key now names %q, not %q", ErrUnvouched, who.Subject, d.signer.Subject)
	}
	return err
}

// boundFile reads raw as a bound path: absolute, clean, at most
// MaxFileBytes, with no control character. The rule is a path's, not an
// identifier's, so it is checked here.
func boundFile(raw []byte) (string, bool) {
	s, ok := strictjson.String(raw)
	if !ok || s == "" || len(s) > MaxFileBytes || s[0] != '/' || path.Clean(s) != s {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return s, true
}
