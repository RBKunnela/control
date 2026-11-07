package reaction

import (
	"context"
	"fmt"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/internal/policykey"
)

// SignedHeaderKind is the kind of the body a 2.0 header's envelope signs.
const SignedHeaderKind = "reaction-list-header/2.0"

// MaxHeaderEnvelopeBytes bounds the envelope a 2.0 header line carries. The
// base64 of a body of MaxSignedBytes and one signature fit within it.
const MaxHeaderEnvelopeBytes = 32768

const memberPrevious = "previous"

// HeaderSigned is what an operator signs of a 2.0 header besides the list
// and route it names: the signing key, the plane's tenant and project, the
// stop list file it is bound to, its serial, which only rises from one list
// to the next, and, for a list carried from another, the previous list's
// head digest. Digest is this header's own head digest, over the body as
// signed: the stop list floor keeps it, and a lift names it.
type HeaderSigned struct {
	KeyID, TenantID, ProjectID, File string
	Serial                           int64
	Previous                         string
	Digest                           string
}

// The refusals of a 2.0 header in its place.
const (
	ErrHeaderOther    Error = "reaction: the signed header names another tenant, project or stop list file than the route's plane"
	ErrHeaderUnsigned Error = "reaction: no operator granted the stop list act signed the header"
)

// headerMembers is every member of a 2.0 header's body; previous alone is
// optional.
var headerMembers = []string{
	memberKind, memberAlg, memberKeyID, memberListID, memberSerial, memberTenantID, memberProjectID, memberFile,
	memberRouteID, memberRouteSerial, memberRouteDigest,
}

// readSignedHeaderLine reads a 2.0 header line, which holds the signed
// envelope alone, and the header its body names. Nothing checks the
// signature here: the judge asks the route's voucher.
func readSignedHeaderLine(o strictjson.Object) (Header, Envelope, error) {
	if err := lineMembers(o, memberEnvelope); err != nil {
		return Header{}, Envelope{}, err
	}
	raw := o[memberEnvelope]
	if len(raw) == 0 || raw[0] != '{' {
		return Header{}, Envelope{}, fmt.Errorf("%w: %s", ErrLineValue, memberEnvelope)
	}
	env, err := policykey.ParseEnvelope(raw, MaxHeaderEnvelopeBytes)
	if err != nil {
		return Header{}, Envelope{}, fmt.Errorf("%w: %s: %w", ErrLineValue, memberEnvelope, err)
	}
	body, err := signedBody(env, SignedHeaderPayloadType)
	if err != nil {
		return Header{}, Envelope{}, fmt.Errorf("%w: the header's envelope: %w", ErrLineValue, err)
	}
	h, err := readHeaderBody(body)
	if err != nil {
		return Header{}, Envelope{}, err
	}
	return h, env, nil
}

// readHeaderBody reads a 2.0 header's signed body.
func readHeaderBody(body []byte) (Header, error) {
	refusals := docRefusals{json: ErrLineJSON, repeated: ErrLineRepeat, kind: ErrLineKind, member: ErrLineMember}
	o, err := readDoc(body, SignedHeaderKind, refusals, append([]string{memberPrevious}, headerMembers...), headerMembers)
	if err != nil {
		return Header{}, err
	}
	var h Header
	if err := readHeaderRoute(o, &h); err != nil {
		return Header{}, err
	}
	if err := readHeaderSigned(o, &h.Signed); err != nil {
		return Header{}, err
	}
	h.Signed.Digest = bundle.Digest(body)
	return h, nil
}

// readHeaderRoute reads the list and the route a 2.0 header names.
func readHeaderRoute(o strictjson.Object, h *Header) error {
	var ok bool
	if h.ListID, ok = identifier(o[memberListID], MaxListIDBytes); !ok {
		return fmt.Errorf("%w: %s", ErrLineValue, memberListID)
	}
	if h.RouteID, ok = strictjson.String(o[memberRouteID]); !ok || !policy.ValidID(h.RouteID) {
		return fmt.Errorf("%w: %s", ErrLineValue, memberRouteID)
	}
	if h.RouteSerial, ok = integer(o[memberRouteSerial], 1, policy.MaxSerial); !ok {
		return fmt.Errorf("%w: %s", ErrLineValue, memberRouteSerial)
	}
	return digestOf(o, memberRouteDigest, &h.RouteDigest)
}

// readHeaderSigned reads what a 2.0 header binds: its serial, key, plane,
// file and previous head.
func readHeaderSigned(o strictjson.Object, s *HeaderSigned) error {
	var ok bool
	if s.Serial, ok = integer(o[memberSerial], 1, policy.MaxSerial); !ok {
		return fmt.Errorf("%w: %s", ErrLineValue, memberSerial)
	}
	for _, f := range [...]struct {
		name  string
		limit int
		into  *string
	}{
		{memberTenantID, MaxTenantIDBytes, &s.TenantID}, {memberProjectID, MaxProjectIDBytes, &s.ProjectID},
		{memberKeyID, MaxListIDBytes, &s.KeyID},
	} {
		if err := identifierOf(o, f.name, f.limit, f.into); err != nil {
			return err
		}
	}
	if s.File, ok = boundFile(o[memberFile]); !ok {
		return fmt.Errorf("%w: %s", ErrLineValue, memberFile)
	}
	if _, set := o[memberPrevious]; set {
		if err := digestOf(o, memberPrevious, &s.Previous); err != nil {
			return err
		}
	}
	return nil
}

// HeaderBody is the body an operator signs for h, a 2.0 header whose Digest
// is left out since the body defines it: canonical, refused unless it reads
// back as h.
func HeaderBody(h Header) ([]byte, error) {
	s := h.Signed
	members := map[string]any{
		memberKind: SignedHeaderKind, memberAlg: signedAlg, memberKeyID: s.KeyID, memberListID: h.ListID,
		memberSerial: s.Serial, memberTenantID: s.TenantID, memberProjectID: s.ProjectID, memberFile: s.File,
		memberRouteID: h.RouteID, memberRouteSerial: h.RouteSerial, memberRouteDigest: h.RouteDigest,
	}
	if s.Previous != "" {
		members[memberPrevious] = s.Previous
	}
	body, err := canon.Canonicalize(members)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineMarshal, canon.ErrUnsupportedValue)
	}
	back, err := readHeaderBody(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineMarshal, err)
	}
	want := h
	want.Signed.Digest = back.Signed.Digest
	if back != want {
		return nil, ErrLineMarshal
	}
	return body, nil
}

// SignedHeaderLine is the 2.0 header line holding env, its newline left out,
// refused unless ParseLine reads it back with env.
func SignedHeaderLine(env Envelope) ([]byte, error) {
	raw, err := canon.Canonicalize(map[string]any{
		memberKind: kindHeader, memberVersion: SignedListVersion, memberEnvelope: envelopeMembers(env),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineMarshal, canon.ErrUnsupportedValue)
	}
	got, err := ParseLine(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineMarshal, err)
	}
	if got.Kind != KindHeader || !sameEnvelope(got.HeaderEnvelope, env) {
		return nil, ErrLineMarshal
	}
	return raw, nil
}

// judgeSignedHeader holds a 2.0 header to its route: the same plane's
// tenant, project and stop list file, and a signer the route's voucher
// vouches for under the stop list act, asked within ctx.
func judgeSignedHeader(ctx context.Context, r Route, h Header, env Envelope) (Signer, error) {
	s := h.Signed
	if s.TenantID != r.tenantID || s.ProjectID != r.projectID {
		return Signer{}, ErrHeaderOther
	}
	signer, err := vouchedWithin(ctx, r.voucher, VouchHeader, env, s.TenantID, s.ProjectID, s.File)
	if err != nil {
		return Signer{}, fmt.Errorf("%w: %w", ErrHeaderUnsigned, err)
	}
	return signer, nil
}
