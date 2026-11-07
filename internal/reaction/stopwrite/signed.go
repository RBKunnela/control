package stopwrite

import (
	"context"
	"fmt"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/reaction"
)

// Signer is an operator key a writer signs a 2.0 header with: its id and a
// function that signs a body under a payload type.
type Signer struct {
	KeyID string
	Sign  func(payloadType string, body []byte) ([]byte, error)
}

// ErrSigner is a write handed no signer, or one whose signature fails.
const ErrSigner Error = "stopwrite: the operator key cannot sign the header"

// InitSigned is Init for a v1alpha2 route, which a voucher took: the header
// is signed by s at serial for the route's tenant and project and the
// route's plane's stop list, and names no previous list, so a plane whose
// floor holds a list takes it only through a carry.
func InitSigned(ctx context.Context, dir string, route reaction.Route, now time.Time, s Signer, serial int64) (reaction.Header, error) {
	h, line, err := signedHeader(route, s, serial, "")
	if err != nil {
		return reaction.Header{}, err
	}
	if err := create(ctx, dir, route, now, [][]byte{line}); err != nil {
		return reaction.Header{}, err
	}
	return h, nil
}

// signedHeader is the 2.0 header of a new list under route, signed by s,
// and its line.
func signedHeader(route reaction.Route, s Signer, serial int64, previous string) (reaction.Header, []byte, error) {
	if !route.Signed() || route.Plane().ListFile == "" {
		return reaction.Header{}, nil, fmt.Errorf("%w: a signed header is written under a v1alpha2 route a voucher took", ErrRefused)
	}
	if s.Sign == nil || s.KeyID == "" {
		return reaction.Header{}, nil, ErrSigner
	}
	if serial < 1 || serial > policy.MaxSerial {
		return reaction.Header{}, nil, fmt.Errorf("%w: serial %d is outside 1 to 2^53-1", ErrRefused, serial)
	}
	h, err := newHeader(route)
	if err != nil {
		return reaction.Header{}, nil, err
	}
	h.Signed = reaction.HeaderSigned{
		KeyID: s.KeyID, TenantID: route.TenantID(), ProjectID: route.ProjectID(), File: route.Plane().ListFile,
		Serial: serial, Previous: previous,
	}
	body, err := reaction.HeaderBody(h)
	if err != nil {
		return reaction.Header{}, nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	sig, err := s.Sign(reaction.SignedHeaderPayloadType, body)
	if err != nil {
		return reaction.Header{}, nil, fmt.Errorf("%w: %w", ErrSigner, err)
	}
	env := reaction.Envelope{
		PayloadType: reaction.SignedHeaderPayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: s.KeyID, Signature: sig}},
	}
	line, err := reaction.SignedHeaderLine(env)
	if err != nil {
		return reaction.Header{}, nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	parsed, err := reaction.ParseLine(line)
	if err != nil {
		return reaction.Header{}, nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return parsed.Header, line, nil
}
