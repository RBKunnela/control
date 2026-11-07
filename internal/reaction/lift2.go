package reaction

import (
	"fmt"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/strictjson"
)

// SignedLiftKind is the kind of a lift an operator signs under the signed
// authority. It names the head digest of the list it lifts in, so it never
// verifies against another list, one carried or restored later included.
const SignedLiftKind = "reaction-lift/v1alpha2"

const memberListHead = "list_head"

// signedLiftMembers is every member of a v1alpha2 lift, each required.
var signedLiftMembers = []string{
	memberKind, memberAlg, memberKeyID, memberListHead, memberRunID, memberThrough, memberTenantID, memberProjectID, memberFile,
}

// SignedLift is the body of a v1alpha2 lift: it ends every stop of one run
// up to and including one line of the list whose head digest it names, on
// one plane's stop list file.
type SignedLift struct {
	KeyID             string
	ListHead          string
	RunID             string
	ThroughLine       int64
	TenantID, Project string
	File              string
}

// The refusals of a v1alpha2 lift in its place.
const (
	ErrSignedLiftMismatch  Error = "reaction: a signed lift's run, line, list head, tenant, project or file is not what its line, header and route name"
	ErrSignedLiftUnvouched Error = "reaction: no operator granted the lift act signed the lift"
)

// Payload is l's canonical body, the bytes an operator signs, refused
// unless it reads back as l.
func (l SignedLift) Payload() ([]byte, error) {
	body, err := canon.Canonicalize(map[string]any{
		memberKind: SignedLiftKind, memberAlg: signedAlg, memberKeyID: l.KeyID, memberListHead: l.ListHead,
		memberRunID: l.RunID, memberThrough: l.ThroughLine, memberTenantID: l.TenantID, memberProjectID: l.Project,
		memberFile: l.File,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLiftValue, canon.ErrUnsupportedValue)
	}
	back, err := readSignedLift(body)
	if err != nil {
		return nil, err
	}
	if back != l {
		return nil, ErrLiftNotCanonical
	}
	return body, nil
}

func readSignedLift(body []byte) (SignedLift, error) {
	if n := len(body); n > MaxLiftBytes {
		return SignedLift{}, fmt.Errorf("%w: %d bytes, limit %d", ErrLiftTooLarge, n, MaxLiftBytes)
	}
	refusals := docRefusals{json: ErrLiftJSON, repeated: ErrLiftRepeated, kind: ErrLiftKind, member: ErrLiftMember}
	o, err := readDoc(body, SignedLiftKind, refusals, signedLiftMembers, signedLiftMembers)
	if err != nil {
		return SignedLift{}, err
	}
	var l SignedLift
	var ok bool
	for _, f := range [...]struct {
		name  string
		limit int
		into  *string
	}{
		{memberKeyID, MaxListIDBytes, &l.KeyID}, {memberRunID, MaxRunIDBytes, &l.RunID},
		{memberTenantID, MaxTenantIDBytes, &l.TenantID}, {memberProjectID, MaxProjectIDBytes, &l.Project},
	} {
		if *f.into, ok = identifier(o[f.name], f.limit); !ok {
			return SignedLift{}, fmt.Errorf("%w: %s", ErrLiftValue, f.name)
		}
	}
	if l.ListHead, ok = strictjson.String(o[memberListHead]); !ok || !canon.ValidDigest(l.ListHead) {
		return SignedLift{}, fmt.Errorf("%w: %s", ErrLiftValue, memberListHead)
	}
	if l.File, ok = boundFile(o[memberFile]); !ok {
		return SignedLift{}, fmt.Errorf("%w: %s", ErrLiftValue, memberFile)
	}
	if l.ThroughLine, ok = integer(o[memberThrough], 1, policy.MaxSerial); !ok {
		return SignedLift{}, ErrLiftLine
	}
	if alg, isString := strictjson.String(o[memberAlg]); !isString || alg != signedAlg {
		return SignedLift{}, fmt.Errorf("%w: %s", ErrLiftValue, memberAlg)
	}
	return l, nil
}

// VerifySignedLiftLine reads l's envelope as a v1alpha2 lift and ties it to
// its place: one signature of SignedLiftPayloadType over a canonical body
// naming the signature's key; the signed run and line are l's; the list head
// is h's; the tenant and project are r's; the file is the plane's stop list;
// and r's voucher vouches for the signer under the lift act.
func VerifySignedLiftLine(l LiftLine, h Header, r Route) (SignedLift, Signer, error) {
	if !r.signed || h.Signed.Digest == "" {
		return SignedLift{}, Signer{}, fmt.Errorf("%w: a signed lift is judged in a 2.0 list under a v1alpha2 route", ErrSignedLiftMismatch)
	}
	body, err := signedBody(l.Envelope, SignedLiftPayloadType)
	if err != nil {
		return SignedLift{}, Signer{}, fmt.Errorf("%w: %w", ErrLiftUnsigned, err)
	}
	signed, err := readSignedLift(body)
	if err != nil {
		return SignedLift{}, Signer{}, fmt.Errorf("%w: %w", ErrLiftUnsigned, err)
	}
	if signed.RunID != l.RunID || signed.ThroughLine != l.ThroughLine || signed.ListHead != h.Signed.Digest ||
		signed.TenantID != r.tenantID || signed.Project != r.projectID {
		return SignedLift{}, Signer{}, ErrSignedLiftMismatch
	}
	who, err := vouched(r.voucher, VouchLift, l.Envelope, signed.TenantID, signed.Project, signed.File)
	if err != nil {
		return SignedLift{}, Signer{}, fmt.Errorf("%w: %w", ErrSignedLiftUnvouched, err)
	}
	return signed, who, nil
}
