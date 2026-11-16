package reaction

import (
	"context"
	"fmt"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/strictjson"
)

// SignedLiftKindV3 is the kind of a lift an operator signs for one plane: it
// names the scope and subject whose stops it ends in place of a run.
const SignedLiftKindV3 = "reaction-lift/v1alpha3"

// signedLiftMembersV3 is every member of a v1alpha3 lift, each required.
var signedLiftMembersV3 = []string{
	memberKind, memberAlg, memberKeyID, memberPlaneID, memberListHead, memberScope, memberSubject, memberThrough,
	memberTenantID, memberProjectID, memberFile,
}

// SignedLiftV3 is the body of a v1alpha3 lift: it ends every stop of one
// scope and subject up to and including one line of the list whose head
// digest it names, on one plane's stop list file.
type SignedLiftV3 struct {
	KeyID, PlaneID, ListHead, Scope, Subject string
	ThroughLine                              int64
	TenantID, Project, File                  string
}

// Payload is l's canonical body, the bytes an operator signs, refused
// unless it reads back as l.
func (l SignedLiftV3) Payload() ([]byte, error) {
	body, err := canon.Canonicalize(map[string]any{
		memberKind: SignedLiftKindV3, memberAlg: signedAlg, memberKeyID: l.KeyID, memberPlaneID: l.PlaneID,
		memberListHead: l.ListHead, memberScope: l.Scope, memberSubject: l.Subject, memberThrough: l.ThroughLine,
		memberTenantID: l.TenantID, memberProjectID: l.Project, memberFile: l.File,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLiftValue, canon.ErrUnsupportedValue)
	}
	back, err := readSignedLiftV3(body)
	if err != nil {
		return nil, err
	}
	if back != l {
		return nil, ErrLiftNotCanonical
	}
	return body, nil
}

// readSignedLiftV3 reads a v1alpha3 lift's body, which signedBody holds to
// MaxSignedBytes. Its scope is one the grammar names, and its subject an
// identifier within its scope's bound: a missing or empty one ends nothing.
func readSignedLiftV3(body []byte) (SignedLiftV3, error) {
	refusals := docRefusals{json: ErrLiftJSON, repeated: ErrLiftRepeated, kind: ErrLiftKind, member: ErrLiftMember}
	o, err := readDoc(body, SignedLiftKindV3, refusals, signedLiftMembersV3, signedLiftMembersV3)
	if err != nil {
		return SignedLiftV3{}, err
	}
	var l SignedLiftV3
	var ok bool
	for _, f := range [...]struct {
		name  string
		limit int
		into  *string
	}{
		{memberKeyID, MaxListIDBytes, &l.KeyID},
		{memberTenantID, MaxTenantIDBytes, &l.TenantID}, {memberProjectID, MaxProjectIDBytes, &l.Project},
	} {
		if *f.into, ok = identifier(o[f.name], f.limit); !ok {
			return SignedLiftV3{}, fmt.Errorf("%w: %s", ErrLiftValue, f.name)
		}
	}
	if l.PlaneID, ok = planeIdentifier(o[memberPlaneID]); !ok {
		return SignedLiftV3{}, fmt.Errorf("%w: %s", ErrLiftValue, memberPlaneID)
	}
	if l.Scope, l.Subject, err = liftTarget(o); err != nil {
		return SignedLiftV3{}, err
	}
	if l.ListHead, ok = strictjson.String(o[memberListHead]); !ok || !canon.ValidDigest(l.ListHead) {
		return SignedLiftV3{}, fmt.Errorf("%w: %s", ErrLiftValue, memberListHead)
	}
	if l.File, ok = boundFile(o[memberFile]); !ok {
		return SignedLiftV3{}, fmt.Errorf("%w: %s", ErrLiftValue, memberFile)
	}
	if l.ThroughLine, ok = integer(o[memberThrough], 1, policy.MaxSerial); !ok {
		return SignedLiftV3{}, ErrLiftLine
	}
	if alg, isString := strictjson.String(o[memberAlg]); !isString || alg != signedAlg {
		return SignedLiftV3{}, fmt.Errorf("%w: %s", ErrLiftValue, memberAlg)
	}
	return l, nil
}

// liftTarget is a lift's scope, one the grammar names, and its subject, an
// identifier within that scope's bound.
func liftTarget(o strictjson.Object) (scope, subject string, err error) {
	scope, ok := readScope(o[memberScope])
	if !ok {
		return "", "", fmt.Errorf("%w: %s", ErrLiftValue, memberScope)
	}
	if subject, ok = identifier(o[memberSubject], subjectBound(scope)); !ok {
		return "", "", fmt.Errorf("%w: %s", ErrLiftValue, memberSubject)
	}
	return scope, subject, nil
}

// verifySignedLiftLineV3 is verifySignedLiftLine for a 3.0 lift line under a
// v1alpha3 route: the signed scope, subject and line are l's, the list head
// h's, the tenant and project r's, and the plane and file are the plane's.
// A v1alpha2 lift's body is ErrLiftUpgrade.
func verifySignedLiftLineV3(ctx context.Context, l LiftLine, h Header, r Route) (Signer, binding, error) {
	body, err := signedBody(l.Envelope, SignedLiftPayloadType)
	if err != nil {
		return Signer{}, binding{}, fmt.Errorf("%w: %w", ErrLiftUnsigned, err)
	}
	signed, err := readSignedLiftV3(body)
	if err != nil {
		if _, old := readSignedLift(body); old == nil {
			return Signer{}, binding{}, ErrLiftUpgrade
		}
		return Signer{}, binding{}, fmt.Errorf("%w: %w", ErrLiftUnsigned, err)
	}
	if signed.Scope != l.Scope || signed.Subject != l.Subject || signed.ThroughLine != l.ThroughLine ||
		signed.ListHead != h.Signed.Digest || signed.TenantID != r.tenantID || signed.Project != r.projectID {
		return Signer{}, binding{}, ErrSignedLiftMismatch
	}
	b := binding{format: r.format, plane: signed.PlaneID, tenant: signed.TenantID, project: signed.Project, file: signed.File}
	who, err := vouchedWithin(ctx, r.voucher, VouchLift, l.Envelope, b)
	if err != nil {
		return Signer{}, binding{}, fmt.Errorf("%w: %w", ErrSignedLiftUnvouched, err)
	}
	return who, b, nil
}
