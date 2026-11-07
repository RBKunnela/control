// Package signedruns judges a signed run record: for a plane under the
// signed authority through the operator ports over its trust roster and
// against its own tenant and project, and for an operator command or a check
// against a verified roster document. It is apart from package runs so that
// a reader of runs, the console among them, links no operator port.
package signedruns

import (
	"context"
	"fmt"
	"slices"

	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/trust"
)

// Authority is a plane's judge of the records of its signed runs directory:
// the operator ports and the plane's tenant and project.
type Authority struct {
	authn           operators.Authenticator
	authz           operators.Authorizer
	tenant, project string
}

var _ runs.Judge = (*Authority)(nil)

// New is the judge over authn and authz for tenant and project, or
// runs.ErrUnjudged where any of them is missing.
func New(authn operators.Authenticator, authz operators.Authorizer, tenant, project string) (*Authority, error) {
	if authn == nil || authz == nil || tenant == "" || project == "" {
		return nil, fmt.Errorf("%w: the judge lacks an operator port, a tenant or a project", runs.ErrUnjudged)
	}
	return &Authority{authn: authn, authz: authz, tenant: tenant, project: project}, nil
}

// Judge takes r through the authenticator, the plane's tenant and project
// and the authorizer, in that order.
func (a *Authority) Judge(ctx context.Context, r runs.SignedRecord) (runs.SignedBy, error) {
	if a == nil {
		return runs.SignedBy{}, runs.ErrUnjudged
	}
	who := a.authn.Authenticate(ctx, operators.ActRun, r.Envelope)
	switch who.State() {
	case operators.AuthAuthenticated:
	case operators.AuthRefused:
		return runs.SignedBy{}, fmt.Errorf("%w: %s", runs.ErrUnauthenticated, who.Cause())
	default:
		return runs.SignedBy{}, fmt.Errorf("%w: the authenticator: %s", runs.ErrAuthority, who.Cause())
	}
	if r.Record.Who.TenantID != a.tenant || r.Record.Who.ProjectID != a.project {
		return runs.SignedBy{}, runs.ErrOtherScope
	}
	perm := a.authz.Authorize(ctx, who, operators.Request{Act: operators.ActRun, Tenant: a.tenant, Project: a.project})
	switch perm.State() {
	case operators.PermPermitted:
	case operators.PermDenied:
		return runs.SignedBy{}, fmt.Errorf("%w: %s", runs.ErrUnauthorized, perm.Cause())
	default:
		return runs.SignedBy{}, fmt.Errorf("%w: the authorizer: %s", runs.ErrAuthority, perm.Cause())
	}
	return runs.SignedBy{Subject: who.Subject(), KeyID: who.KeyID()}, nil
}

// Roster is the judge of a roster document the caller verified and found
// usable: an operator key of it signed the record, granted operate or admin
// over the record's tenant and project, which have to be Tenant and Project
// where those are set.
type Roster struct {
	Document        trust.Document
	Tenant, Project string
}

var _ runs.Judge = Roster{}

// Judge checks r as the plane's authenticator and authorizer would, with
// the roster the document holds.
func (j Roster) Judge(_ context.Context, r runs.SignedRecord) (runs.SignedBy, error) {
	who := r.Record.Who
	if (j.Tenant != "" && who.TenantID != j.Tenant) || (j.Project != "" && who.ProjectID != j.Project) {
		return runs.SignedBy{}, fmt.Errorf("%w: tenant %q project %q", runs.ErrOtherScope, who.TenantID, who.ProjectID)
	}
	key, err := j.signer(r)
	if err != nil {
		return runs.SignedBy{}, err
	}
	if !slices.ContainsFunc(key.Grants(), func(g trust.Grant) bool {
		return g.Tenant == who.TenantID && g.Project == who.ProjectID && g.Level >= trust.LevelOperate
	}) {
		return runs.SignedBy{}, fmt.Errorf("%w: %s", runs.ErrUnauthorized, key.Subject())
	}
	return runs.SignedBy{Subject: key.Subject(), KeyID: key.ID()}, nil
}

// signer is the operator key of the roster whose signature r carries, or
// runs.ErrUnauthenticated.
func (j Roster) signer(r runs.SignedRecord) (trust.Key, error) {
	if len(r.Envelope.Signatures) != 1 || r.Envelope.PayloadType != operators.RunPayloadType {
		return trust.Key{}, fmt.Errorf("%w: not one signature under %s", runs.ErrUnauthenticated, operators.RunPayloadType)
	}
	sig := r.Envelope.Signatures[0]
	keys := j.Document.Keys()
	i := slices.IndexFunc(keys, func(k trust.Key) bool { return k.ID() == sig.KeyID })
	if i < 0 || keys[i].Role() != trust.RoleOperator || keys[i].Alg() != trust.AlgEd25519 {
		return trust.Key{}, fmt.Errorf("%w: the roster names no operator key %s", runs.ErrUnauthenticated, sig.KeyID)
	}
	if err := keys[i].Verify(operators.RunPayloadType, r.Envelope.Payload, sig.Signature); err != nil {
		return trust.Key{}, fmt.Errorf("%w: %w", runs.ErrUnauthenticated, err)
	}
	return keys[i], nil
}
