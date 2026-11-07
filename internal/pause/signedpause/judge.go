// Package signedpause judges a signed pause file for a plane under the
// signed authority: through the operator ports over its trust roster, against
// its own tenant and project, and above its pause floor. It is apart from
// package pause so that a reader of the pause file, the console among them,
// links no operator port and no key reader.
package signedpause

import (
	"context"
	"errors"
	"fmt"

	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policystate"
)

// Authority is a plane's judge of its signed pause file: the operator ports,
// the plane's tenant and project, and the pause floor directory its account
// owns.
type Authority struct {
	authn           operators.Authenticator
	authz           operators.Authorizer
	tenant, project string
	file, floorDir  string
}

var _ pause.Judge = (*Authority)(nil)

// New is the judge over authn and authz for tenant and project and the
// pause file at file, raising the floor in floorDir, or pause.ErrOptions
// where any of them is missing.
func New(authn operators.Authenticator, authz operators.Authorizer, tenant, project, file, floorDir string) (*Authority, error) {
	if authn == nil || authz == nil || tenant == "" || project == "" || file == "" || floorDir == "" {
		return nil, pause.ErrOptions
	}
	bound, err := pause.BindingOf(file)
	if err != nil {
		return nil, err
	}
	return &Authority{authn: authn, authz: authz, tenant: tenant, project: project, file: bound, floorDir: floorDir}, nil
}

// Judge takes f through the authenticator, the plane's tenant, project and
// pause file, the authorizer and the floor, in that order, so the floor is raised only
// for a document every other step took.
func (a *Authority) Judge(ctx context.Context, f pause.Signed) (pause.SignedBy, error) {
	who := a.authn.Authenticate(ctx, operators.ActPause, f.Envelope)
	switch who.State() {
	case operators.AuthAuthenticated:
	case operators.AuthRefused:
		return pause.SignedBy{}, fmt.Errorf("%w: %s", pause.ErrUnauthenticated, who.Cause())
	default:
		return pause.SignedBy{}, fmt.Errorf("%w: the authenticator: %s", pause.ErrAuthority, who.Cause())
	}
	h := f.Body.Header
	if h.Tenant != a.tenant || h.Project != a.project {
		return pause.SignedBy{}, pause.ErrOtherScope
	}
	if h.File != a.file {
		return pause.SignedBy{}, fmt.Errorf("%w: it names %s, and this plane reads %s", pause.ErrOtherFile, h.File, a.file)
	}
	perm := a.authz.Authorize(ctx, who, operators.Request{Act: operators.ActPause, Tenant: a.tenant, Project: a.project})
	switch perm.State() {
	case operators.PermPermitted:
	case operators.PermDenied:
		return pause.SignedBy{}, fmt.Errorf("%w: %s", pause.ErrUnauthorized, perm.Cause())
	default:
		return pause.SignedBy{}, fmt.Errorf("%w: the authorizer: %s", pause.ErrAuthority, perm.Cause())
	}
	floor, err := policystate.RaisePause(ctx, a.floorDir, a.tenant, a.project, h.Serial, f.Body.Digest)
	switch {
	case errors.Is(err, policystate.ErrPauseBelowFloor):
		return pause.SignedBy{}, fmt.Errorf("%w: %w", pause.ErrBelowFloor, err)
	case errors.Is(err, policystate.ErrPauseForked):
		return pause.SignedBy{}, fmt.Errorf("%w: %w", pause.ErrForked, err)
	case err != nil:
		return pause.SignedBy{}, fmt.Errorf("%w: %w", pause.ErrFloor, err)
	}
	return pause.SignedBy{Subject: who.Subject(), KeyID: who.KeyID(), Serial: h.Serial, Floor: floor.Serial}, nil
}
