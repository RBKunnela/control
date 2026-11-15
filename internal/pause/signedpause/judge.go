// Package signedpause judges a signed pause file for a plane under the
// signed authority: through the operator ports over its trust roster, against
// its own id, tenant, project and pause file, and above its pause floor. It is apart from
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
	"github.com/guardana/control/internal/trust"
)

// Binding is what a signed pause file has to name to be one plane's: the
// plane's id, its tenant and project, and its pause file as BindingOf binds
// it. The plane's judge and doctor hold a file to the same Binding.
type Binding struct {
	plane, tenant, project, file string
}

// NewBinding is the binding of the plane planeID of tenant and project that
// reads the pause file at file, or pause.ErrOptions where any is missing.
func NewBinding(planeID, tenant, project, file string) (Binding, error) {
	if planeID == "" || tenant == "" || project == "" || file == "" {
		return Binding{}, pause.ErrOptions
	}
	bound, err := pause.BindingOf(file)
	if err != nil {
		return Binding{}, err
	}
	return Binding{plane: planeID, tenant: tenant, project: project, file: bound}, nil
}

// Check refuses h unless it names b's tenant and project, with
// pause.ErrOtherScope, b's plane, with pause.ErrOtherPlane, and b's pause
// file, with pause.ErrOtherFile. An empty plane id on either side is never
// the same plane.
func (b Binding) Check(h pause.Header) error {
	switch {
	case h.Tenant != b.tenant || h.Project != b.project:
		return pause.ErrOtherScope
	case h.PlaneID == "" || b.plane == "" || h.PlaneID != b.plane:
		return fmt.Errorf("%w: it names plane %q, and this plane is %q", pause.ErrOtherPlane, h.PlaneID, b.plane)
	case h.File != b.file:
		return fmt.Errorf("%w: it names %s, and this plane reads %s", pause.ErrOtherFile, h.File, b.file)
	}
	return nil
}

// Vouched is the subject Vouched names for f once b checked its header:
// what the plane's judge decides short of its floor, for a check that may
// not raise one.
func (b Binding) Vouched(roster trust.Document, f pause.Signed) (string, error) {
	if err := b.Check(f.Body.Header); err != nil {
		return "", err
	}
	return Vouched(roster, f)
}

// Authority is a plane's judge of its signed pause file: the operator ports,
// the plane's binding, and the pause floor directory its account owns.
type Authority struct {
	authn    operators.Authenticator
	authz    operators.Authorizer
	binding  Binding
	floorDir string
}

var _ pause.Judge = (*Authority)(nil)

// New is the judge over authn and authz for the plane planeID of tenant and
// project and the pause file at file, raising the floor in floorDir, or
// pause.ErrOptions where any of them is missing.
func New(authn operators.Authenticator, authz operators.Authorizer, planeID, tenant, project, file, floorDir string) (*Authority, error) {
	if authn == nil || authz == nil || floorDir == "" {
		return nil, pause.ErrOptions
	}
	b, err := NewBinding(planeID, tenant, project, file)
	if err != nil {
		return nil, err
	}
	return &Authority{authn: authn, authz: authz, binding: b, floorDir: floorDir}, nil
}

// Judge takes f through the authenticator, the plane's binding, the
// authorizer and the floor, in that order, so the floor is raised only for a
// document every other step took.
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
	if err := a.binding.Check(h); err != nil {
		return pause.SignedBy{}, err
	}
	b := a.binding
	perm := a.authz.Authorize(ctx, who, operators.Request{Act: operators.ActPause, Tenant: b.tenant, Project: b.project})
	switch perm.State() {
	case operators.PermPermitted:
	case operators.PermDenied:
		return pause.SignedBy{}, fmt.Errorf("%w: %s", pause.ErrUnauthorized, perm.Cause())
	default:
		return pause.SignedBy{}, fmt.Errorf("%w: the authorizer: %s", pause.ErrAuthority, perm.Cause())
	}
	floor, err := policystate.RaisePause(ctx, a.floorDir, b.tenant, b.project, h.Serial, f.Body.Digest)
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
