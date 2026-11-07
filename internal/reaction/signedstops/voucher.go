// Package signedstops judges the signed stop formats for a plane under the
// signed authority: the route, the stop list's header and the lifts an
// operator signs, through the operator ports over the trust roster or through
// a roster the caller verified, and the stop list floor. It is apart from
// package reaction so that the judge links no operator port and no file.
package signedstops

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/trust"
)

// Error is a refusal by this package, matched with errors.Is.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The refusals of this package.
const (
	ErrOptions         Error = "signedstops: a voucher needs its ports or roster, a tenant, a project and both files"
	ErrUnauthenticated Error = "signedstops: no operator key of the roster signed the document for its act"
	ErrUnauthorized    Error = "signedstops: the operator holds no grant over the plane's tenant and project at the act's level"
	ErrAuthority       Error = "signedstops: the operator ports could not answer"
	ErrKind            Error = "signedstops: not a signed stop format"
)

// rule is the act a signed kind is signed under, its payload type and the
// level a grant needs to permit it.
type rule struct {
	act         operators.Act
	payloadType string
	level       trust.Level
}

var rules = map[reaction.SignedKind]rule{
	reaction.VouchRoute:  {operators.ActRoute, reaction.SignedRoutePayloadType, trust.LevelAdmin},
	reaction.VouchHeader: {operators.ActStops, reaction.SignedHeaderPayloadType, trust.LevelOperate},
	reaction.VouchLift:   {operators.ActLift, reaction.SignedLiftPayloadType, trust.LevelOperate},
}

// BindingOf is the path a signed document names for the file at path:
// absolute and clean, with every link on the way to its directory resolved,
// so a writer and a plane that spell one file two ways bind it alike.
func BindingOf(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

// PlaneOf is the plane of tenant and project whose route file and stop list
// directory are routeFile and stopsDir, each bound as BindingOf says.
func PlaneOf(tenant, project, routeFile, stopsDir, listName string) (reaction.Plane, error) {
	if tenant == "" || project == "" || routeFile == "" || stopsDir == "" {
		return reaction.Plane{}, ErrOptions
	}
	route, err := BindingOf(routeFile)
	if err != nil {
		return reaction.Plane{}, fmt.Errorf("the route file: %w", err)
	}
	list, err := BindingOf(filepath.Join(stopsDir, listName))
	if err != nil {
		return reaction.Plane{}, fmt.Errorf("the stop list: %w", err)
	}
	return reaction.Plane{Tenant: tenant, Project: project, RouteFile: route, ListFile: list}, nil
}

// Ports vouches through a plane's operator ports: the authenticator for the
// act, then the authorizer over the plane's tenant and project. Each call is
// held to the ports' own bounds.
type Ports struct {
	authn operators.Authenticator
	authz operators.Authorizer
	plane reaction.Plane
}

var _ reaction.ContextVoucher = (*Ports)(nil)

// NewPorts is the voucher over authn and authz for plane, or ErrOptions.
func NewPorts(authn operators.Authenticator, authz operators.Authorizer, plane reaction.Plane) (*Ports, error) {
	if authn == nil || authz == nil || !complete(plane) {
		return nil, ErrOptions
	}
	return &Ports{authn: authn, authz: authz, plane: plane}, nil
}

// Plane is the plane the voucher judges for.
func (p *Ports) Plane() reaction.Plane { return p.plane }

// Vouch authenticates env for kind's act and authorizes its signer over the
// plane's tenant and project. An unavailable answer is ErrAuthority, never a
// refusal a retry could turn into a pass.
func (p *Ports) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	return p.VouchContext(context.Background(), kind, env)
}

// VouchContext is Vouch with each call to the ports held to ctx: one that
// ends before they answer is ErrAuthority.
func (p *Ports) VouchContext(ctx context.Context, kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	r, ok := rules[kind]
	if !ok {
		return reaction.Signer{}, ErrKind
	}
	who := p.authn.Authenticate(ctx, r.act, env)
	switch who.State() {
	case operators.AuthAuthenticated:
	case operators.AuthRefused:
		return reaction.Signer{}, fmt.Errorf("%w: %s", ErrUnauthenticated, who.Cause())
	default:
		return reaction.Signer{}, fmt.Errorf("%w: %w: the authenticator: %s", ErrAuthority, reaction.ErrUnanswered, who.Cause())
	}
	perm := p.authz.Authorize(ctx, who, operators.Request{Act: r.act, Tenant: p.plane.Tenant, Project: p.plane.Project})
	switch perm.State() {
	case operators.PermPermitted:
	case operators.PermDenied:
		return reaction.Signer{}, fmt.Errorf("%w: %s", ErrUnauthorized, perm.Cause())
	default:
		return reaction.Signer{}, fmt.Errorf("%w: %w: the authorizer: %s", ErrAuthority, reaction.ErrUnanswered, perm.Cause())
	}
	return reaction.Signer{Subject: who.Subject(), KeyID: who.KeyID()}, nil
}

// Roster vouches with a roster the caller verified under its trust root, as
// the plane's ports would answer short of asking the roster again: for a
// writer that judges what it signs over and for doctor.
type Roster struct {
	doc   trust.Document
	plane reaction.Plane
}

var _ reaction.Voucher = Roster{}

// NewRoster is the voucher over doc for plane, or ErrOptions.
func NewRoster(doc trust.Document, plane reaction.Plane) (Roster, error) {
	if !complete(plane) {
		return Roster{}, ErrOptions
	}
	return Roster{doc: doc, plane: plane}, nil
}

// Plane is the plane the voucher judges for.
func (r Roster) Plane() reaction.Plane { return r.plane }

// Vouch is the subject of the operator key of the roster that signed env for
// kind, holding a grant over the plane's tenant and project at kind's level.
func (r Roster) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	ru, ok := rules[kind]
	if !ok {
		return reaction.Signer{}, ErrKind
	}
	if len(env.Signatures) != 1 || env.PayloadType != ru.payloadType {
		return reaction.Signer{}, fmt.Errorf("%w: not one signature of the act's payload type", ErrUnauthenticated)
	}
	sig := env.Signatures[0]
	keys := r.doc.Keys()
	i := slices.IndexFunc(keys, func(k trust.Key) bool { return k.ID() == sig.KeyID })
	if i < 0 || keys[i].Role() != trust.RoleOperator {
		return reaction.Signer{}, fmt.Errorf("%w: the roster names no operator key %s", ErrUnauthenticated, sig.KeyID)
	}
	key := keys[i]
	if err := key.Verify(ru.payloadType, env.Payload, sig.Signature); err != nil {
		return reaction.Signer{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if !slices.ContainsFunc(key.Grants(), func(g trust.Grant) bool {
		return g.Tenant == r.plane.Tenant && g.Project == r.plane.Project && g.Level >= ru.level
	}) {
		return reaction.Signer{}, fmt.Errorf("%w: %s", ErrUnauthorized, key.Subject())
	}
	return reaction.Signer{Subject: key.Subject(), KeyID: key.ID()}, nil
}

func complete(p reaction.Plane) bool {
	return p.Tenant != "" && p.Project != "" && p.RouteFile != "" && p.ListFile != ""
}

// IsUnavailable reports whether err is the ports' unavailability rather than
// a refusal of the document.
func IsUnavailable(err error) bool { return errors.Is(err, ErrAuthority) }
