package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// stopListRead is how a plane reads its stop list: whose account owns it,
// and what each read it accepts is held to.
type stopListRead struct {
	owner stoplist.Owner
	take  func(reaction.List, []byte) error
}

// stopsAuthority is what a serving plane under the signed authority takes
// its route, its list's header and its lifts through: the voucher over its
// operator ports, its stop list floor, and whether files its own account
// owns are taken, which only a dev or test plane allows.
type stopsAuthority struct {
	voucher    reaction.Voucher
	floor      signedstops.Floor
	planeOwned bool
}

// read is the signed read: a list another account owns, unless planeOwned,
// whose header and accepted part are held to the floor at every read and
// raise it each time the part grows.
func (a *stopsAuthority) read() stopListRead {
	owner := stoplist.OwnedByAnother
	if a.planeOwned {
		owner = stoplist.AnyOwner
	}
	return stopListRead{owner: owner, take: func(l reaction.List, content []byte) error {
		ctx, cancel := context.WithTimeout(context.Background(), floorLockWait)
		defer cancel()
		_, err := a.floor.Take(ctx, l, content)
		return err
	}}
}

// signedStops reports whether cfg's route is read under the signed
// authority, which needs the operator ports before it can be opened.
func signedStops(cfg *gatewayconfig.Config) bool {
	return cfg.Reaction.Configured() && cfg.Approvals.Authority == gatewayconfig.AuthoritySigned
}

// stopsPlane is the plane cfg's signed documents are bound to: the tenant
// the listener serves, which the route names, and the project. The stop list
// floor is kept for the same tenant and project.
func stopsPlane(cfg *gatewayconfig.Config) (reaction.Plane, error) {
	plane, err := signedstops.PlaneOf(cfg.ListenerTenant(), cfg.ProjectID, cfg.Resolve(cfg.Reaction.Route),
		cfg.Resolve(cfg.Reaction.Stops), stoplist.FileName)
	if err != nil {
		return reaction.Plane{}, fmt.Errorf("reaction: %w", err)
	}
	return plane, nil
}

// stopsAuthority is what a serving plane under the signed authority judges
// its route, list and lifts by: its operator ports and its stop list floor.
func (p *plane) stopsAuthority() (*stopsAuthority, error) {
	plane, err := stopsPlane(p.cfg)
	if err != nil {
		return nil, err
	}
	v, err := signedstops.NewPorts(p.signed.authn, p.signed.authz, plane)
	if err != nil {
		return nil, fmt.Errorf("reaction: %w", err)
	}
	floor, err := signedstops.NewFloor(p.cfg.Resolve(p.cfg.Reaction.StopsFloorDir), plane.Tenant, plane.Project)
	if err != nil {
		return nil, fmt.Errorf("reaction.stops_floor_dir: %w", err)
	}
	return &stopsAuthority{voucher: v, floor: floor, planeOwned: p.signedStart != nil}, nil
}

// readSignedRoute reads the route file as a v1alpha2 route an operator
// signed, judged through v, and holds it to the configuration. The file and
// its directory may not be owned by the plane's account unless planeOwned.
func readSignedRoute(cfg *gatewayconfig.Config, v reaction.Voucher, planeOwned bool) (reaction.Route, error) {
	path := cfg.Resolve(cfg.Reaction.Route)
	if !planeOwned {
		if err := notPlaneOwned(path); err != nil {
			return reaction.Route{}, fmt.Errorf("reaction.route: %w", err)
		}
	}
	raw, err := readBounded(path, reaction.MaxRouteFileBytes)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.route: %w", err)
	}
	env, err := reaction.ParseRouteFile(raw)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.route: %w", err)
	}
	route, err := reaction.VerifySignedRoute(env, v)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.route: %w", err)
	}
	if err := cfg.CheckRoute(route, nil); err != nil {
		return reaction.Route{}, err
	}
	return route, nil
}

// errPlaneOwnedRoute is a route file, or its directory, the plane's own
// account owns under the signed authority, which that account could replace.
var errPlaneOwnedRoute = errors.New("under the signed authority the plane's own account owns it")

// notPlaneOwned refuses path, or its directory, when the plane's own account
// owns it.
func notPlaneOwned(path string) error {
	for _, p := range []string{path, filepath.Dir(path)} {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		err = ondisk.CheckOwnedBy(info, os.Geteuid())
		switch {
		case err == nil:
			return fmt.Errorf("%s: %w", p, errPlaneOwnedRoute)
		case !errors.Is(err, ondisk.ErrOwner):
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

// signedRoute is what doctor reads under the signed authority: the route
// judged against the roster file verified under the trust root, and the
// list read as signedListRead says.
func (d *examination) signedRoute() (reaction.Route, stopListRead, error) {
	root, err := readRouteKey(d.cfg.Resolve(d.cfg.Trust.RootPublicKey))
	if err != nil {
		return reaction.Route{}, stopListRead{}, fmt.Errorf("trust.root_public_key: %w", err)
	}
	roster, err := d.roster(root)
	if err != nil {
		return reaction.Route{}, stopListRead{}, fmt.Errorf("trust.roster: %w", err)
	}
	plane, err := stopsPlane(d.cfg)
	if err != nil {
		return reaction.Route{}, stopListRead{}, err
	}
	v, err := signedstops.NewRoster(roster, plane)
	if err != nil {
		return reaction.Route{}, stopListRead{}, fmt.Errorf("reaction: %w", err)
	}
	route, err := readSignedRoute(d.cfg, v, doctorPlaneOwned)
	if err != nil {
		return reaction.Route{}, stopListRead{}, err
	}
	return route, d.signedListRead(), nil
}

// signedListRead reads the stop list as a signed plane does, refusing one
// its own account owns, held to the stop list floor, which is read and never
// raised.
func (d *examination) signedListRead() stopListRead {
	owner := stoplist.OwnedByAnother
	if doctorPlaneOwned {
		owner = stoplist.AnyOwner
	}
	dir := d.cfg.Resolve(d.cfg.Reaction.StopsFloorDir)
	return stopListRead{owner: owner, take: func(l reaction.List, content []byte) error {
		stored, err := policystate.ReadStops(dir, d.cfg.ListenerTenant(), d.cfg.ProjectID)
		if err != nil {
			return fmt.Errorf("reaction.stops_floor_dir: %w: %w", stoplist.ErrFloor, err)
		}
		return signedstops.Hold(stored, l, content)
	}}
}
