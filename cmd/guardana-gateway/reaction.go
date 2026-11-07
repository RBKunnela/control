package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"time"

	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// The route key's public key file holds one public key line: its 44 base64
// characters and a newline. A longer file is refused before it becomes a
// string, since it may be a private key given in the wrong place.
const (
	maxRouteKeyFileBytes = 1 << 10
	routeKeyLineBytes    = 44
)

// planeStops is what a serving plane stops runs under (ADR-0046): the route it
// verified at start, the route floor as the start left it, and the reader of
// its stop list.
type planeStops struct {
	route  reaction.Route
	floor  policystate.RouteFloor
	poller *stoplist.Poller
}

// stopSource is what the pipeline reads the stop state from: the stop list's
// reader where a route is configured, and the disabled source where none is.
func (p *plane) stopSource() gateway.StopSource {
	if p.stops == nil {
		return gateway.StopsDisabled()
	}
	return p.stops.poller
}

// openStops verifies the route a serving plane is configured with, opens the
// stop list's reader, whose first read has to find a state it can serve, and
// only then raises the route's floor under the floor directory's lock, so a
// start refused for its list leaves the floor as it was. A route below its
// floor, at it with another digest, or with no floor at all refuses the
// start; the floor is never created here. Without a route it returns nil.
//
// Under the signed authority the route is an operator's, taken through
// authority; the list is read as an operator's, each read it accepts is held
// to the stop list floor, and a part that grew raises it.
func openStops(cfg *gatewayconfig.Config, logger *slog.Logger, authority *stopsAuthority) (*planeStops, error) {
	if !cfg.Reaction.Configured() {
		return nil, nil
	}
	var (
		route reaction.Route
		err   error
		read  = stopListRead{owner: stoplist.OwnedByThisUser}
	)
	if authority == nil {
		route, err = readRoute(cfg)
	} else {
		route, err = readSignedRoute(cfg, authority.voucher, authority.planeOwned)
		read = authority.read()
	}
	if err != nil {
		return nil, err
	}
	poller, err := openStopList(cfg, route, logger, read)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), floorLockWait)
	defer cancel()
	floor, err := policystate.RaiseRoute(ctx, cfg.Resolve(cfg.Reaction.FloorDir), route.ID(), route.Serial(), route.Digest())
	if err != nil {
		return nil, fmt.Errorf("reaction.floor_dir: %w", err)
	}
	snap := poller.Current()
	logger.Info("the reaction route starts", "route_id", route.ID(), "serial", route.Serial(), "digest", route.Digest(),
		"floor", routeFloorText(floor), "list_id", snap.Header().ListID, "state", snap.State().String())
	return &planeStops{route: route, floor: floor, poller: poller}, nil
}

// openStopList opens the reader of the stop list judged against route, read
// as read says. With no floor to take it takes no lock and writes nothing,
// so doctor opens it too.
func openStopList(cfg *gatewayconfig.Config, route reaction.Route, logger *slog.Logger, read stopListRead) (*stoplist.Poller, error) {
	poller, err := stoplist.Open(stoplist.Options{
		Dir:      cfg.Resolve(cfg.Reaction.Stops),
		Route:    route,
		Interval: cfg.Reaction.PollInterval,
		Clock:    time.Now,
		Logger:   logger,
		Owner:    read.owner,
		Take:     read.take,
	})
	if err != nil {
		return nil, fmt.Errorf("reaction.stops: %w", err)
	}
	return poller, nil
}

// readRoute reads the route file and the route key the configuration names,
// verifies the route under that key, which refuses it whole when a rule it
// names may not stop a run, and holds it to the configuration: its tenant and
// the four keys apart.
func readRoute(cfg *gatewayconfig.Config) (reaction.Route, error) {
	raw, err := readBounded(cfg.Resolve(cfg.Reaction.Route), reaction.MaxRouteFileBytes)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.route: %w", err)
	}
	env, err := reaction.ParseRouteFile(raw)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.route: %w", err)
	}
	pub, err := readRouteKey(cfg.Resolve(cfg.Reaction.PublicKey))
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.public_key: %w", err)
	}
	route, err := reaction.VerifyRoute(env, pub)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.route: %w", err)
	}
	if err := cfg.CheckRoute(route, pub); err != nil {
		return reaction.Route{}, err
	}
	return route, nil
}

// readRouteKey reads a public key file of one key line.
func readRouteKey(path string) (ed25519.PublicKey, error) {
	line, err := ondisk.ReadRegular(path, maxRouteKeyFileBytes, 0)
	defer clear(line)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSuffix(line, []byte("\n"))) != routeKeyLineBytes {
		return nil, policykey.ErrPublicLine
	}
	return policykey.ParsePublic(string(line))
}

// routeAgainstFloor refuses, as RaiseRoute would, a route below the floor's
// serial or at it with another digest, without taking the lock or writing.
func routeAgainstFloor(f policystate.RouteFloor, r reaction.Route) error {
	switch {
	case r.Serial() < f.Serial:
		return fmt.Errorf("%w: serial %d, the floor's %d", policystate.ErrRouteBelowFloor, r.Serial(), f.Serial)
	case r.Serial() == f.Serial && r.Digest() != f.Digest:
		return fmt.Errorf("%w: serial %d", policystate.ErrRouteForked, r.Serial())
	}
	return nil
}

// routeFloorText is a route floor as the log and doctor print it.
func routeFloorText(f policystate.RouteFloor) string {
	if !f.HasSerial() {
		return "no serial yet"
	}
	return fmt.Sprintf("serial %d digest %s", f.Serial, f.Digest)
}
