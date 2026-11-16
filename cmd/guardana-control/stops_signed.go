package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/guardana/control/internal/brand"
	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// rosterRoute reads the route an operator signed at path, which routeFlag
// named, and verifies it with verify against the roster at roster, verified
// under the trust root at rootKey and usable now, for the plane of the
// route's tenant and project whose route file is path and whose stop list is
// in dir; note names the roster. The plane's id is planeID, or with none the
// one the route names: a v1alpha2 route names none and is refused, naming
// the command that upgrades it, unless the caller vouches for its plane.
func rosterRoute(routeFlag, path, roster, rootKey, dir, planeID string, note *rosterNote,
	verify func(reaction.Envelope, reaction.Voucher) (reaction.Route, error)) (reaction.Route, error) {
	raw, err := ondisk.ReadRegular(path, reaction.MaxRouteFileBytes, 0)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	env, err := reaction.ParseRouteFile(raw)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	if env.PayloadType != reaction.SignedRoutePayloadType {
		return reaction.Route{}, fmt.Errorf("%s %s: not a route an operator signed; a v1alpha1 route is verified with --public-key", routeFlag, path)
	}
	claimed, err := reaction.ParseRoute(env.Payload)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	if planeID == "" {
		if claimed.Format() != reaction.FormatV1Alpha3 {
			return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, reaction.ErrRouteUpgrade)
		}
		planeID = claimed.PlaneID()
	}
	doc, err := readRoster(roster, rootKey, note)
	if err != nil {
		return reaction.Route{}, err
	}
	plane, err := signedstops.PlaneOf(planeID, claimed.TenantID(), claimed.ProjectID(), path, dir, stoplist.FileName)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	v, err := signedstops.NewRoster(doc, plane)
	if err != nil {
		return reaction.Route{}, err
	}
	r, err := verify(env, v)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	return r, nil
}

// readOperatorKey reads the operator's private key at path, kept for the
// command's life and cleared by release.
func readOperatorKey(path string) (ed25519.PrivateKey, func(), error) {
	key, err := policykey.ReadPrivate(path)
	if err != nil {
		return nil, nil, fmt.Errorf("--key: %w", err)
	}
	return key, func() { clear(key) }, nil
}

// headerSigner is the signer of a 3.0 header over key.
func headerSigner(key ed25519.PrivateKey) stopwrite.Signer {
	return stopwrite.Signer{KeyID: policykey.KeyID(publicHalf(key)), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key)
	}}
}

// headerSignedLine is what a signed header says it signed, on standard
// error.
func headerSignedLine(command string, h reaction.Header) string {
	s := h.Signed
	previous := "none"
	if s.Previous != "" {
		previous = s.Previous
	}
	return fmt.Sprintf("%s: %s: signed list header %s serial %d for plane %s tenant %s project %s of %s, route %s serial %d, previous head %s",
		brand.CLI, command, oneLine(h.ListID), s.Serial, oneLine(s.PlaneID), oneLine(s.TenantID), oneLine(s.ProjectID), oneLine(s.File),
		oneLine(h.RouteID), h.RouteSerial, previous)
}

// stopsInitSigned starts a 3.0 list in dir under a v1alpha3 route, or
// carries the list in --carry, a 2.0 list of a v1alpha2 route or a 3.0 list,
// into it. A carry judges the old list, its header and every lift through
// the roster, for the new route's plane, which the operator vouches the old
// list is, before its stops are signed again under the new header. Each says
// on standard error what it signed.
func stopsInitSigned(a stopsInitArgs, dir string, now time.Time, stdout, stderr io.Writer) int {
	note := &rosterNote{w: stderr, command: stopsInitName}
	route, err := a.verified(dir, note)
	if err != nil {
		return fail(stderr, stopsInitName, err)
	}
	var from reaction.Route
	if a.carry != "" {
		if from, err = rosterRoute("--carry-route", a.carryRoute, a.roster, a.rootKey, a.carry, route.PlaneID(), note,
			reaction.VerifySignedCarrySource); err != nil {
			return fail(stderr, stopsInitName, err)
		}
	}
	key, release, err := readOperatorKey(a.key)
	if err != nil {
		return fail(stderr, stopsInitName, err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), stopsLockWait)
	defer cancel()
	if a.carry == "" {
		h, err := stopwrite.InitSigned(ctx, dir, route, now, headerSigner(key), a.serial)
		if err != nil {
			return fail(stderr, stopsInitName, err)
		}
		writeLine(stderr, headerSignedLine(stopsInitName, h))
		return emit(stdout, stderr, stopsInitName, headerLines(h), dir)
	}
	hold, err := carryHold(a.stopsFloor, from, stderr)
	if err != nil {
		return fail(stderr, stopsInitName, err)
	}
	c, err := stopwrite.CarrySigned(ctx, a.carry, from, dir, route, now, headerSigner(key), hold)
	if err != nil {
		return fail(stderr, stopsInitName, err)
	}
	writeLine(stderr, headerSignedLine(stopsInitName, c.Header))
	lines := append(headerLines(c.Header), "stops: "+strconv.Itoa(c.Stops), "covered: "+strconv.Itoa(c.Covered))
	if c.LeftOut > 0 {
		lines = append(lines, fmt.Sprintf("left out: the last %d line(s) of the old list, from %s", c.LeftOut, oneLine(c.Refused.Error())))
	}
	return emit(stdout, stderr, stopsInitName, lines, dir)
}

// carryHold is what a signed carry holds the old list to: the stop list
// floor in floorDir of the old route's tenant and project, read once, which
// refuses a list cut back below the part the plane accepted. With no
// floorDir it says on stderr that the floor was not read, and holds nothing.
func carryHold(floorDir string, from reaction.Route, stderr io.Writer) (func(reaction.List, []byte) error, error) {
	if floorDir == "" {
		writeLine(stderr, brand.CLI+": "+stopsInitName+": the plane's stop list floor was not read (--stops-floor), "+
			"so a list cut back since the plane read it is carried as it stands")
		return nil, nil
	}
	stored, err := policystate.ReadStops(floorDir, from.TenantID(), from.ProjectID())
	if err != nil {
		return nil, fmt.Errorf("--stops-floor %s: %w", floorDir, err)
	}
	return func(l reaction.List, content []byte) error { return signedstops.Hold(stored, l, content) }, nil
}

func stopsFloorInitFlags(command string, out io.Writer) (*flag.FlagSet, *string, *string) {
	flags := commandFlags(command, out)
	tenant := flags.String("tenant", "", "the plane's tenant_id")
	project := flags.String("project", "", "the plane's project_id")
	return flags, tenant, project
}

func stopsFloorInitFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _, _ := stopsFloorInitFlags(command, out)
	return flags
}

// stopsFloorInitCommand makes a directory the stop list floor of a plane of
// one tenant and project, with no serial yet, and never replaces one.
func stopsFloorInitCommand(args []string, stdout, stderr io.Writer) int {
	flags, tenant, project := stopsFloorInitFlags(stopsFloorInitName, stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 || *tenant == "" || *project == "" {
		return usageError(stderr, stopsFloorInitName, "takes --tenant and --project, then one directory, with every flag before it")
	}
	ctx, cancel := context.WithTimeout(context.Background(), floorLockWait)
	defer cancel()
	if err := policystate.InitStops(ctx, flags.Arg(0), *tenant, *project); err != nil {
		return fail(stderr, stopsFloorInitName, err)
	}
	return writeFloorLines(stdout, stderr, stopsFloorInitName,
		"tenant: "+oneLine(*tenant)+"\nproject: "+oneLine(*project)+"\nfloor: no serial\n", "the floor file was made as asked")
}

// errPlaneAccount is react run as the plane's account under the signed
// authority, where the stops it writes would be the plane's own to rewrite.
var errPlaneAccount = errors.New("this process runs as the account that owns the approvals directory, which is the plane's; " +
	"under the signed authority run react as the stop writers' own account")
