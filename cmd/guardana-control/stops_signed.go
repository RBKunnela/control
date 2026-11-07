package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
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

// rosterRoute reads the v1alpha2 route at path, which routeFlag named, and
// verifies it with verify against the roster at roster, verified under the
// trust root at rootKey and usable now, for the plane of the route's tenant
// and project whose route file is path and whose stop list is in dir.
func rosterRoute(routeFlag, path, roster, rootKey, dir string, verify func(reaction.Envelope, reaction.Voucher) (reaction.Route, error)) (reaction.Route, error) {
	raw, err := ondisk.ReadRegular(path, reaction.MaxRouteFileBytes, 0)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	env, err := reaction.ParseRouteFile(raw)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	if env.PayloadType != reaction.SignedRoutePayloadType {
		return reaction.Route{}, fmt.Errorf("%s %s: not a v1alpha2 route an operator signed; a v1alpha1 route is verified with --public-key", routeFlag, path)
	}
	claimed, err := reaction.ParseRoute(env.Payload)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	doc, err := readRoster(roster, rootKey)
	if err != nil {
		return reaction.Route{}, err
	}
	plane, err := signedstops.PlaneOf(claimed.TenantID(), claimed.ProjectID(), path, dir, stoplist.FileName)
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

// headerSigner is the signer of a 2.0 header over key.
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
	return fmt.Sprintf("%s: %s: signed list header %s serial %d for tenant %s project %s of %s, route %s serial %d, previous head %s",
		brand.CLI, command, oneLine(h.ListID), s.Serial, oneLine(s.TenantID), oneLine(s.ProjectID), oneLine(s.File),
		oneLine(h.RouteID), h.RouteSerial, previous)
}

// stopsInitSigned starts a 2.0 list in dir under a v1alpha2 route, or
// carries the list in --carry into it. A carry judges the old list, its
// header and every lift through the roster, before its stops are signed
// again under the new header. Each says on standard error what it signed.
func stopsInitSigned(a stopsInitArgs, dir string, now time.Time, stdout, stderr io.Writer) int {
	route, err := a.verified(dir)
	if err != nil {
		return fail(stderr, stopsInitName, err)
	}
	var from reaction.Route
	if a.carry != "" {
		if from, err = rosterRoute("--carry-route", a.carryRoute, a.roster, a.rootKey, a.carry, reaction.VerifySignedCarrySource); err != nil {
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

// stopsLiftSigned refuses in a fixed order and writes nothing on any
// refusal: the route, the list, whose header and lifts are judged through
// the roster before anything is signed, a lift that would end no stop, the
// key, then the lift as the plane's judge reads it. The lift names the
// list's head, so it never verifies against another list. It says on
// standard error what it signed.
func stopsLiftSigned(a stopsLiftArgs, dir string, now time.Time, stdout, stderr io.Writer) int {
	route, err := a.verified(dir)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	list, _, err := judgedList(dir, route, now)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	through := a.through
	if through == 0 {
		through = list.Usage().Lines
	}
	if !slices.ContainsFunc(list.Entries(), func(e reaction.Entry) bool { return e.RunID == a.run && e.Line <= through }) {
		return fail(stderr, stopsLiftName, fmt.Errorf("run %s has no stop through line %d for a lift to end", oneLine(a.run), through))
	}
	key, release, err := readOperatorKey(a.key)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	defer release()
	lift := reaction.SignedLift{
		KeyID: policykey.KeyID(publicHalf(key)), ListHead: list.Header().Signed.Digest, RunID: a.run, ThroughLine: through,
		TenantID: route.TenantID(), Project: route.ProjectID(), File: route.Plane().ListFile,
	}
	body, err := lift.Payload()
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	sig, err := bundle.SignBytesAs(reaction.SignedLiftPayloadType, body, key)
	if err != nil {
		return fail(stderr, stopsLiftName, fmt.Errorf("--key: %w", err))
	}
	env := reaction.Envelope{PayloadType: reaction.SignedLiftPayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: lift.KeyID, Signature: sig}}}
	ctx, cancel := context.WithTimeout(context.Background(), stopsLockWait)
	defer cancel()
	n, err := stopwrite.AppendLift(ctx, dir, route, reaction.LiftLine{RunID: a.run, ThroughLine: through, Envelope: env}, now)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	writeLine(stderr, fmt.Sprintf("%s: %s: signed lift of run %s through line %d of list head %s for tenant %s project %s of %s",
		brand.CLI, stopsLiftName, oneLine(a.run), through, lift.ListHead, oneLine(lift.TenantID), oneLine(lift.Project), oneLine(lift.File)))
	return emit(stdout, stderr, stopsLiftName,
		[]string{fmt.Sprintf("lift line %d run %s through line %d", n, oneLine(a.run), through)}, dir)
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
