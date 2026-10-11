package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/supervise"
)

const (
	routeSignName = "route sign"
	routeSignForm = "--key <file> --out <file> <route.json>"
)

// stopsAuthority is what the help and docs/reference/cli.md both say about
// who may stop a run and who may lift a stop.
const stopsAuthority = "Only the lift key lifts a stop while a plane runs; write access to the stops directory\n" +
	"adds any stop the route allows and, across a restart, can start a new list with none."

// routeFileMode is the mode route sign writes with: a signed route is
// public, as a freshness statement is.
const routeFileMode fs.FileMode = 0o644

type routeSignPaths struct{ key, out string }

func routeSignFlags(command string, out io.Writer) (*flag.FlagSet, *routeSignPaths) {
	flags := commandFlags(command, out)
	var p routeSignPaths
	flags.StringVar(&p.key, "key", "", "the private key file keygen wrote for the route key")
	flags.StringVar(&p.out, "out", "", "the signed route file to write, replacing only a signed route")
	return flags, &p
}

func routeSignFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := routeSignFlags(command, out)
	return flags
}

// routeSignCommand checks its own arguments for key text, as signCommand
// does.
func routeSignCommand(args []string, stdout, stderr io.Writer) int {
	if err := policykey.CheckArguments(args); err != nil {
		return usageError(stderr, routeSignName, err.Error())
	}
	flags, p := routeSignFlags(routeSignName, io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 || p.key == "" || p.out == "" {
		return usageError(stderr, routeSignName, "takes --key and --out, then one route document, with every flag before it")
	}
	return routeSign(p.key, p.out, flags.Arg(0), stdout, stderr)
}

// routeSign refuses in a fixed order and writes nothing on any refusal: the
// document, its rules against supervise's, the output path, the key, then
// the signature. A document refused is refused before the key file is
// opened.
func routeSign(keyPath, out, document string, stdout, stderr io.Writer) int {
	if err := policykey.CheckPlatform(); err != nil {
		return fail(stderr, routeSignName, err)
	}
	raw, err := ondisk.ReadRegular(document, reaction.MaxRouteBytes, 0)
	if err != nil {
		return fail(stderr, routeSignName, fmt.Errorf("document %s: %w", document, err))
	}
	route, err := reaction.ParseRoute(raw)
	if err != nil {
		return fail(stderr, routeSignName, fmt.Errorf("document %s: %w", document, err))
	}
	if err := supervisedRules(route); err != nil {
		return fail(stderr, routeSignName, fmt.Errorf("document %s: %w", document, err))
	}
	out = filepath.Clean(out)
	if err := checkRouteOut(out); err != nil {
		return fail(stderr, routeSignName, err)
	}
	key, err := policykey.ReadPrivate(keyPath)
	if err != nil {
		return fail(stderr, routeSignName, fmt.Errorf("--key: %w", err))
	}
	defer clear(key)
	env, err := reaction.SignRoute(route, key)
	if err != nil {
		return fail(stderr, routeSignName, err)
	}
	body, err := reaction.MarshalRouteFile(env)
	if err != nil {
		return fail(stderr, routeSignName, err)
	}
	if err := ondisk.Replace(filepath.Dir(out), filepath.Base(out), body, routeFileMode); err != nil {
		return fail(stderr, routeSignName, fmt.Errorf("--out %s: %w", out, err))
	}
	lines := "route_id: " + oneLine(route.ID()) + "\n" +
		"serial: " + strconv.FormatInt(route.Serial(), 10) + "\n" +
		"digest: " + route.Digest() + "\n" +
		"key_id: " + env.Signatures[0].KeyID + "\n" +
		"out: " + oneLine(out) + "\n"
	if _, err := io.WriteString(stdout, lines); err != nil {
		return fail(stderr, routeSignName, fmt.Errorf("writing to standard output: %w; the route was written to %s", err, out))
	}
	return exitOK
}

// supervisedRules refuses a rule no finding of supervise can stop a run
// with: a rule id supervise does not have, a rule version that is not that
// rule's, and a rule outside the table of those that may stop, which every
// reader of a signed route refuses.
func supervisedRules(r reaction.Route) error {
	for i, rule := range r.Rules() {
		version, known := supervise.RuleVersionOf(rule.RuleID)
		switch {
		case !known:
			return fmt.Errorf("rules[%d]: rule_id %s is no rule supervise has", i, strconv.Quote(rule.RuleID))
		case rule.RuleVersion != version:
			return fmt.Errorf("rules[%d]: rule_version %s is not supervise's %s", i,
				strconv.Quote(rule.RuleVersion), strconv.Quote(version))
		case !reaction.MayStop(rule.RuleID, rule.RuleVersion):
			return fmt.Errorf("rules[%d]: %s: %w", i, rule.RuleID, reaction.ErrRouteRuleStops)
		}
	}
	return nil
}

// checkRouteOut refuses an output path whose directory is missing, and one
// that exists and is not a regular file holding a route's envelope: route
// sign replaces an earlier route and nothing else, the key and the document
// among what it refuses. The envelope's signature is not checked: this keeps
// a mistyped path from replacing another file, and whoever may write the path
// may write any file there.
func checkRouteOut(out string) error {
	info, err := os.Lstat(out)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := ondisk.CheckDir(filepath.Dir(out), 0); err != nil {
			return fmt.Errorf("--out %s: %w", out, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("--out %s: %w", out, err)
	}
	notARoute := fmt.Errorf("--out %s exists and is not a route's envelope, and route sign replaces nothing else", out)
	if !info.Mode().IsRegular() {
		return notARoute
	}
	raw, err := ondisk.ReadRegular(out, reaction.MaxRouteFileBytes, 0)
	if errors.Is(err, ondisk.ErrTooLarge) {
		return notARoute
	}
	if err != nil {
		return fmt.Errorf("--out %s: %w", out, err)
	}
	if env, err := reaction.ParseRouteFile(raw); err != nil || env.PayloadType != reaction.RoutePayloadType {
		return notARoute
	}
	return nil
}

// verifiedRoute reads the signed route at path, which routeFlag named, and
// verifies it under the route key in the public key file --public-key names.
func verifiedRoute(routeFlag, path, publicKey string) (reaction.Route, error) {
	return readSignedRoute(routeFlag, path, publicKey, reaction.VerifyRoute)
}

// verifiedCarrySource is verifiedRoute for --carry-route, the one route that
// may name a rule version a later one superseded.
func verifiedCarrySource(path, publicKey string) (reaction.Route, error) {
	return readSignedRoute("--carry-route", path, publicKey, reaction.VerifyCarrySource)
}

func readSignedRoute(routeFlag, path, publicKey string, verify func(reaction.Envelope, ed25519.PublicKey) (reaction.Route, error)) (reaction.Route, error) {
	pub, err := readPublicKey("--public-key", publicKey)
	if err != nil {
		return reaction.Route{}, err
	}
	raw, err := ondisk.ReadRegular(path, reaction.MaxRouteFileBytes, 0)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	env, err := reaction.ParseRouteFile(raw)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	r, err := verify(env, pub)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("%s %s: %w", routeFlag, path, err)
	}
	return r, nil
}
