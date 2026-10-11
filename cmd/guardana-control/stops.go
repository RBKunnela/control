package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

const (
	stopsInitName = "stops init"
	stopsLiftName = "stops lift"
	stopsListName = "stops list"
	stopsInitForm = "--route <file> --public-key <file>\n" +
		"      [--carry <dir> --carry-route <file>] <dir>"
	stopsLiftForm = "--route <file> --public-key <file> --key <file> --run <run-id>\n" +
		"      [--through <line>] <dir>"
	stopsListForm = "--route <file> --public-key <file> <dir>"
)

// stopsLockWait bounds how long a writer waits for another writer's lock on
// a stops directory. A plane never takes it.
const stopsLockWait = 10 * time.Second

// routeFlags is the signed route every stops command and react judge by.
type routeFlags struct{ route, publicKey string }

func (r *routeFlags) declare(flags *flag.FlagSet) {
	flags.StringVar(&r.route, "route", "", "the signed route file route sign wrote")
	flags.StringVar(&r.publicKey, "public-key", "", "the public key file of the route key")
}

func (r routeFlags) set() bool { return r.route != "" && r.publicKey != "" }

func (r routeFlags) verified() (reaction.Route, error) {
	return verifiedRoute("--route", r.route, r.publicKey)
}

type stopsInitArgs struct {
	routeFlags
	carry, carryRoute string
}

func stopsInitFlags(command string, out io.Writer) (*flag.FlagSet, *stopsInitArgs) {
	flags := commandFlags(command, out)
	a := &stopsInitArgs{}
	a.declare(flags)
	flags.StringVar(&a.carry, "carry", "", "the stops directory of the list to carry into the new one")
	flags.StringVar(&a.carryRoute, "carry-route", "", "the signed route the list carried from is judged against")
	return flags, a
}

func stopsInitFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := stopsInitFlags(command, out)
	return flags
}

func stopsInitCommand(args []string, stdout, stderr io.Writer) int {
	flags, a := stopsInitFlags(stopsInitName, io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 || !a.set() || (a.carry == "") != (a.carryRoute == "") {
		return usageError(stderr, stopsInitName,
			"takes --route and --public-key, --carry and --carry-route together or neither, then the stops directory")
	}
	return stopsInit(*a, flags.Arg(0), time.Now(), stdout, stderr)
}

// stopsInit starts a list in dir judged against the route, or carries the
// list in --carry, judged against --carry-route under the same route key,
// into it.
func stopsInit(a stopsInitArgs, dir string, now time.Time, stdout, stderr io.Writer) int {
	route, err := a.verified()
	if err != nil {
		return fail(stderr, stopsInitName, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), stopsLockWait)
	defer cancel()
	if a.carry == "" {
		h, err := stopwrite.Init(ctx, dir, route, now)
		if err != nil {
			return fail(stderr, stopsInitName, err)
		}
		return emit(stdout, stderr, stopsInitName, headerLines(h), dir)
	}
	from, err := verifiedCarrySource(a.carryRoute, a.publicKey)
	if err != nil {
		return fail(stderr, stopsInitName, err)
	}
	c, err := stopwrite.Carry(ctx, a.carry, from, dir, route, now)
	if err != nil {
		return fail(stderr, stopsInitName, err)
	}
	lines := append(headerLines(c.Header), "stops: "+strconv.Itoa(c.Stops), "covered: "+strconv.Itoa(c.Covered))
	if c.LeftOut > 0 {
		lines = append(lines, fmt.Sprintf("left out: the last %d line(s) of the old list, from %s", c.LeftOut, oneLine(c.Refused.Error())))
	}
	return emit(stdout, stderr, stopsInitName, lines, dir)
}

type stopsLiftArgs struct {
	routeFlags
	key, run string
	through  int64
}

func stopsLiftFlags(command string, out io.Writer) (*flag.FlagSet, *stopsLiftArgs) {
	flags := commandFlags(command, out)
	a := &stopsLiftArgs{}
	a.declare(flags)
	flags.StringVar(&a.key, "key", "", "the private key file keygen wrote for the route's lift key")
	flags.StringVar(&a.run, "run", "", "the opened run whose stops the lift ends")
	flags.Int64Var(&a.through, "through", 0, "the last line the lift ends; the list's last complete line when left out")
	return flags, a
}

func stopsLiftFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := stopsLiftFlags(command, out)
	return flags
}

// stopsLiftCommand checks its own arguments for key text, as signCommand
// does.
func stopsLiftCommand(args []string, stdout, stderr io.Writer) int {
	if err := policykey.CheckArguments(args); err != nil {
		return usageError(stderr, stopsLiftName, err.Error())
	}
	flags, a := stopsLiftFlags(stopsLiftName, io.Discard)
	err := flags.Parse(args)
	throughGiven := false
	flags.Visit(func(f *flag.Flag) { throughGiven = throughGiven || f.Name == "through" })
	if err != nil || flags.NArg() != 1 || !a.set() || a.key == "" || a.run == "" || (throughGiven && a.through <= 0) {
		return usageError(stderr, stopsLiftName,
			"takes --route, --public-key, --key and --run, a --through above zero if any, then the stops directory")
	}
	return stopsLift(*a, flags.Arg(0), time.Now(), stdout, stderr)
}

// stopsLift refuses in a fixed order and writes nothing on any refusal: the
// route, the key, which must be the route's lift key, the list, a lift that
// would end no stop, then the lift as the plane's judge reads it.
func stopsLift(a stopsLiftArgs, dir string, now time.Time, stdout, stderr io.Writer) int {
	route, err := a.verified()
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	key, err := policykey.ReadPrivate(a.key)
	if err != nil {
		return fail(stderr, stopsLiftName, fmt.Errorf("--key: %w", err))
	}
	defer clear(key)
	if pub, _ := key.Public().(ed25519.PublicKey); !bytes.Equal(pub, route.LiftKey()) {
		return fail(stderr, stopsLiftName, errors.New("--key: its public half is not the route's lift_public_key"))
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
	lift := reaction.Lift{Version: reaction.LiftVersion, ListID: list.Header().ListID, RouteDigest: route.Digest(),
		RunID: a.run, ThroughLine: through}
	env, err := reaction.SignLift(lift, key)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), stopsLockWait)
	defer cancel()
	n, err := stopwrite.AppendLift(ctx, dir, route, reaction.LiftLine{RunID: a.run, ThroughLine: through, Envelope: env}, now)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	return emit(stdout, stderr, stopsLiftName,
		[]string{fmt.Sprintf("lift line %d run %s through line %d", n, oneLine(a.run), through)}, dir)
}

type stopsListArgs struct{ routeFlags }

func stopsListFlags(command string, out io.Writer) (*flag.FlagSet, *stopsListArgs) {
	flags := commandFlags(command, out)
	a := &stopsListArgs{}
	a.declare(flags)
	return flags, a
}

func stopsListFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := stopsListFlags(command, out)
	return flags
}

func stopsListCommand(args []string, stdout, stderr io.Writer) int {
	flags, a := stopsListFlags(stopsListName, io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 || !a.set() {
		return usageError(stderr, stopsListName, "takes --route and --public-key, then the stops directory")
	}
	return stopsList(a.routeFlags, flags.Arg(0), time.Now(), stdout, stderr)
}

// stopsList prints the list as a plane with a trusted clock at now would
// judge it: the header, each stop no lift ended and whether it is active,
// the covered lines and lifts counted, and the use of the bounds.
func stopsList(r routeFlags, dir string, now time.Time, stdout, stderr io.Writer) int {
	route, err := r.verified()
	if err != nil {
		return fail(stderr, stopsListName, err)
	}
	list, accepted, err := judgedList(dir, route, now)
	if err != nil {
		return fail(stderr, stopsListName, fmt.Errorf("%w; a plane reading this list blocks every call", err))
	}
	lines := headerLines(list.Header())
	for _, e := range list.Entries() {
		state := "expired"
		if activeAt(e, now) {
			state = "active"
		}
		lines = append(lines, fmt.Sprintf("stop line %d run %s finding %s rule %s created_at %s expires_at %s %s",
			e.Line, oneLine(e.RunID), oneLine(e.FindingID), oneLine(e.RuleID),
			policy.FormatIssuedAt(e.CreatedAt), policy.FormatIssuedAt(e.ExpiresAt), state))
	}
	covered, lifts, err := countLines(accepted)
	if err != nil {
		return fail(stderr, stopsListName, err)
	}
	u := list.Usage()
	use := fmt.Sprintf("bytes: %d of %d, lines: %d of %d", u.Bytes, reaction.MaxListBytes, u.Lines, reaction.MaxListLines)
	if u.Degraded() {
		use += ", past nine tenths"
	}
	lines = append(lines, fmt.Sprintf("covered: %d, lifts: %d", covered, lifts), use)
	return emit(stdout, stderr, stopsListName, lines, "")
}

// countLines counts the covered and lift lines of accepted, the part of a
// list a judge accepted.
func countLines(accepted []byte) (covered, lifts int, err error) {
	for line := range bytes.Lines(accepted) {
		l, err := reaction.ParseLine(bytes.TrimSuffix(line, []byte{'\n'}))
		if err != nil {
			return 0, 0, err
		}
		switch l.Kind {
		case reaction.KindCovered:
			covered++
		case reaction.KindLift:
			lifts++
		}
	}
	return covered, lifts, nil
}

// judgedList reads the list in dir with every check a plane's read makes and
// judges it against route at now, with no tolerance past it, as the writer
// does, and returns it with the bytes the judge accepted. A refusal names
// the cause a plane would report.
func judgedList(dir string, route reaction.Route, now time.Time) (reaction.List, []byte, error) {
	raw, err := stoplist.Read(dir)
	if err != nil {
		return reaction.List{}, nil, fmt.Errorf("the stop list in %s is unknown (%s): %w", dir, stoplist.CauseOf(err), err)
	}
	list, err := reaction.Judge(route, reaction.Prefix{}, raw, now, 0)
	if err != nil {
		return reaction.List{}, nil, fmt.Errorf("the stop list in %s is unknown (%s): %w", dir, reaction.CauseOf(err), err)
	}
	return list, raw[:list.Prefix().Length()], nil
}

// activeAt reports whether e still stops at now, as a plane whose clock is
// trusted judges it: until its expiry.
func activeAt(e reaction.Entry, now time.Time) bool { return e.ActiveAt(now, time.Time{}) }

func headerLines(h reaction.Header) []string {
	return []string{
		"list_id: " + oneLine(h.ListID),
		"route_id: " + oneLine(h.RouteID),
		"route_serial: " + strconv.FormatInt(h.RouteSerial, 10),
		"route_digest: " + oneLine(h.RouteDigest),
	}
}

// emit prints lines, and on a failed write says the list in dir was changed
// all the same when dir is not empty.
func emit(stdout, stderr io.Writer, command string, lines []string, dir string) int {
	if _, err := io.WriteString(stdout, strings.Join(lines, "\n")+"\n"); err != nil {
		if dir != "" {
			err = fmt.Errorf("%w; the stop list in %s was written", err, dir)
		}
		return fail(stderr, command, fmt.Errorf("writing to standard output: %w", err))
	}
	return exitOK
}
