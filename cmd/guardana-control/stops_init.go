package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

type stopsInitArgs struct {
	routeFlags
	carry, carryRoute string
	key               string
	serial            int64
	stopsFloor        string
}

func stopsInitFlags(command string, out io.Writer) (*flag.FlagSet, *stopsInitArgs) {
	flags := commandFlags(command, out)
	a := &stopsInitArgs{}
	a.declare(flags)
	flags.StringVar(&a.carry, "carry", "", "the stops directory of the list to carry into the new one")
	flags.StringVar(&a.carryRoute, "carry-route", "", "the signed route the list carried from is judged against, a v1alpha2 route among them")
	flags.StringVar(&a.key, "key", "", "the operator's private key file, which signs a 3.0 list's header")
	flags.Int64Var(&a.serial, "serial", 1, "a new 3.0 list's first serial, taken only by a plane whose stop list floor holds none; a carry takes the next")
	flags.StringVar(&a.stopsFloor, "stops-floor", "", "the plane's reaction.stops_floor_dir, which a signed carry holds the old list to")
	return flags, a
}

func stopsInitFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := stopsInitFlags(command, out)
	return flags
}

// usable reports whether the flags name a route and its check, a key exactly
// when the route is signed, --carry and --carry-route together, a --serial
// only for a new signed list and a --stops-floor only for a signed carry.
func (a stopsInitArgs) usable(serialGiven bool) bool {
	return a.set() && (a.carry == "") == (a.carryRoute == "") && (a.key != "") == a.signed() &&
		(!serialGiven || (a.signed() && a.carry == "")) && (a.stopsFloor == "" || (a.signed() && a.carry != ""))
}

func stopsInitCommand(args []string, stdout, stderr io.Writer) int {
	if err := policykey.CheckArguments(args); err != nil {
		return usageError(stderr, stopsInitName, err.Error())
	}
	flags, a := stopsInitFlags(stopsInitName, io.Discard)
	err := flags.Parse(args)
	serialGiven := false
	flags.Visit(func(f *flag.Flag) { serialGiven = serialGiven || f.Name == "serial" })
	if err != nil || flags.NArg() != 1 || !a.usable(serialGiven) {
		return usageError(stderr, stopsInitName,
			"takes --route with --public-key, or with --roster, --root-key and --key, --carry and --carry-route together or neither, "+
				"a --serial only for a new signed list, a --stops-floor only for a signed carry, then the stops directory")
	}
	if a.signed() {
		return stopsInitSigned(*a, flags.Arg(0), time.Now(), stdout, stderr)
	}
	return stopsInit(*a, flags.Arg(0), time.Now(), stdout, stderr)
}

// stopsInit starts a list in dir judged against the route, or carries the
// list in --carry, judged against --carry-route under the same route key,
// into it.
func stopsInit(a stopsInitArgs, dir string, now time.Time, stdout, stderr io.Writer) int {
	route, err := a.verified(dir, &rosterNote{w: stderr, command: stopsInitName})
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
