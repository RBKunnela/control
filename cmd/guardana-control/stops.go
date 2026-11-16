package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

const (
	stopsInitName      = "stops init"
	stopsLiftName      = "stops lift"
	stopsListName      = "stops list"
	stopsFloorInitName = "stops floor init"
	stopsInitForm      = "--route <f> (--public-key <f> | --roster <f> --root-key <f> --key <k>\n" +
		"      [--serial <n>]) [--carry <dir> --carry-route <file> [--stops-floor <dir>]] <dir>"
	stopsLiftForm = "--route <f> (--public-key <f> | --roster <f> --root-key <f>) --key <k>\n" +
		"      (--run <run-id> | --agent <agent-id> | --principal <principal-id>)\n" +
		"      [--through <line>] <dir>"
	stopsListForm      = "--route <f> (--public-key <f> | --roster <f> --root-key <f>) <dir>"
	stopsFloorInitForm = "--tenant <t> --project <p> <dir>"
)

// stopsLockWait bounds how long a writer waits for another writer's lock on
// a stops directory. A plane never takes it.
const stopsLockWait = 10 * time.Second

// routeFlags is the signed route every stops command and react judge by: a
// v1alpha1 route under its route key, or a v1alpha3 route under the roster
// verified under the trust root.
type routeFlags struct{ route, publicKey, roster, rootKey string }

func (r *routeFlags) declare(flags *flag.FlagSet) {
	flags.StringVar(&r.route, "route", "", "the signed route file route sign wrote")
	flags.StringVar(&r.publicKey, "public-key", "", "the public key file of the route key, for a v1alpha1 route")
	flags.StringVar(&r.roster, "roster", "", "the plane's trust.roster, for a v1alpha3 route an operator signed")
	flags.StringVar(&r.rootKey, "root-key", "", "the plane's trust.root_public_key, which the roster has to verify under")
}

// set reports whether the flags name a route and one way to verify it: the
// route key, or the roster with its trust root.
func (r routeFlags) set() bool {
	keyed, rostered := r.publicKey != "", r.roster != "" || r.rootKey != ""
	return r.route != "" && keyed != rostered && (keyed || (r.roster != "" && r.rootKey != ""))
}

// signed reports whether the flags verify a route an operator signed.
func (r routeFlags) signed() bool { return r.publicKey == "" }

// verified is the route the flags name, verified, a v1alpha3 one bound to
// the stop list in dir under the roster note names.
func (r routeFlags) verified(dir string, note *rosterNote) (reaction.Route, error) {
	if !r.signed() {
		return verifiedRoute("--route", r.route, r.publicKey)
	}
	return rosterRoute("--route", r.route, r.roster, r.rootKey, dir, "", note, reaction.VerifySignedRoute)
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
	lines := []string{
		"list_id: " + oneLine(h.ListID),
		"route_id: " + oneLine(h.RouteID),
		"route_serial: " + strconv.FormatInt(h.RouteSerial, 10),
		"route_digest: " + oneLine(h.RouteDigest),
	}
	if s := h.Signed; s.Digest != "" {
		lines = append(lines, "serial: "+strconv.FormatInt(s.Serial, 10), "head: "+s.Digest, "signed by key: "+oneLine(s.KeyID))
		if s.Previous != "" {
			lines = append(lines, "previous: "+s.Previous)
		}
	}
	return lines
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
