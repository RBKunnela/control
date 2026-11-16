package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/reaction"
)

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
		return usageError(stderr, stopsListName, "takes --route with --public-key or with --roster and --root-key, then the stops directory")
	}
	return stopsList(a.routeFlags, flags.Arg(0), time.Now(), stdout, stderr)
}

// stopsList prints the list as a plane with a trusted clock at now would
// judge it: the header, each stop no lift ended, the agent or principal it
// stops when it stops one, and whether it is active,
// the covered lines and lifts counted, and the use of the bounds.
func stopsList(r routeFlags, dir string, now time.Time, stdout, stderr io.Writer) int {
	route, err := r.verified(dir, &rosterNote{w: stderr, command: stopsListName})
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
		lines = append(lines, fmt.Sprintf("stop line %d %srun %s finding %s rule %s created_at %s expires_at %s %s",
			e.Line, whomOf(e.Stop), oneLine(e.RunID), oneLine(e.FindingID), oneLine(e.RuleID),
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

// whomOf is the scope and subject of s followed by a space when s stops an
// agent or a principal, and empty for a stop of its run, which the line
// names anyway.
func whomOf(s reaction.Stop) string {
	if t := s.Target(); t.Scope != reaction.ScopeRun {
		return t.Scope + " " + oneLine(t.Subject) + " "
	}
	return ""
}
