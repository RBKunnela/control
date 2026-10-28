// Command evidence-report reads an evidence export on standard input and
// prints one row per request with its lifecycle: the action proposed, the
// verdict and reason codes decided, the decision that blocked it beside them,
// whether it was held and how the approval ended, and how the action ended.
//
// It is the export's external consumer: it reads the format that
// docs/contracts.md names "The evidence export" and decodes each event with
// the generated package of the frozen wire contract, and nothing else of this
// module. A consumer outside the module can generate that package from
// api/proto and do the same.
//
// What it proves: every request it reports as completed, failed, aborted or
// blocked has one unbroken prev_event_id chain in this export, from the event
// that proposed an action to the one that ended it, in steps the plane's
// chain validator allows, every event naming the run the first one names and
// the same declared enforcement mode, every decision's verdict one the
// contract declares, and a run ending with a result that says how it ended.
// Under a mode that enforces, the action ran only after a verdict that let it,
// or after REQUIRE_APPROVAL and an approval answered yes; an approval never
// lifts a DENY or an INDETERMINATE.
//
// What it cannot prove: that a record was not altered, since the link is an
// ordering and not a digest; or that the plane recorded everything. A record
// the plane quarantined never reaches the trail file: one inside a request's
// chain shows here as a broken chain or an unfinished one, reported as
// unknown or open; a FINDING_RAISED or POLICY_RELOADED after the event that
// ended the action leaves the row complete; and a request whose first record
// the plane refused does not appear at all. It does not read an action's
// effect class, so a material action run without the approval APPROVE asks
// for, or run under LOCKDOWN, is not told from a read.
//
// It exits 0 when the export accounts for at least one request, every
// request's lifecycle is complete, and nothing is missing: the trailer was
// read, the file's end was reached, the query named no filter but of
// requests, and no gap, conflicting event or refused record was seen. It
// exits 1 when anything is missing, unknown, uncertain, cut or filtered by
// more than requests, or the export is refused, and 2 on a usage error. A run that timed out
// or reported an unknown outcome ended uncertain, never failed: its effect may
// have happened.
//
// With -state DIR it follows one trail from export to export instead: -init
// makes the directory, -cursor prints the cursor the next export starts
// after, and each run reads the export after it. It prints the rows of the
// requests that ended in that export, and appends each new alert, one JSON
// line of this example's own experimental format, to DIR/alerts.jsonl and to
// standard error. It exits 0 with no new alert, 1 with one or more, and 2
// when it refuses the export or the state, which it then leaves as it was.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	if len(os.Args) > 1 {
		// A reader gone from stdout is then an error the state mode reports
		// after its alerts are logged, not a signal that ends it before.
		signal.Ignore(syscall.SIGPIPE)
	}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

const name = "evidence-report"

const usage = "usage: " + name + " < export.jsonl, or " + name + " -state DIR [-init | -cursor] [< export.jsonl]; " +
	"without -state it reads one export on standard input and takes no argument"

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return reportOnce(stdin, stdout, stderr)
	}
	o, ok := parseState(args)
	if !ok {
		say(stderr, usage)
		return 2
	}
	switch {
	case o.init:
		return initState(o.dir, stderr)
	case o.cursor:
		return printCursor(o.dir, stdout, stderr)
	}
	return follow(o.dir, stdin, stdout, stderr)
}

// stateArgs is a state mode's command line: -state DIR, and -init or -cursor
// at most.
type stateArgs struct {
	dir          string
	init, cursor bool
}

func parseState(args []string) (stateArgs, bool) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var o stateArgs
	flags.StringVar(&o.dir, "state", "", "")
	flags.BoolVar(&o.init, "init", false, "")
	flags.BoolVar(&o.cursor, "cursor", false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 || o.dir == "" || (o.init && o.cursor) {
		return stateArgs{}, false
	}
	return o, true
}

// reportOnce reads one export and prints its report.
func reportOnce(stdin io.Reader, stdout, stderr io.Writer) int {
	x, err := readExport(stdin)
	if err != nil {
		say(stderr, "the export is refused: "+err.Error())
		return 1
	}
	rows := x.lifecycles()
	var t totals
	lines := []string{"tenant\tproject\trequest\trun\taction\tverdict\treasons\tblock\theld\tapproval\tend\tnote"}
	for _, r := range rows {
		t.add(r)
		lines = append(lines, r.String())
	}
	lines = append(lines, t.line(x))
	if _, err := io.WriteString(stdout, strings.Join(lines, "\n")+"\n"); err != nil {
		say(stderr, "the report could not be written: "+err.Error())
		return 1
	}
	for _, p := range x.problems {
		say(stderr, p)
	}
	for _, p := range x.missing(t) {
		say(stderr, p)
	}
	if len(x.problems) > 0 || len(x.missing(t)) > 0 {
		return 1
	}
	return 0
}

func say(w io.Writer, line string) { _, _ = fmt.Fprintln(w, name+": "+line) }

// totals counts the rows by how their requests ended.
type totals struct{ requests, completed, failed, uncertain, aborted, blocked, open, unknown int }

func (t *totals) add(r row) {
	t.requests++
	switch r.end {
	case endCompleted:
		t.completed++
	case endFailed:
		t.failed++
	case endUncertain:
		t.uncertain++
	case endAborted:
		t.aborted++
	case endBlocked:
		t.blocked++
	case endOpen:
		t.open++
	default:
		t.unknown++
	}
}

func (t totals) line(x *export) string {
	return fmt.Sprintf("totals: requests %d, completed %d, failed %d, uncertain %d, aborted %d, blocked %d, open %d, unknown %d; "+
		"gaps %d, duplicates %d, conflicting %d, refused %d; %s",
		t.requests, t.completed, t.failed, t.uncertain, t.aborted, t.blocked, t.open, t.unknown,
		x.gaps, x.duplicates, x.conflicting, x.refused, x.trailerState())
}

// missing names what keeps the report from saying the export is whole and
// every lifecycle complete. Problems with single records, gaps among them,
// are already said.
func (x *export) missing(t totals) []string {
	var out []string
	if t.requests == 0 {
		out = append(out, "the export holds no event, so it accounts for no request")
	}
	switch {
	case x.trailer == nil:
		out = append(out, "the export has no trailer read: it was cut short, and what it holds is not all there was")
	case !x.trailer.endReached:
		out = append(out, "the trailer says the file's end was not reached: export again after its next_cursor")
	case x.trailer.tailBytes > 0 && x.trailer.writerHeld:
		out = append(out, fmt.Sprintf("the trailer says %d bytes are still being written: export again once they end", x.trailer.tailBytes))
	case x.trailer.tailBytes > 0:
		out = append(out, fmt.Sprintf("the trailer says the %d bytes after the last newline are a cut line no writer holds: the file is damaged there", x.trailer.tailBytes))
	}
	if x.header.splits {
		out = append(out, "the export's query names a filter other than requests: an event it does not name, such as one of another run, is not there, so no request is known to be whole")
	}
	if t.open > 0 || t.unknown > 0 {
		out = append(out, fmt.Sprintf("not every request's lifecycle is complete: %d open, %d unknown", t.open, t.unknown))
	}
	if t.uncertain > 0 {
		out = append(out, fmt.Sprintf("%d request(s) ended uncertain: each ran and nobody knows whether its effect happened", t.uncertain))
	}
	return out
}

func (x *export) trailerState() string {
	switch {
	case x.trailer == nil:
		return "no trailer read, the export is not whole"
	case !x.trailer.endReached:
		return "trailer end not reached"
	case x.trailer.tailBytes > 0 && x.trailer.writerHeld:
		return fmt.Sprintf("trailer %d bytes still being written", x.trailer.tailBytes)
	case x.trailer.tailBytes > 0:
		return fmt.Sprintf("trailer %d bytes cut, no writer holds them", x.trailer.tailBytes)
	default:
		return "trailer end reached"
	}
}
