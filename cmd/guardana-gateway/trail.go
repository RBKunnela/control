package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/trailfile"
)

// maxShownID bounds how much of one identifier a trail line prints.
const maxShownID = 64

// shapeNote is the last line trail prints: evidence.ValidateChain reads the
// links and the order, and a nil from it is not a verification.
const shapeNote = "the check proves each chain's shape and not its integrity: a record altered to keep that shape passes it"

const trailForm = "[segments] [export [--after <cursor>] [--limit <n>] [--max-bytes <n>] [--request <id>]... [--run <id>]... " +
	"[--tenant <id>]... [--project <id>]... [--kind <kind>]...] <file or dir>"

// declareTrail declares the flags of trail export on the trail command's set,
// so the help lists them; plain trail takes none of them.
func declareTrail(flags *flag.FlagSet) commandFunc {
	q := trailfile.Query{}
	flags.StringVar(&q.After, "after", "", "trail export: start after the line this `cursor`, from an earlier export, names")
	flags.IntVar(&q.Limit, "limit", trailfile.DefaultExportLimit, "trail export: the most records to write, every type counted; at most 100000")
	flags.Int64Var(&q.MaxBytes, "max-bytes", 0, "trail export: the most bytes of whole lines to read; 0 is no bound")
	var requests, runs, tenants, projects, kinds valueList
	flags.Var(&requests, "request", "trail export: write the events of this request `id`; repeatable")
	flags.Var(&runs, "run", "trail export: write the events of this run `id`; repeatable")
	flags.Var(&tenants, "tenant", "trail export: write the events of this tenant `id`; repeatable")
	flags.Var(&projects, "project", "trail export: write the events of this project `id`; repeatable")
	flags.Var(&kinds, "kind", "trail export: write the events of this `kind`, as the contract spells it; repeatable")
	return func(_ context.Context, args []string, stdout, stderr io.Writer) int {
		if len(args) == 0 || args[0] != "export" {
			switch {
			case flags.NFlag() > 0:
				writeLine(stderr, flags.Name()+": its flags are trail export's: "+flags.Name()+" "+trailForm)
				return exitUsage
			case len(args) == 2 && args[0] == "segments":
				return trailSegments(args[1], stdout, stderr)
			case len(args) != 1:
				writeLine(stderr, flags.Name()+": name one trail file or directory of segments to read")
				return exitUsage
			}
			return trail(args[0], stdout, stderr)
		}
		path, ok := exportPath(flags, args[1:], stderr)
		if !ok {
			return exitUsage
		}
		q.Requests, q.Runs, q.Tenants, q.Projects, q.Kinds = requests, runs, tenants, projects, kinds
		return trailExport(path, q, stdout, stderr)
	}
}

// exportPath parses trail export's flags on either side of its one file.
func exportPath(flags *flag.FlagSet, args []string, stderr io.Writer) (string, bool) {
	if err := flags.Parse(args); err != nil {
		return "", false
	}
	if flags.NArg() == 0 {
		writeLine(stderr, flags.Name()+" export: name one trail file or directory of segments to export")
		return "", false
	}
	path := flags.Arg(0)
	if err := flags.Parse(flags.Args()[1:]); err != nil {
		return "", false
	}
	if flags.NArg() > 0 {
		writeLine(stderr, flags.Name()+" export: name one trail file or directory of segments to export, not "+oneLine(flags.Arg(0))+" as well")
		return "", false
	}
	return path, true
}

// trailExport writes the evidence export of one trail file, or of one
// segment of a directory of segments, to stdout. It exits 0 when nothing was
// refused and the export holds no gap, 1 when the export is whole, trailer
// included, and holds a gap, and 2 when it was refused or cut short: a query
// or a cursor refused, an expired cursor among them, a file that cannot be
// read, or output that could not be written. A refused export writes no
// trailer, and a reader without one knows the export is not whole.
func trailExport(path string, q trailfile.Query, stdout, stderr io.Writer) int {
	tr, err := trailfile.ExportPath(path, q, stdout)
	if err != nil {
		writeLine(stderr, brand.Gateway+": trail export: "+oneLine(err.Error()))
		return exitUsage
	}
	if tr.Gaps > 0 {
		return fail(stderr, "trail export", fmt.Errorf("%s: the export holds %d gap(s): lines that are not events this build reads, "+
			"an event id with two contents, or a partial line no collector is writing", strconv.Quote(path), tr.Gaps))
	}
	return exitOK
}

// valueList is a flag given once per value.
type valueList []string

func (l *valueList) String() string { return strings.Join(*l, " ") }

func (l *valueList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// trail reads a trail file, or every segment of a directory of segments not
// pruned, up to the last newline and prints one line per request's trail with
// the chain check's verdict, then the counts, with the segments pruned for a
// directory, and what the check does not prove. It exits 1 when a trail
// failed or could not be read either way, when the file holds no trail at all, since a check of nothing is
// not a pass, and when the file ends in a partial line no collector is
// writing.
func trail(path string, stdout, stderr io.Writer) int {
	rep, err := trailfile.ReadPath(path, trailfile.DefaultMaxLines)
	if err != nil {
		return fail(stderr, "trail", err)
	}
	if len(rep.Trails) == 0 {
		return fail(stderr, "trail", fmt.Errorf("%s holds no trail: %d line(s), %d byte(s) after the last newline",
			strconv.Quote(path), rep.Lines, rep.Unread))
	}
	counts := map[trailfile.Verdict]int{}
	var b strings.Builder
	for _, tr := range rep.Trails {
		counts[tr.Verdict]++
		fmt.Fprintf(&b, "request=%s project=%s tenant=%s last=%s %s", shown(tr.RequestID), shown(tr.ProjectID),
			shown(tr.TenantID), tr.Last, tr.Verdict)
		if tr.Reason != nil {
			b.WriteString(": " + oneLine(tr.Reason.Error()))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "trails %d: ok %d, open %d, failed %d, indeterminate %d; lines %d, repeated lines collapsed %d, bytes after the last newline %d",
		len(rep.Trails), counts[trailfile.Passed], counts[trailfile.StillOpen], counts[trailfile.Failed],
		counts[trailfile.Indeterminate], rep.Lines, rep.Duplicates, rep.Unread)
	if rep.Log {
		fmt.Fprintf(&b, "; segments pruned %d", rep.Pruned)
	}
	b.WriteString("\n")
	b.WriteString(shapeNote + "\n")
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		return fail(stderr, "trail", errors.Join(errors.New("writing to standard output"), err))
	}
	if rep.Unread > 0 && !rep.Held {
		return fail(stderr, "trail", fmt.Errorf("%s ends in %d byte(s) after its last newline and no collector holds it: "+
			"no append is under way, so the file is damaged", strconv.Quote(path), rep.Unread))
	}
	if counts[trailfile.Failed]+counts[trailfile.Indeterminate] > 0 {
		return exitFail
	}
	return exitOK
}

// shown is an identifier as a trail line prints it: as it is when it is
// printable ASCII with no space, quote or equals sign, and quoted otherwise,
// so a line break or a terminal's escape in a file never reaches the
// terminal. One longer than maxShownID bytes is cut and says so. Key text in
// it is withheld, as oneLine withholds it.
func shown(id string) string {
	if len(id) > maxShownID {
		return oneLine(strconv.QuoteToASCII(id[:maxShownID])) + " (cut)"
	}
	if id == "" || strings.IndexFunc(id, func(r rune) bool { return r <= ' ' || r >= 0x7f || r == '"' || r == '=' }) >= 0 {
		return oneLine(strconv.QuoteToASCII(id))
	}
	return oneLine(id)
}
