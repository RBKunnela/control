package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/brand"
	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/supervise"
)

const (
	superviseName = "supervise"
	superviseForm = "--procedure <file> --runs <dir> --run <run-id> --findings <dir>\n" +
		"      [--evidence <export>]... [--source <descriptor> --log <dir>]...\n" +
		"      [--view <file> [--view-all]]\n" +
		"      [" + runsReadHint + "]"
	superviseUsage = "takes --procedure, --runs, --run and --findings once each, any --evidence, " +
		"each --source with its --log, in order, --view at most once, and for a signed --runs " +
		"--roster, --root-key, --tenant and --project once each"
)

type superviseArgs struct {
	procedure, runs, run, findings, evidence, sources, logs, view valueList
	viewAll                                                       bool
	read                                                          runsReadFlags
}

func superviseFlags(command string, out io.Writer) (*flag.FlagSet, *superviseArgs) {
	flags := commandFlags(command, out)
	a := &superviseArgs{}
	flags.Var(&a.procedure, "procedure", "the procedure, a JSON `file` of this account that no other account may write; given once")
	flags.Var(&a.runs, "runs", "the runs `dir` the run was opened in; given once")
	flags.Var(&a.run, "run", "the opened run's `id`, run- and 32 hex digits; given once")
	flags.Var(&a.evidence, "evidence", "an evidence `export` as the gateway's trail export wrote it; repeatable")
	flags.Var(&a.sources, "source", "a source descriptor `file`, paired in order with --log; one that does not exist is left out; repeatable, at most "+strconv.Itoa(supervise.MaxSources))
	flags.Var(&a.logs, "log", "the observation log `dir` of the --source in the same place; one with no log yet was never heard; repeatable")
	flags.Var(&a.findings, "findings", "the findings log `dir`, owner-only; given once")
	flags.Var(&a.view, "view", "a `file` to draw the run in as one page, mode 0600, replacing only a page drawn before; given once")
	a.read.declare(flags)
	flags.BoolVar(&a.viewAll, "view-all", false, "draw every call on the --view page, up to its bound, not each finding's neighbourhood")
	return flags, a
}

func superviseFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := superviseFlags(command, out)
	return flags
}

// superviseCommand checks one opened run against its procedure, appends what
// it found to the findings log and then prints it. It exits 0 when no rule
// fired, every rule on was checked, an event of the run was read and every
// --source was read and heard within its heartbeat; 1 otherwise; and 2,
// printing nothing, on a refused input or an edited procedure, both refused
// before the log is opened, or on a log it could not open or write, whose
// unfinished write no reader takes. A failure once the write is committed,
// closing the log, writing the --view page or writing the output, is 2 too,
// with the write kept. A --view path it may not replace is refused before
// any input is read.
func superviseCommand(args []string, stdout, stderr io.Writer) int {
	flags, a := superviseFlags(superviseName, io.Discard)
	err := flags.Parse(args)
	switch {
	case err != nil:
		return refuseSupervise(stderr, err.Error()+"; "+superviseUsage)
	case flags.NArg() != 0 || len(a.procedure) != 1 || len(a.runs) != 1 || len(a.run) != 1 ||
		len(a.findings) != 1 || len(a.sources) != len(a.logs):
		return refuseSupervise(stderr, superviseUsage)
	case len(a.sources) > supervise.MaxSources:
		return refuseSupervise(stderr, fmt.Sprintf("%d sources are given, bound %d", len(a.sources), supervise.MaxSources))
	}
	view, err := viewPath(a)
	if err != nil {
		return refuseSupervise(stderr, err.Error())
	}
	a.read.note = &rosterNote{w: stderr, command: superviseName}
	in, err := readSuperviseInput(a)
	if err != nil {
		return refuseSupervise(stderr, err.Error())
	}
	res, err := supervise.Evaluate(in)
	if err != nil {
		return refuseSupervise(stderr, err.Error())
	}
	return recordSupervision(a, view, in, res, stdout, stderr)
}

// recordSupervision draws the --view page if one was asked for, appends
// res to the findings log, writes the page, then prints.
func recordSupervision(a *superviseArgs, view string, in supervise.Input, res *supervise.Result, stdout, stderr io.Writer) int {
	page, err := drawView(view, in.Procedure, res, a.viewAll)
	if err != nil {
		return refuseSupervise(stderr, err.Error())
	}
	logged, err := appendFindings(a.findings[0], in.Procedure, res)
	if err != nil {
		return refuseSupervise(stderr, refusedInput("findings", a.findings[0], err).Error())
	}
	if err := writeView(view, page); err != nil {
		return refuseSupervise(stderr, err.Error()+"; the findings log was written")
	}
	unread := unreadSources(in, res)
	text := strings.Join(superviseLines(in, res, unread, logged), "\n") + "\n"
	if _, err := io.WriteString(stdout, text); err != nil {
		return refuseSupervise(stderr, "writing to standard output: "+err.Error())
	}
	return superviseStatus(res, unread)
}

func refuseSupervise(stderr io.Writer, message string) int {
	writeLine(stderr, brand.CLI+": "+superviseName+": "+oneLine(message))
	return exitUsage
}

// superviseStatus is 1 unless an event of the run was read, no finding was
// made, every rule the procedure keeps on was checked and no source was left
// unread.
func superviseStatus(res *supervise.Result, unread []string) int {
	if res.Report.GetRead().GetEventsTaken() == 0 || len(res.Findings) != 0 || len(unread) != 0 {
		return exitFail
	}
	for _, rule := range res.Report.GetRules() {
		if s := rule.GetState(); s != findingv1alpha1.RuleState_RULE_STATE_CHECKED && s != findingv1alpha1.RuleState_RULE_STATE_OFF {
			return exitFail
		}
	}
	return exitOK
}

// appendFindings writes the findings and the report to the log in dir, and
// returns nil when there was nothing to write. A procedure id and version the
// log holds under another digest is refused before the log is opened, so
// the refusal leaves the file as it was, and again once the log is held, so
// no write that came between is missed: findings under one version must rest
// on one document.
func appendFindings(dir string, p *supervise.Procedure, res *supervise.Result) (*findinglog.Result, error) {
	if err := checkOneDigest(dir, p, true); err != nil {
		return nil, err
	}
	log, err := findinglog.Open(dir)
	if err != nil {
		return nil, err
	}
	logged, err := writeUnderOneDigest(log, dir, p, res)
	return logged, errors.Join(err, log.Close())
}

func writeUnderOneDigest(log *findinglog.Log, dir string, p *supervise.Procedure, res *supervise.Result) (*findinglog.Result, error) {
	if err := checkOneDigest(dir, p, false); err != nil {
		return nil, err
	}
	// A run none of whose events was read names no project, and the log
	// keeps no record without one; nothing was judged, so nothing is lost.
	if res.Report.GetRead().GetEventsTaken() == 0 {
		return nil, nil
	}
	logged, err := log.Write(res.Findings, res.Report)
	if err != nil {
		return nil, err
	}
	return &logged, nil
}

// checkOneDigest refuses p when the log in dir holds its id and version
// under another digest. A log not there yet holds nothing when absentOK.
func checkOneDigest(dir string, p *supervise.Procedure, absentOK bool) error {
	records, err := findinglog.ReadFile(filepath.Join(dir, findinglog.FileName))
	switch {
	case absentOK && errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	}
	for _, r := range records {
		ref := r.GetSuperviseReport().GetProcedure()
		if f := r.GetFindingRecord(); f != nil {
			ref = f.GetProcedure()
		}
		if ref.GetProcedureId() == p.ID() && ref.GetVersion() == p.Version() && ref.GetDigest() != p.Digest() {
			return fmt.Errorf("procedure %s version %s was supervised under another digest; "+
				"an edited procedure takes a new version", strconv.Quote(p.ID()), strconv.Quote(p.Version()))
		}
	}
	return nil
}

// readSuperviseInput reads every input. A descriptor given that does not
// exist is named in SourcesNotRead by its path, the only name it has.
func readSuperviseInput(a *superviseArgs) (supervise.Input, error) {
	var in supervise.Input
	raw, err := ondisk.ReadOwned(a.procedure[0], supervise.MaxProcedureBytes, descriptorForbidden, os.Geteuid())
	if err != nil {
		return in, refusedInput("procedure", a.procedure[0], err)
	}
	if in.Procedure, err = supervise.ReadProcedure(raw); err != nil {
		return in, refusedInput("procedure", a.procedure[0], err)
	}
	if in.Run, in.Tree, err = readRun(a.runs[0], a.run[0], in.Procedure.Children(), a.read); err != nil {
		return in, err
	}
	for _, path := range a.evidence {
		x, err := readSupervisedExport(path)
		if err != nil {
			return in, err
		}
		in.Exports = append(in.Exports, x)
	}
	for i := range a.sources {
		src, present, err := readSupervisedSource(a.sources[i], a.logs[i])
		switch {
		case err != nil:
			return in, err
		case present:
			in.Sources = append(in.Sources, src)
		default:
			in.SourcesNotRead = append(in.SourcesNotRead, a.sources[i])
		}
	}
	return in, nil
}
