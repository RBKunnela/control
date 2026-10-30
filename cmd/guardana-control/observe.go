package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/ingest"
	"github.com/guardana/control/internal/ingest/egresslog"
	"github.com/guardana/control/internal/observe"
	"github.com/guardana/control/internal/observelog"
)

const (
	observeImportName = "observe import"
	observeExportName = "observe export"
	observeImportForm = "--source <file> --log <dir> <file>"
	observeExportForm = "[--after] [--limit] [--max-bytes] <file>"
)

// maxDescriptorBytes bounds the descriptor read; ingest.ReadDescriptor
// refuses more than this anyway.
const maxDescriptorBytes = 64 << 10

// The descriptor states the trust a later finding rests on, so only its
// owner may write it.
const descriptorForbidden = 0o022

func observeImportFlags(command string, out io.Writer) (*flag.FlagSet, *string, *string) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(out)
	source := flags.String("source", "", "the source descriptor, a JSON file of this account that no other account may write")
	logDir := flags.String("log", "", "the observation log's directory, of this account and reachable by no other")
	return flags, source, logDir
}

func observeImportFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _, _ := observeImportFlags(command, out)
	return flags
}

func observeExportFlags(command string, out io.Writer) (*flag.FlagSet, *observelog.Query) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(out)
	q := &observelog.Query{}
	flags.StringVar(&q.After, "after", "", "start after the line this `cursor`, from an earlier export, names")
	flags.IntVar(&q.Limit, "limit", observelog.DefaultExportLimit, "the most records to write, every type counted; at most 100000")
	flags.Int64Var(&q.MaxBytes, "max-bytes", 0, "the most bytes of whole lines to read; 0 is no bound")
	return flags, q
}

func observeExportFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := observeExportFlags(command, out)
	return flags
}

// observeImportCommand imports one input file of a source into an
// observation log, through the importer of the descriptor's kind: OTLP/JSON
// trace lines for otel-genai-traces, an access log's JSON lines for
// egress-access-log. It exits 0 when everything read was imported, skipped or
// already in the log, 1 when a line or a span was refused or an observation
// conflicted with the log, and 2 when the import did not complete; the error
// says whether it was written.
func observeImportCommand(args []string, stdout, stderr io.Writer) int {
	flags, source, logDir := observeImportFlags(observeImportName, io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 || *source == "" || *logDir == "" {
		return usageError(stderr, observeImportName, "takes --source and --log, and one input file of the source's kind")
	}
	raw, err := ondisk.ReadOwned(*source, maxDescriptorBytes, descriptorForbidden, os.Geteuid())
	if err != nil {
		return usageError(stderr, observeImportName, "--source: "+err.Error())
	}
	desc, err := ingest.ReadDescriptor(raw)
	if err != nil {
		return usageError(stderr, observeImportName, "--source: "+err.Error())
	}
	kind, ok := ingest.Lookup(desc.GetKind())
	if !ok {
		return usageError(stderr, observeImportName, "--source: kind "+strconv.Quote(desc.GetKind())+" has no importer in this build")
	}
	batch, err := importFile(flags.Arg(0), kind, desc, observe.DescriptorSHA256(raw))
	if err != nil {
		return usageError(stderr, observeImportName, err.Error())
	}
	log, err := observelog.Open(*logDir)
	if err != nil {
		return usageError(stderr, observeImportName, "--log: "+err.Error())
	}
	written, err := log.Write(batch.Observations, batch.Report)
	closeErr := log.Close()
	switch {
	case err != nil:
		return usageError(stderr, observeImportName, "--log: "+errors.Join(err, closeErr).Error())
	case closeErr != nil:
		return usageError(stderr, observeImportName, "--log: the import was written; closing the log failed: "+closeErr.Error())
	}
	return printImport(kind.Labels, batch.Report.GetCounts(), written, stdout, stderr)
}

// maxInputBytes bounds one import's input, which is read whole.
const maxInputBytes = 256 << 20

// inputBound is the bound importFile reads under: maxInputBytes, which a test
// lowers rather than writing an input of that size.
var inputBound int64 = maxInputBytes

// importFile reads the input as a regular file, so a pipe or a device put at
// its name cannot hold the command, and maps it with the kind's importer at
// this moment's clock. Under independent trust the input may not be writable
// by group or others: the trust states that the agent cannot write it.
func importFile(path string, kind ingest.Kind, desc *observev1.SourceDescriptor, descriptorSHA256 string) (ingest.Batch, error) {
	raw, err := ondisk.ReadRegular(path, inputBound, egresslog.InputForbidden(desc))
	if err != nil {
		return ingest.Batch{}, fmt.Errorf("input %s: %w", strconv.Quote(path), err)
	}
	return kind.Import(bytes.NewReader(raw), desc, descriptorSHA256, time.Now().UTC())
}

// printImport writes one line per count, under the kind's labels, and
// returns the exit status the counts call for.
func printImport(labels ingest.Labels, c *observev1.ImportCounts, w observelog.Written, stdout, stderr io.Writer) int {
	u := func(n uint64) string { return strconv.FormatUint(n, 10) }
	lines := [][2]string{
		{labels.Read, u(c.GetRead())}, {"observed", u(c.GetObserved())}, {"written", strconv.Itoa(w.Observations)},
		{"duplicate", strconv.Itoa(w.Duplicates)}, {"conflict", strconv.Itoa(w.Conflicts)},
	}
	for _, n := range labels.Counts {
		lines = append(lines, [2]string{n.Label, u(n.Of(c))})
	}
	out := ""
	for _, l := range lines {
		out += l[0] + ": " + l[1] + "\n"
	}
	if _, err := io.WriteString(stdout, out); err != nil {
		return fail(stderr, observeImportName, fmt.Errorf("writing to standard output: %w; the import was written", err))
	}
	if c.GetRefused() > 0 || w.Conflicts > 0 {
		return fail(stderr, observeImportName, fmt.Errorf("%d span(s) or line(s) refused and %d observation(s) conflicting with the log; the import report holds the counts", c.GetRefused(), w.Conflicts))
	}
	return exitOK
}

// observeExportCommand writes the observation export of one log file. It
// exits 0 when the export holds no gap, 1 when it is whole and holds one, and
// 2 when it was refused or cut short.
func observeExportCommand(args []string, stdout, stderr io.Writer) int {
	flags, q := observeExportFlags(observeExportName, io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return usageError(stderr, observeExportName, "takes one observation log file")
	}
	tr, err := observelog.ExportFile(flags.Arg(0), *q, stdout)
	if err != nil {
		return usageError(stderr, observeExportName, err.Error())
	}
	if gaps := tr.Counts["gap"]; gaps > 0 {
		return fail(stderr, observeExportName, fmt.Errorf("%s: the export holds %d gap(s): lines that are not observation records this build reads, "+
			"an observation id with two contents, or a partial line no writer is writing", strconv.Quote(flags.Arg(0)), gaps))
	}
	return exitOK
}
