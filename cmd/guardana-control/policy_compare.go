package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policycompare"
)

const (
	policyCompareName = "policy compare"
	policyCompareForm = "--current <document> --candidate <document> [--cases <dir>]\n" +
		"      [--evidence <export>] [--labels <file>] --report <file>"
	policyCompareUsage = "takes --current, --candidate and --report once each, and --cases, --evidence or both"
	// maxCompareExportBytes bounds the export compare reads whole: room for
	// the events of more requests than a run may hold.
	maxCompareExportBytes = 32 << 20
	// maxLabelsBytes bounds the labels file.
	maxLabelsBytes = 1 << 20
	// reportMode keeps the report to its owner: it names the requests and
	// decisions of the evidence it read.
	reportMode = 0o600
)

// compareArgs are the flags of policy compare.
type compareArgs struct {
	current, candidate, cases, evidence, labels, report string
}

// given holds when every required flag is set and at least one source of
// cases is named.
func (a *compareArgs) given() bool {
	return a.current != "" && a.candidate != "" && a.report != "" && (a.cases != "" || a.evidence != "")
}

func policyCompareFlags(command string, out io.Writer) (*flag.FlagSet, *compareArgs) {
	flags := commandFlags(command, out)
	a := &compareArgs{}
	flags.Var(&onceString{dst: &a.current}, "current", "the policy `document` in force, as policy sign takes it; every case file's document is this one")
	flags.Var(&onceString{dst: &a.candidate}, "candidate", "the policy `document` to compare with it")
	flags.Var(&onceString{dst: &a.cases}, "cases", "a `dir` of policy test cases; expect is optional, its format is checked, and it is not compared with any decision")
	flags.Var(&onceString{dst: &a.evidence}, "evidence", "an evidence `export`, as the gateway's trail export wrote it; each request is a case")
	flags.Var(&onceString{dst: &a.labels}, "labels", "a policy-case-labels/v1alpha1 `file` labelling cases attack or legitimate")
	flags.Var(&onceString{dst: &a.report}, "report", "the `file` the report is written to; one that exists is refused")
	return flags, a
}

// onceString is a flag that takes one value and refuses a second, which
// would otherwise replace the first without a word.
type onceString struct {
	dst *string
	set bool
}

func (o *onceString) String() string {
	if o == nil || o.dst == nil {
		return ""
	}
	return *o.dst
}

func (o *onceString) Set(v string) error {
	if o.set {
		return errors.New("given twice")
	}
	*o.dst, o.set = v, true
	return nil
}

func policyCompareFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := policyCompareFlags(command, out)
	return flags
}

// policyCompareCommand evaluates each case under the current and the
// candidate policy, writes the report and prints its counts. It exits 0 when
// every case was evaluated on both sides and none is unknown, 1 when the
// report holds an unknown case, and 2 when an input was refused or the report
// was not written. It sends no call, reads no approval and writes nothing but
// the report.
func policyCompareCommand(args []string, stdout, stderr io.Writer) int {
	flags, a := policyCompareFlags(policyCompareName, io.Discard)
	if err := flags.Parse(args); err != nil {
		return usageError(stderr, policyCompareName, err.Error()+"; "+policyCompareUsage)
	}
	if flags.NArg() != 0 || !a.given() {
		return usageError(stderr, policyCompareName, policyCompareUsage)
	}
	run, err := readCompareInput(a)
	if err != nil {
		return usageError(stderr, policyCompareName, err.Error())
	}
	rep, err := policycompare.Compare(run)
	if err != nil {
		return usageError(stderr, policyCompareName, err.Error())
	}
	body, err := rep.Marshal()
	if err == nil {
		err = writeReport(a.report, body)
	}
	if err != nil {
		return usageError(stderr, policyCompareName, "the report was not written: "+err.Error())
	}
	if err := printSummary(stdout, a.report, rep); err != nil {
		return fail(stderr, policyCompareName, fmt.Errorf("the report is written; writing to standard output: %w", err))
	}
	if rep.Complete() {
		return exitOK
	}
	return exitFail
}

// writeReport creates the report under its name and never replaces a file:
// the body is forced to disk under a temporary name in the same directory,
// which is linked to the name and removed.
func writeReport(path string, body []byte) error {
	dir, name := filepath.Split(filepath.Clean(path))
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		return fmt.Errorf("--report %s names no file", path)
	}
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	return errors.Join(ondisk.CreateNoReplaceIn(root, name, body, reportMode), root.Close())
}

func printSummary(w io.Writer, path string, r *policycompare.Report) error {
	for _, line := range summaryLines(path, r) {
		if _, err := io.WriteString(w, oneLine(line)+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func summaryLines(path string, r *policycompare.Report) []string {
	c := r.Counts
	var reasons []string
	for _, reason := range policycompare.Reasons() {
		if n := c.Unknown.ByReason[reason]; n > 0 {
			reasons = append(reasons, fmt.Sprintf("%s %d", reason, n))
		}
	}
	unknown := fmt.Sprintf("unknown: %d of %d", c.Unknown.Count, c.Unknown.Of)
	if len(reasons) > 0 {
		unknown += " (" + strings.Join(reasons, ", ") + ")"
	}
	lines := []string{
		"report: " + path,
		fmt.Sprintf("read: %d (%d case, %d evidence)", c.Read, c.BySource[policycompare.SourceCase], c.BySource[policycompare.SourceEvidence]),
		fmt.Sprintf("evaluated on both sides: %d of %d", c.EvaluatedBothSides.Count, c.EvaluatedBothSides.Of),
		unknown,
		fmt.Sprintf("changes of %d compared: %d unchanged, %d stricter, %d looser, %d other",
			c.Change.Of, c.Change.Unchanged, c.Change.Stricter, c.Change.Looser, c.Change.Other),
	}
	if r.Provenance.Labels == nil {
		return lines
	}
	for _, label := range []string{string(policycompare.Attack), string(policycompare.Legitimate), "unlabelled"} {
		t := c.ByLabel[label]
		lines = append(lines, fmt.Sprintf("%s: %d: %d unchanged, %d stricter, %d looser, %d other, %d unknown",
			label, t.Of, t.Unchanged, t.Stricter, t.Looser, t.Other, t.Unknown))
	}
	return append(lines, "labeller independence: "+r.Scope.LabellerIndependence)
}
