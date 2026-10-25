package main

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/guardana/control/internal/supervise"
)

const (
	procedureLintName = "procedure lint"
	procedureTestName = "procedure test"
)

var childrenNames = map[supervise.Children]string{
	supervise.ChildrenInherit:  "inherit",
	supervise.ChildrenSeparate: "separate",
}

// procedureLint reads the procedure at path as supervise reads it and prints
// what it configures: its schema, id, version and digest, the children mode
// of a 0.2 document, and each rule of its schema with the rule's version and
// whether a confirmed finding of it may stop a run. A document the reader
// refuses exits 2 with the reader's reason on one line.
func procedureLint(path string, stdout, stderr io.Writer) int {
	raw, err := readBounded(path)
	if err != nil {
		return usageError(stderr, procedureLintName, err.Error())
	}
	p, err := supervise.ReadProcedure(raw)
	if err != nil {
		return usageError(stderr, procedureLintName, path+": "+err.Error())
	}
	lines := []string{"schema_version: " + p.Schema(), "procedure_id: " + p.ID(), "version: " + p.Version(), "digest: " + p.Digest()}
	if mode, stated := childrenNames[p.Children()]; stated {
		lines = append(lines, "children: "+mode)
	}
	for _, id := range supervise.RuleIDsOf(p.Schema()) {
		version, _ := supervise.RuleVersionOf(id)
		stops := "never stops"
		if supervise.MayStop(id) {
			stops = "may stop"
		}
		lines = append(lines, fmt.Sprintf("rule: %s version %s, %s", id, version, stops))
	}
	if err := writeLines(stdout, lines); err != nil {
		return usageError(stderr, procedureLintName, err.Error())
	}
	return exitOK
}

// procedureTest supervises each case of the cases document at path and
// compares what was found with what the case expects, exactly. It prints
// `ok   name: findings` or `FAIL name: what differed` per case and a
// summary, and exits 1 when any case fails. A document it cannot read, a
// procedure the reader refuses or an export it cannot read is refused
// before any case runs: exit 2, nothing on stdout.
func procedureTest(path string, stdout, stderr io.Writer) int {
	doc, err := readCasesFile(path)
	if err != nil {
		return usageError(stderr, procedureTestName, err.Error())
	}
	lines := make([]string, 0, len(doc.cases)+1)
	passed := 0
	for _, c := range doc.cases {
		line, ok := runProcedureCase(doc.procedure, c)
		mark := "FAIL"
		if ok {
			mark = "ok  "
			passed++
		}
		lines = append(lines, mark+" "+c.name+": "+line)
	}
	lines = append(lines, fmt.Sprintf("procedure %s version %s: %d cases, %d passed, %d failed",
		doc.procedure.ID(), doc.procedure.Version(), len(doc.cases), passed, len(doc.cases)-passed))
	if err := writeLines(stdout, lines); err != nil {
		return usageError(stderr, procedureTestName, err.Error())
	}
	if passed != len(doc.cases) {
		return exitFail
	}
	return exitOK
}

// evaluateCase supervises in with each source under the run's tenant and the
// project its events name: a case's source has no descriptor, so no identity
// of its own.
func evaluateCase(in supervise.Input) (*supervise.Result, error) {
	project, err := supervise.RunProject(in)
	if err != nil {
		return nil, err
	}
	in.Sources = slices.Clone(in.Sources)
	for i := range in.Sources {
		in.Sources[i].Tenant, in.Sources[i].Project = in.Run.Tenant, project
	}
	return supervise.Evaluate(in)
}

// runProcedureCase supervises one case and reports its line and whether it
// matched. A case supervise refuses to judge fails with the refusal.
func runProcedureCase(p *supervise.Procedure, c procedureCase) (string, bool) {
	in := c.input
	in.Procedure = p
	res, err := evaluateCase(in)
	if err != nil {
		return "refused: " + err.Error(), false
	}
	got := foundOf(res.Findings)
	diffs := slices.Concat(compareRules(c.expect.rules, res.Report.GetRules()), compareFindings(c.expect.findings, got),
		compareSources(c.expect, res))
	if len(diffs) > 0 {
		return strings.Join(diffs, "; "), false
	}
	if len(got) == 0 {
		return "no finding", true
	}
	names := make([]string, len(got))
	for i, f := range got {
		names[i] = f.rule + " " + findingVerdictName(f.verdict)
	}
	return strings.Join(names, ", "), true
}

// writeLines writes each line as oneLine prints it.
func writeLines(w io.Writer, lines []string) error {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(oneLine(l) + "\n")
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("writing to standard output: %w", err)
	}
	return nil
}
