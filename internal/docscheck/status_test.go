// The one inventory, docs/status.md: under "## Components" one table per
// group, each row a stable id, a name, a label and one sentence that links to
// its details; under "## Details" one heading per row, in the tables' order.
// The label is the project's honesty claim and the id is what the landing
// page binds to, so a row that loses either fails here.
package docscheck

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	componentHead   = "ID | Component | Status | What it does"
	maxComponentID  = 32
	maxSummaryWords = 30
	// minComponentRows is the inventory's row count: fewer means a row was
	// lost or the tables were not read.
	minComponentRows = 57
)

var (
	componentGroups = []string{"Decisions", "Integrations", "Evidence", "Supervision and reaction", "Operations", "Project"}
	componentID     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	allowedStatus   = map[string]bool{"`implemented`": true, "`experimental`": true, "`planned`": true}
	// summaryRefused is what belongs in the details, not in the sentence: a
	// path, a record's number, a test's name.
	summaryRefused = regexp.MustCompile(`/|\bADR-?[0-9]|\b(?:Test|Fuzz|Benchmark|Example)[A-Z]`)
	// sentenceBreak is a full stop, question or exclamation mark and the
	// start of another sentence: a capital, a code span or a digit.
	sentenceBreak = regexp.MustCompile("[.!?] +[A-Z0-9`]")
	// barePipe is a pipe no backslash escapes: on a line that does not start
	// with one, the renderer still draws a table row nothing here reads.
	barePipe = regexp.MustCompile(`(?:^|[^\\])\|`)
)

// componentRow is one row of a component table.
type componentRow struct {
	line                            int
	group, id, name, label, summary string
}

// statusComponents reads the component tables and the details of the page
// in lines and returns their rows and every problem with them; a page with
// fewer than minRows rows is a problem, so nothing parsed never passes.
func statusComponents(lines []string, minRows int) ([]componentRow, []string) {
	p := &statusPage{detailLines: map[string][]int{}, detailBody: map[string]int{}}
	for i, raw := range lines {
		p.read(i+1, strings.TrimSpace(raw))
	}
	components, detailsAt := slices.Index(p.sections, "Components"), slices.Index(p.sections, "Details")
	switch {
	case components < 0:
		p.add(`no "## Components" section`)
	case detailsAt < 0:
		p.add(`no "## Details" section`)
	case detailsAt < components:
		p.add(`"## Details" comes before "## Components"`)
	}
	if !slices.Equal(p.groups, componentGroups) {
		p.add("the groups are %q, want %q", p.groups, componentGroups)
	}
	for _, g := range componentGroups {
		if slices.Contains(p.groups, g) && !slices.ContainsFunc(p.rows, func(r componentRow) bool { return r.group == g }) {
			p.add("the group %q holds no row", g)
		}
	}
	if len(p.rows) < minRows {
		p.add("read %d component rows, want at least %d", len(p.rows), minRows)
	}
	return p.rows, append(p.problems, detailProblems(p.rows, p.details, p.detailLines, p.detailBody)...)
}

// statusPage is what statusComponents has read so far.
type statusPage struct {
	problems                  []string
	rows                      []componentRow
	sections, groups, details []string
	detailLines               map[string][]int
	detailBody                map[string]int
	section, group, detail    string
	tableLine                 int
	fenced, comment           bool
}

func (p *statusPage) add(format string, a ...any) {
	p.problems = append(p.problems, fmt.Sprintf(format, a...))
}

// read takes line n, trimmed. Fenced code and HTML comments are neither
// structure nor prose.
func (p *statusPage) read(n int, s string) {
	switch {
	case strings.HasPrefix(s, "```"):
		p.fenced = !p.fenced
		return
	case p.fenced:
		return
	case p.comment || strings.HasPrefix(s, "<!--"):
		p.comment = !strings.Contains(s, "-->")
		return
	case !strings.HasPrefix(s, "|") && barePipe.MatchString(s):
		p.add("line %d: a pipe on a line that does not start with one is a table row this check cannot read: %s", n, s)
	}
	p.structure(n, s)
}

// structure takes line n as a section, a group, a table line, a details
// heading or a line of a details body; a body counts only prose, not a
// heading of its own.
func (p *statusPage) structure(n int, s string) {
	switch {
	case strings.HasPrefix(s, "## "):
		p.section, p.group, p.detail = strings.TrimPrefix(s, "## "), "", ""
		p.sections = append(p.sections, p.section)
	case p.section == "Components" && strings.HasPrefix(s, "### "):
		p.group, p.tableLine = strings.TrimPrefix(s, "### "), 0
		p.groups = append(p.groups, p.group)
	case p.section == "Components" && strings.HasPrefix(s, "|"):
		p.table(n, s)
	case p.section == "Details" && strings.HasPrefix(s, "### "):
		p.detail = strings.TrimPrefix(s, "### ")
		p.details = append(p.details, p.detail)
		p.detailLines[p.detail] = append(p.detailLines[p.detail], n)
	case p.section == "Details" && p.detail != "" && s != "" && !strings.HasPrefix(s, "#"):
		p.detailBody[p.detail]++
	}
}

// table takes line n of a component table: its header, its separator, or
// a row.
func (p *statusPage) table(n int, s string) {
	switch {
	case p.group == "":
		p.add("line %d: a table line before the first group heading", n)
		return
	case p.tableLine == 0:
		if got := strings.Join(tableCells(s), " | "); got != componentHead {
			p.add("line %d: header is %q, want %q", n, got, componentHead)
		}
		p.tableLine++
		return
	case p.tableLine == 1:
		if !tableSeparator.MatchString(s) {
			p.add("line %d: want the header separator row, got %q", n, s)
		}
		p.tableLine++
		return
	}
	cells := tableCells(s)
	if len(cells) != 4 {
		p.add("line %d: row has %d cells, want 4: %s", n, len(cells), s)
		return
	}
	row := componentRow{n, p.group, cells[0], cells[1], cells[2], cells[3]}
	for _, problem := range componentRowProblems(row, p.rows) {
		p.add("line %d: %s", n, problem)
	}
	row.label = strings.Trim(row.label, "`")
	p.rows = append(p.rows, row)
}

// componentRowProblems judges one row against itself and the rows before it.
func componentRowProblems(row componentRow, before []componentRow) []string {
	var problems []string
	switch {
	case !componentID.MatchString(row.id):
		problems = append(problems, fmt.Sprintf("the id %q is not lowercase words joined by hyphens", row.id))
	case len(row.id) > maxComponentID:
		problems = append(problems, fmt.Sprintf("the id %q is longer than %d characters", row.id, maxComponentID))
	}
	if slices.ContainsFunc(before, func(r componentRow) bool { return r.id == row.id }) {
		problems = append(problems, fmt.Sprintf("the id %q is used twice", row.id))
	}
	if row.name == "" {
		problems = append(problems, fmt.Sprintf("%q has no name", row.id))
	}
	if !allowedStatus[row.label] {
		problems = append(problems, fmt.Sprintf("%q has status %q, want one of `implemented`, `experimental`, `planned`", row.id, row.label))
	}
	if p := summaryProblem(row); p != "" {
		problems = append(problems, p)
	}
	return problems
}

// summaryProblem holds a row's sentence to what a stranger reads in one
// line: one sentence of at most maxSummaryWords words, no path, record
// number or test name, then the link to the row's own details.
func summaryProblem(row componentRow) string {
	link := fmt.Sprintf("[details](#%s)", row.id)
	sentence, ok := strings.CutSuffix(row.summary, " "+link)
	switch words := len(strings.Fields(sentence)); {
	case !ok:
		return fmt.Sprintf("%q: the sentence does not end with %s", row.id, link)
	case words > maxSummaryWords:
		return fmt.Sprintf("%q: the sentence has %d words, want at most %d", row.id, words, maxSummaryWords)
	case !strings.HasSuffix(sentence, "."):
		return fmt.Sprintf("%q: the sentence does not end with a full stop", row.id)
	case sentenceBreak.MatchString(sentence):
		return fmt.Sprintf("%q: %q is more than one sentence", row.id, sentence)
	case summaryRefused.MatchString(sentence):
		return fmt.Sprintf("%q: the sentence names %q, which belongs in the details", row.id, summaryRefused.FindString(sentence))
	}
	return ""
}

// detailProblems holds the details to the rows: one heading with a body per
// row, no heading without a row, and the rows' order.
func detailProblems(rows []componentRow, details []string, lines map[string][]int, body map[string]int) []string {
	var problems []string
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.id
		switch n := len(lines[r.id]); {
		case n == 0:
			problems = append(problems, fmt.Sprintf("line %d: %q has no heading under Details", r.line, r.id))
		case n > 1:
			problems = append(problems, fmt.Sprintf("%q has %d headings under Details, at lines %v", r.id, n, lines[r.id]))
		case body[r.id] == 0:
			problems = append(problems, fmt.Sprintf("line %d: the details of %q hold no line of prose", lines[r.id][0], r.id))
		}
	}
	for _, d := range details {
		if !slices.Contains(ids, d) {
			problems = append(problems, fmt.Sprintf("line %d: the details heading %q names no row", lines[d][0], d))
		}
	}
	if len(problems) == 0 && len(details) == len(ids) && !slices.Equal(details, ids) {
		i := 0
		for i < len(ids) && details[i] == ids[i] {
			i++
		}
		problems = append(problems, fmt.Sprintf("details heading %d is %q, want %q, the tables' order", i+1, details[i], ids[i]))
	}
	return problems
}

// statusRows maps each component row of the page in lines by its id, and
// returns the page's problems: a site check reads it only when it parses.
func statusRows(lines []string) (map[string]componentRow, []string) {
	rows, problems := statusComponents(lines, minComponentRows)
	byID := map[string]componentRow{}
	for _, r := range rows {
		byID[r.id] = r
	}
	return byID, problems
}

// statusIDs pins every id the page has published: the landing page and any
// link bind to one, so an id is never renamed or dropped, and a new one is
// appended to the file on purpose.
const statusIDs = "internal/docscheck/testdata/status-ids.txt"

// pinnedIDProblems compares the page's ids with the pinned list in lines:
// one id per line, blank lines and lines starting with # ignored.
func pinnedIDProblems(rows []componentRow, lines []string) []string {
	var problems, pinned []string
	for i, line := range lines {
		id := strings.TrimSpace(line)
		switch {
		case id == "" || strings.HasPrefix(id, "#"):
		case slices.Contains(pinned, id):
			problems = append(problems, fmt.Sprintf("%s:%d: %q is pinned twice", statusIDs, i+1, id))
		default:
			pinned = append(pinned, id)
		}
	}
	if len(pinned) == 0 {
		return append(problems, statusIDs+" pins no id")
	}
	for _, id := range pinned {
		if !slices.ContainsFunc(rows, func(r componentRow) bool { return r.id == id }) {
			problems = append(problems, fmt.Sprintf("the published id %q is gone; an id is never renamed or dropped", id))
		}
	}
	for _, r := range rows {
		if !slices.Contains(pinned, r.id) {
			problems = append(problems, fmt.Sprintf("line %d: the id %q is not in %s; append it there on purpose", r.line, r.id, statusIDs))
		}
	}
	return problems
}

func TestStatusIDsArePinned(t *testing.T) {
	fsys := repoFS(t)
	rows, _ := statusRows(readLines(t, fsys, "docs/status.md"))
	list := make([]componentRow, 0, len(rows))
	for _, r := range rows {
		list = append(list, r)
	}
	report(t, "docs/status.md", pinnedIDProblems(list, readLines(t, fsys, statusIDs)))
}

// TestStatusComponents is the load-bearing check. The root documents no
// longer keep their own inventories, they all point here, so these tables
// are the only place the project states what is implemented, experimental
// or planned; a row that loses its label takes the honesty claim with it.
func TestStatusComponents(t *testing.T) {
	_, problems := statusComponents(readLines(t, repoFS(t), "docs/status.md"), minComponentRows)
	report(t, "docs/status.md", problems)
}
