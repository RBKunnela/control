package docscheck

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const adrIndex = "docs/adr/README.md"

var (
	adrRecord = regexp.MustCompile(`^docs/adr/([0-9]{4})-[^/]+\.md$`)
	adrRow    = regexp.MustCompile(`^\| \[([0-9]{4})\]\(([0-9]{4}-[^/)]+\.md)\) \|`)
)

// adrIndexProblems holds the index to the records files lists: every record
// but the template has one row, and every row of the table names, under its
// own number, a record that exists.
func adrIndexProblems(files, index []string) []string {
	records := adrRecords(files)
	var problems []string
	rowed := map[string]int{}
	for i, line := range index {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| ADR ") || strings.HasPrefix(line, "| ---") {
			continue
		}
		m := adrRow.FindStringSubmatch(line)
		switch {
		case m == nil:
			problems = append(problems, fmt.Sprintf("%s:%d: a row that names no record as | [NNNN](NNNN-name.md) |", adrIndex, i+1))
		case !records[m[2]]:
			problems = append(problems, fmt.Sprintf("%s:%d: a row names %s, which is no record", adrIndex, i+1, m[2]))
		case !strings.HasPrefix(m[2], m[1]+"-"):
			problems = append(problems, fmt.Sprintf("%s:%d: a row labelled %s names %s", adrIndex, i+1, m[1], m[2]))
		default:
			rowed[m[2]]++
		}
	}
	for record := range records {
		if n := rowed[record]; n != 1 {
			problems = append(problems, fmt.Sprintf("%s has %d row(s) in %s, want one", record, n, adrIndex))
		}
	}
	slices.Sort(problems)
	return problems
}

// adrRecords is the file name of every record of files but the template.
func adrRecords(files []string) map[string]bool {
	records := map[string]bool{}
	for _, rel := range files {
		if m := adrRecord.FindStringSubmatch(rel); m != nil && m[1] != "0000" {
			records[strings.TrimPrefix(rel, "docs/adr/")] = true
		}
	}
	return records
}

func TestEveryRecordHasOneRowInTheIndex(t *testing.T) {
	files := repoFiles(t, repoRoot(t))
	if !slices.ContainsFunc(files, adrRecord.MatchString) {
		t.Fatal("the repository lists no record, so the index was compared with nothing")
	}
	for _, problem := range adrIndexProblems(files, readLines(t, repoFS(t), adrIndex)) {
		t.Error(problem)
	}
}

func TestADRIndexProblems(t *testing.T) {
	files := []string{"docs/adr/0000-template.md", "docs/adr/0001-first.md", "docs/adr/0002-second.md", "docs/adr/README.md"}
	head := []string{"# Records", "", "| ADR | Decision |", "| --- | --- |"}
	for name, c := range map[string]struct {
		rows []string
		want []string
	}{
		"every record once": {[]string{"| [0001](0001-first.md) | One |", "| [0002](0002-second.md) | Two |"}, nil},
		"a record with no row": {[]string{"| [0001](0001-first.md) | One |"},
			[]string{"0002-second.md has 0 row(s) in docs/adr/README.md, want one"}},
		"a record with two rows": {[]string{"| [0001](0001-first.md) | One |", "| [0002](0002-second.md) | Two |", "| [0002](0002-second.md) | Again |"},
			[]string{"0002-second.md has 2 row(s) in docs/adr/README.md, want one"}},
		"a row naming no file": {[]string{"| [0001](0001-first.md) | One |", "| [0002](0002-second.md) | Two |", "| [0003](0003-gone.md) | Gone |"},
			[]string{"docs/adr/README.md:7: a row names 0003-gone.md, which is no record"}},
		"a row under another number": {[]string{"| [0001](0001-first.md) | One |", "| [0003](0002-second.md) | Two |"},
			[]string{"0002-second.md has 0 row(s) in docs/adr/README.md, want one", "docs/adr/README.md:6: a row labelled 0003 names 0002-second.md"}},
		"a row with no link": {[]string{"| [0001](0001-first.md) | One |", "| [0002](0002-second.md) | Two |", "| 0003 | Plain |"},
			[]string{"docs/adr/README.md:7: a row that names no record as | [NNNN](NNNN-name.md) |"}},
		"the template's row": {[]string{"| [0000](0000-template.md) | Template |", "| [0001](0001-first.md) | One |", "| [0002](0002-second.md) | Two |"},
			[]string{"docs/adr/README.md:5: a row names 0000-template.md, which is no record"}},
	} {
		got := adrIndexProblems(files, slices.Concat(head, c.rows))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

// The index as it stands, less the row of 0001, is refused for that row alone.
func TestADRIndexProblemsRefuseTheIndexLessARow(t *testing.T) {
	index := readLines(t, repoFS(t), adrIndex)
	i := slices.IndexFunc(index, func(line string) bool { return strings.HasPrefix(line, "| [0001](") })
	if i < 0 {
		t.Fatalf("%s holds no row of 0001 to take away", adrIndex)
	}
	got := adrIndexProblems(repoFiles(t, repoRoot(t)), slices.Delete(slices.Clone(index), i, i+1))
	if want := []string{"0001-language-and-toolchain.md has 0 row(s) in docs/adr/README.md, want one"}; !slices.Equal(got, want) {
		t.Errorf("%q, want %q", got, want)
	}
}
