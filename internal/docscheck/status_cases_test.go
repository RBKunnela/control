package docscheck

import (
	"strings"
	"testing"
)

// goodStatus is a page that holds every rule: six groups in order, a row
// each, an id of exactly the longest length allowed and a sentence of
// exactly the most words allowed.
const goodStatus = "# Status\n\nIntro.\n\n## Components\n\n" +
	"### Decisions\n\n| ID | Component | Status | What it does |\n| --- | --- | --- | --- |\n" +
	"| decision-kernel | Decision kernel | `implemented` | Decides each call in a fixed order. [details](#decision-kernel) |\n" +
	"| candidate-policy | Candidate policies | `planned` | Compares a candidate policy; not built. [details](#candidate-policy) |\n\n" +
	"### Integrations\n\n| ID | Component | Status | What it does |\n| --- | --- | --- | --- |\n" +
	"| tool-definition-review-and-alert | Tool `definition` review | `experimental` | " +
	"One two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen " +
	"sixteen seventeen eighteen nineteen twenty one two three four five six seven eight nine ten. " +
	"[details](#tool-definition-review-and-alert) |\n\n" +
	"### Evidence\n\n| ID | Component | Status | What it does |\n| --- | --- | --- | --- |\n" +
	"| evidence-spool | Evidence spool | `experimental` | Keeps evidence on disk, as [backlog B35](backlog.md) says. [details](#evidence-spool) |\n\n" +
	"### Supervision and reaction\n\n| ID | Component | Status | What it does |\n| --- | --- | --- | --- |\n" +
	"| run-stop | Stopping a run | `experimental` | Stops a run's later calls with `supervise --view`. [details](#run-stop) |\n\n" +
	"### Operations\n\n| ID | Component | Status | What it does |\n| --- | --- | --- | --- |\n" +
	"| dev-mode | Dev mode | `experimental` | Starts a local plane at version `1.0`. [details](#dev-mode) |\n\n" +
	"### Project\n\n| ID | Component | Status | What it does |\n| --- | --- | --- | --- |\n" +
	"| go-module | Go module | `implemented` | One module. [details](#go-module) |\n\n" +
	"A paragraph under the last table.\n\n" +
	"## Details\n\n" +
	"### decision-kernel\n\n`internal/core/`, [ADR-0012](adr/0012.md).\n\n" +
	"### candidate-policy\n\nNo command.\n\n" +
	"### tool-definition-review-and-alert\n\n- `internal/x/`\n- `internal/y/`\n\n" +
	"### evidence-spool\n\n`internal/spool/`.\n\n" +
	"### run-stop\n\n`internal/reaction/`.\n\n" +
	"### dev-mode\n\n`cmd/x/`; a \\| b is escaped.\n\n```text\na | b\n```\n\n<!-- a | b -->\n\n" +
	"### go-module\n\n`go.mod`.\n\n" +
	"## What it supervises today\n\n| Aim | Today |\n| --- | --- |\n| a | b |\n"

func TestStatusComponentProblems(t *testing.T) {
	lines := strings.Split(goodStatus, "\n")
	rows, problems := statusComponents(lines, 7)
	wantNone(t, "a page that holds every rule", problems)
	if len(rows) != 7 || rows[2].id != "tool-definition-review-and-alert" || rows[2].group != "Integrations" ||
		rows[2].name != "Tool `definition` review" || rows[2].label != "experimental" || rows[0].line != 11 {
		t.Errorf("rows = %+v", rows)
	}
	if _, problems := statusComponents(lines, 8); len(problems) != 1 || problems[0] != "read 7 component rows, want at least 8" {
		t.Errorf("a floor above the rows read: %q", problems)
	}
	_, problems = statusComponents(nil, 1)
	wantProblem(t, "an empty page", problems, "read 0 component rows, want at least 1")
	wantProblem(t, "an empty page", problems, `no "## Components" section`)

	long := "tool-definition-review-and-alert"
	for name, c := range map[string]struct{ from, to, want string }{
		"a renamed column":           {"| ID | Component | Status | What it does |\n| --- | --- | --- | --- |\n| decision-kernel", "| ID | Name | Status | What it does |\n| --- | --- | --- | --- |\n| decision-kernel", `line 9: header is "ID | Name | Status | What it does"`},
		"a missing separator":        {"| --- | --- | --- | --- |\n| decision-kernel", "| decision-kernel", "line 10: want the header separator row"},
		"a row of three cells":       {"| go-module | Go module | `implemented` |", "| go-module | `implemented` |", "row has 3 cells, want 4"},
		"a fifth cell":               {"One module. [details](#go-module) |", "One module. [details](#go-module) | x |", "row has 5 cells, want 4"},
		"an id in capitals":          {"| decision-kernel |", "| Decision-kernel |", `the id "Decision-kernel" is not lowercase words joined by hyphens`},
		"an id with a space":         {"| dev-mode |", "| dev mode |", `the id "dev mode" is not lowercase words`},
		"an id with two hyphens":     {"| dev-mode |", "| dev--mode |", `the id "dev--mode" is not lowercase words`},
		"a name for an id":           {"| go-module | Go module |", "| Go module | Go module |", `the id "Go module" is not lowercase`},
		"an id a character too long": {long, long + "s", `the id "tool-definition-review-and-alerts" is longer than 32 characters`},
		"an id used twice":           {"| dev-mode | Dev mode |", "| go-module | Dev mode |", `the id "go-module" is used twice`},
		"no name":                    {"| Go module |", "|  |", `"go-module" has no name`},
		"an unknown label":           {"`implemented` | One module.", "`done` | One module.", "\"go-module\" has status \"`done`\""},
		"a label without code":       {"`implemented` | One module.", "implemented | One module.", `"go-module" has status "implemented"`},
		"a word too many":            {"eight nine ten. [details](#" + long, "eight nine ten eleven. [details](#" + long, "the sentence has 31 words, want at most 30"},
		"no details link":            {"One module. [details](#go-module)", "One module.", "the sentence does not end with [details](#go-module)"},
		"another row's details":      {"One module. [details](#go-module)", "One module. [details](#dev-mode)", `"go-module": the sentence does not end with [details](#go-module)`},
		"no sentence":                {"One module. [details](#go-module)", "[details](#go-module)", "does not end with"},
		"no full stop":               {"One module. [details]", "One module [details]", "does not end with a full stop"},
		"two sentences":              {"One module. [details]", "One module. It builds. [details]", `"One module. It builds." is more than one sentence`},
		"a path":                     {"One module. [details]", "One module in `internal/core`. [details]", `names "/", which belongs in the details`},
		"a record's number":          {"One module. [details]", "One module, ADR-0007. [details]", `names "ADR-0", which belongs in the details`},
		"a test's name":              {"One module. [details]", "One module, held by TestModule. [details]", `names "TestM"`},
		"a fuzz target":              {"One module. [details]", "One module, fuzzed by FuzzModule. [details]", `names "FuzzM"`},
		"a table before any group":   {"Intro.\n\n## Components\n\n", "Intro.\n\n## Components\n\n| x |\n\n", "line 7: a table line before the first group heading"},
		"a group missing":            {"### Operations\n\n| ID | Component | Status | What it does |\n| --- | --- | --- | --- |\n| dev-mode | Dev mode | `experimental` | Starts a local plane at version `1.0`. [details](#dev-mode) |\n\n", "", `the groups are ["Decisions" "Integrations" "Evidence" "Supervision and reaction" "Project"]`},
		"a group renamed":            {"### Supervision and reaction", "### Supervision", `"Supervision" "Operations"`},
		"a group with no row":        {"| go-module | Go module | `implemented` | One module. [details](#go-module) |\n", "", `the group "Project" holds no row`},
		"a second table in a group":  {"| go-module | Go module | `implemented` | One module. [details](#go-module) |\n", "| go-module | Go module | `implemented` | One module. [details](#go-module) |\n\n| ID | Component | Status | What it does |\n", `the id "ID" is not lowercase`},
		"a row with no details":      {"### go-module\n\n`go.mod`.\n\n", "", `"go-module" has no heading under Details`},
		"details twice":              {"### go-module\n\n`go.mod`.\n\n", "### go-module\n\n`go.mod`.\n\n### go-module\n\nAgain.\n\n", `"go-module" has 2 headings under Details`},
		"details with no row":        {"### go-module\n\n`go.mod`.\n\n", "### go-module\n\n`go.mod`.\n\n### gone-row\n\nOld.\n\n", `the details heading "gone-row" names no row`},
		"empty details":              {"### go-module\n\n`go.mod`.\n\n", "### go-module\n\n", `the details of "go-module" hold no line of prose`},
		"details of a comment":       {"### go-module\n\n`go.mod`.\n\n", "### go-module\n\n<!-- moved -->\n\n", `the details of "go-module" hold no line of prose`},
		"details of a long comment":  {"### go-module\n\n`go.mod`.\n\n", "### go-module\n\n<!--\nmoved\n-->\n\n", `the details of "go-module" hold no line of prose`},
		"details of a subheading":    {"### go-module\n\n`go.mod`.\n\n", "### go-module\n\n#### Notes\n\n", `the details of "go-module" hold no line of prose`},
		"details of a code block":    {"### go-module\n\n`go.mod`.\n\n", "### go-module\n\n```\ngo.mod\n```\n\n", `the details of "go-module" hold no line of prose`},
		"a row with no first pipe":   {"| dev-mode |", "ghost-row | Ghost | `implemented` | Anything. |\n| dev-mode |", "a pipe on a line that does not start with one is a table row this check cannot read: ghost-row"},
		"a bare pipe in the details": {"; a \\| b", "; a | b", "a pipe on a line that does not start with one"},
		"a sentence after a code":    {"One module. [details]", "One module. `go` builds it. [details]", "more than one sentence"},
		"a sentence after a digit":   {"One module. [details]", "One module. 2 tools build it. [details]", "more than one sentence"},
		"details out of order":       {"### decision-kernel\n\n`internal/core/`, [ADR-0012](adr/0012.md).\n\n### candidate-policy\n\nNo command.\n\n", "### candidate-policy\n\nNo command.\n\n### decision-kernel\n\n`internal/core/`, [ADR-0012](adr/0012.md).\n\n", `details heading 1 is "candidate-policy", want "decision-kernel", the tables' order`},
		"no details section":         {"## Details\n\n", "## Notes\n\n", `no "## Details" section`},
		"a row in a tilde fence":     {"| go-module | Go module | `implemented` | One module. [details](#go-module) |\n", "~~~\n| go-module | Go module | `implemented` | One module. [details](#go-module) |\n~~~\n", `the group "Project" holds no row`},
		"backticks in a tilde fence": {"| go-module | Go module | `implemented` | One module. [details](#go-module) |\n", "~~~\n```\n| go-module | Go module | `implemented` | One module. [details](#go-module) |\n~~~\n", `the group "Project" holds no row`},
		"a row indented as code":     {"| go-module | Go module |", "    | go-module | Go module |", "line 42: a table line indented as code is drawn as code, not as a row: | go-module"},
		"details before components":  {"Intro.\n\n## Components", "Intro.\n\n## Details\n\n## Components", `"## Details" comes before "## Components"`},
	} {
		page := strings.Replace(goodStatus, c.from, c.to, 1)
		if page == goodStatus {
			t.Fatalf("%s: the fixture edit changed nothing", name)
		}
		_, problems := statusComponents(strings.Split(page, "\n"), 7)
		wantProblem(t, name, problems, c.want)
	}
	swapped := strings.NewReplacer("### Decisions", "### Integrations", "### Integrations", "### Decisions").Replace(goodStatus)
	_, problems = statusComponents(strings.Split(swapped, "\n"), 7)
	wantProblem(t, "two groups swapped", problems, `the groups are ["Integrations" "Decisions" "Evidence"`)
}

func TestPinnedIDProblems(t *testing.T) {
	rows, _ := statusComponents(strings.Split(goodStatus, "\n"), 7)
	good := "# pinned\n\ndecision-kernel\ncandidate-policy\ntool-definition-review-and-alert\nevidence-spool\nrun-stop\ndev-mode\ngo-module\n"
	wantNone(t, "every id pinned once", pinnedIDProblems(rows, strings.Split(good, "\n")))
	for name, c := range map[string]struct{ from, to, want string }{
		"an id renamed on the page": {"run-stop\n", "run-halt\n", `the published id "run-halt" is gone`},
		"a new id not appended":     {"dev-mode\n", "", `the id "dev-mode" is not in internal/docscheck/testdata/status-ids.txt`},
		"an id pinned twice":        {"go-module\n", "go-module\ngo-module\n", `"go-module" is pinned twice`},
		"no id pinned":              {good, "# pinned\n", "pins no id"},
	} {
		list := strings.Replace(good, c.from, c.to, 1)
		if list == good {
			t.Fatalf("%s: the fixture edit changed nothing", name)
		}
		wantProblem(t, name, pinnedIDProblems(rows, strings.Split(list, "\n")), c.want)
	}
}

func TestStatusRowsByID(t *testing.T) {
	rows, problems := statusRows(strings.Split(goodStatus, "\n"))
	if got := rows["decision-kernel"]; got.name != "Decision kernel" || got.label != "implemented" || len(rows) != 7 {
		t.Errorf("statusRows = %+v", rows)
	}
	wantProblem(t, "a page below the inventory's floor", problems, "read 7 component rows, want at least 57")
}
