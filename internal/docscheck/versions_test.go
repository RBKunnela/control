package docscheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/guardana/control/internal/findinglog"
)

const (
	versionsDoc    = "docs/reference/versions.md"
	versionsHeader = "| Format | Written | Read | Stability | Defined in |"
	versionsStable = "`stable`"
	wireRowKey     = "Wire messages"
)

// The roles a cited constant plays in its row: a version the tree writes, a
// version it reads, or the major of every version it reads.
const (
	writes = 1 << iota
	reads
	readsMajor
)

// versionCite names one constant or literal major by where it stands:
// "<file>#<Name>" for a constant, "<file>#<func>/major" for a major spelled
// inside a function.
type versionCite struct {
	at   string
	role int
}

// versionSpec is what the test knows of one row: the name in its Format
// cell's parentheses, where the code holds its versions, and the reader's
// own verdict on a version where a reader is exported.
type versionSpec struct {
	name    func() string
	cites   []versionCite
	refuses func(v string) (bool, error)
}

// versionRow is one row of the page's table as a reader reads it.
type versionRow struct {
	line               int
	key, name          string
	written, read      []string
	readMajor          string
	stability, rawRead string
}

var (
	versionNameRE  = regexp.MustCompile(`(?i)(version|schema|kind|major)`)
	versionValueRE = regexp.MustCompile(`^([0-9]+(\.[0-9]+)*|([a-z][a-z-]*/)?v[0-9]+((alpha|beta)[0-9]+)?)$`)
	backtickedRE   = regexp.MustCompile("`([^`]+)`")
	majorRuleRE    = regexp.MustCompile(`^([0-9]+)\.x$`)
)

// versionsNotFormats are version constants the scan finds that name no
// format of the product, each with the reason.
var versionsNotFormats = map[string]string{
	"examples/evidence-report/state.go#stateVersion": "an example program's own state",
}

// The page's table, held to the constants and the readers the code holds.
func TestVersionsPageIsTheCode(t *testing.T) {
	page, err := fs.ReadFile(repoFS(t), versionsDoc)
	if err != nil {
		t.Fatalf("reading %s: %v", versionsDoc, err)
	}
	contracts, err := fs.ReadFile(repoFS(t), "docs/contracts.md")
	if err != nil {
		t.Fatalf("reading docs/contracts.md: %v", err)
	}
	if !strings.Contains(frontmatterOf(string(contracts)), "\nstability: stable\n") {
		t.Errorf("docs/contracts.md no longer says stability: stable, which the wire row repeats")
	}
	for _, p := range versionProblems(page, versionSources(t), versionSpecs()) {
		t.Error(p)
	}
}

// versionProblems judges the page against the found versions and the specs.
func versionProblems(page []byte, found map[string]string, specs map[string]versionSpec) []string {
	rows, problems := versionRows(string(page))
	for _, key := range slices.Sorted(maps.Keys(specs)) {
		if _, ok := rows[key]; !ok {
			problems = append(problems, fmt.Sprintf("%s has no row for %q", versionsDoc, key))
		}
	}
	for _, key := range slices.Sorted(maps.Keys(rows)) {
		row := rows[key]
		spec, ok := specs[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s:%d: %q is a format this test does not know", versionsDoc, row.line, key))
			continue
		}
		problems = append(problems, rowProblems(row, spec, found)...)
	}
	return append(problems, uncitedProblems(found, specs)...)
}

// versionRows reads the table after its header, keyed by the Format cell's
// text before its parentheses.
func versionRows(page string) (map[string]versionRow, []string) {
	lines := strings.Split(page, "\n")
	start := slices.Index(lines, versionsHeader)
	if start < 0 || start+1 >= len(lines) {
		return nil, []string{fmt.Sprintf("%s has no table headed %q", versionsDoc, versionsHeader)}
	}
	rows := map[string]versionRow{}
	var problems []string
	for i := start + 2; i < len(lines) && strings.HasPrefix(lines[i], "| "); i++ {
		row, err := parseVersionRow(lines[i], i+1)
		switch _, twice := rows[row.key]; {
		case err != nil:
			problems = append(problems, err.Error())
		case twice:
			problems = append(problems, fmt.Sprintf("%s:%d: %q has two rows", versionsDoc, i+1, row.key))
		default:
			rows[row.key] = row
		}
	}
	return rows, problems
}

func parseVersionRow(line string, n int) (versionRow, error) {
	cells := strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, "| "), " |"), " | ")
	if len(cells) != 5 {
		return versionRow{}, fmt.Errorf("%s:%d: %d cells, want 5", versionsDoc, n, len(cells))
	}
	row := versionRow{line: n, key: cells[0], stability: cells[3], rawRead: cells[2]}
	if before, inside, ok := strings.Cut(cells[0], " ("); ok {
		row.key = before
		if m := backtickedRE.FindStringSubmatch(inside); m != nil {
			row.name = m[1]
		}
	}
	row.written = cellVersions(cells[1])
	row.read = cellVersions(cells[2])
	if len(row.read) == 1 {
		if m := majorRuleRE.FindStringSubmatch(row.read[0]); m != nil {
			row.read, row.readMajor = nil, m[1]
		}
	}
	return row, nil
}

// cellVersions is every backticked value of a cell, sorted; "—" holds none.
func cellVersions(cell string) []string {
	var out []string
	for _, m := range backtickedRE.FindAllStringSubmatch(cell, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func rowProblems(row versionRow, spec versionSpec, found map[string]string) []string {
	at := fmt.Sprintf("%s:%d: %s", versionsDoc, row.line, row.key)
	var problems []string
	if spec.name != nil && row.name != spec.name() {
		problems = append(problems, fmt.Sprintf("%s: names %q, the code %q", at, row.name, spec.name()))
	}
	switch stable := row.stability == versionsStable; {
	case stable != (row.key == wireRowKey):
		problems = append(problems, fmt.Sprintf("%s: stability %s; only the wire messages are stable", at, row.stability))
	case !stable && row.stability != "`experimental`" && row.stability != "alpha":
		problems = append(problems, fmt.Sprintf("%s: stability %q is neither `experimental` nor alpha", at, row.stability))
	}
	values, missing := citedValues(spec, found)
	for _, m := range missing {
		problems = append(problems, fmt.Sprintf("%s: %s is no longer in the code", at, m))
	}
	if !slices.Equal(row.written, values[writes]) {
		problems = append(problems, fmt.Sprintf("%s: written %v, the code writes %v", at, row.written, values[writes]))
	}
	return append(problems, readProblems(at, row, spec, values)...)
}

// citedValues gathers each role's values, sorted, and names a cite the scan
// did not find.
func citedValues(spec versionSpec, found map[string]string) (map[int][]string, []string) {
	values := map[int][]string{}
	var missing []string
	for _, c := range spec.cites {
		v, ok := found[c.at]
		if !ok {
			missing = append(missing, c.at)
			continue
		}
		for _, role := range []int{writes, reads, readsMajor} {
			if c.role&role != 0 {
				values[role] = append(values[role], v)
			}
		}
	}
	for role, vs := range values {
		slices.Sort(vs)
		values[role] = slices.Compact(vs)
	}
	return values, missing
}

func readProblems(at string, row versionRow, spec versionSpec, values map[int][]string) []string {
	switch {
	case row.readMajor != "":
		return majorRuleProblems(at, row, spec, values)
	case len(row.read) == 0:
		if row.rawRead != "—" || len(values[reads]) > 0 || len(values[readsMajor]) > 0 || spec.refuses != nil {
			return []string{fmt.Sprintf("%s: read %q, and the code reads it back", at, row.rawRead)}
		}
		return nil
	}
	var problems []string
	if !slices.Equal(row.read, values[reads]) && (spec.refuses == nil || !isSubset(values[reads], row.read)) {
		problems = append(problems, fmt.Sprintf("%s: read %v, the code reads %v", at, row.read, values[reads]))
	}
	problems = append(problems, otherMajors(at, row.read, values[readsMajor])...)
	return append(problems, probeProblems(at, spec, row.read, neighbours(row.read))...)
}

// otherMajors names each version read whose major is not the one the
// reader takes.
func otherMajors(at string, read, majors []string) []string {
	var problems []string
	for _, m := range majors {
		for _, v := range read {
			if major, _, _ := strings.Cut(v, "."); major != m {
				problems = append(problems, fmt.Sprintf("%s: read %s, and the reader takes major %s only", at, v, m))
			}
		}
	}
	return problems
}

// majorRuleProblems judges a row that reads any minor of one major: the
// code spells that major, or its reader accepts minors of it and refuses
// the majors either side.
func majorRuleProblems(at string, row versionRow, spec versionSpec, values map[int][]string) []string {
	var problems []string
	for _, v := range values[reads] {
		if major, _, _ := strings.Cut(v, "."); major != row.readMajor {
			problems = append(problems, fmt.Sprintf("%s: reads %s.x, and the code reads %s", at, row.readMajor, v))
		}
	}
	for _, m := range values[readsMajor] {
		if m != row.readMajor {
			problems = append(problems, fmt.Sprintf("%s: reads %s.x, and the code reads major %s", at, row.readMajor, m))
		}
	}
	if len(values[readsMajor]) == 0 && spec.refuses == nil {
		problems = append(problems, fmt.Sprintf("%s: reads %s.x, and nothing in the code pins that major", at, row.readMajor))
	}
	n, err := strconv.Atoi(row.readMajor)
	if err != nil {
		return append(problems, fmt.Sprintf("%s: major %q is not a number", at, row.readMajor))
	}
	refused := []string{fmt.Sprintf("%d.0", n+1)}
	if n > 0 {
		refused = append(refused, fmt.Sprintf("%d.9", n-1))
	}
	return append(problems, probeProblems(at, spec, []string{row.readMajor + ".0", row.readMajor + ".7"}, refused)...)
}

// probeProblems asks the row's reader, where one is exported, to accept
// each version of accepted and to refuse each of refused.
func probeProblems(at string, spec versionSpec, accepted, refused []string) []string {
	if spec.refuses == nil {
		return nil
	}
	var problems []string
	for _, v := range slices.Concat(accepted, refused) {
		got, err := spec.refuses(v)
		switch want := !slices.Contains(accepted, v); {
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: the reader could not be asked about %s: %v", at, v, err))
		case got && !want:
			problems = append(problems, fmt.Sprintf("%s: the page says %s is read, and the reader refuses it", at, v))
		case !got && want:
			problems = append(problems, fmt.Sprintf("%s: the reader accepts %s, which the page does not name", at, v))
		}
	}
	return problems
}

// neighbours are the versions next to an exact set that it leaves out: the
// next minor and the next major of a number, the next alpha and the
// release of a kind.
func neighbours(set []string) []string {
	var out []string
	for _, v := range set {
		out = append(out, neighboursOf(v)...)
	}
	return slices.DeleteFunc(out, func(v string) bool { return slices.Contains(set, v) })
}

func neighboursOf(v string) []string {
	if base, alpha, ok := strings.Cut(v, "alpha"); ok {
		n, err := strconv.Atoi(alpha)
		if err != nil {
			return nil
		}
		return []string{base + "alpha" + strconv.Itoa(n+1), base}
	}
	major, minor, dotted := strings.Cut(v, ".")
	a, errA := strconv.Atoi(major)
	b, errB := strconv.Atoi(minor)
	switch {
	case !dotted && errA == nil:
		return []string{strconv.Itoa(a + 1), v + ".0"}
	case dotted && errA == nil && errB == nil && !strings.Contains(minor, "."):
		return []string{fmt.Sprintf("%d.%d", a, b+1), fmt.Sprintf("%d.0", a+1)}
	}
	return nil
}

func isSubset(sub, set []string) bool {
	return !slices.ContainsFunc(sub, func(v string) bool { return !slices.Contains(set, v) })
}

// uncitedProblems names each version the scan found that no row cites and
// that is not set apart as naming no format, and each one set apart that the
// scan no longer finds.
func uncitedProblems(found map[string]string, specs map[string]versionSpec) []string {
	cited := map[string]bool{}
	for _, spec := range specs {
		for _, c := range spec.cites {
			cited[c.at] = true
		}
	}
	var problems []string
	for _, at := range slices.Sorted(maps.Keys(found)) {
		if _, apart := versionsNotFormats[at]; !cited[at] && !apart {
			problems = append(problems, fmt.Sprintf("%s holds version %q, and %s has no row citing it", at, found[at], versionsDoc))
		}
	}
	for _, at := range slices.Sorted(maps.Keys(versionsNotFormats)) {
		if _, ok := found[at]; !ok {
			problems = append(problems, fmt.Sprintf("versionsNotFormats sets apart %s, which the scan no longer finds", at))
		}
	}
	return problems
}

// versionSources scans the module's hand-written Go for the versions it
// spells: each constant whose name speaks of a version, schema, kind or
// major and whose value reads as a version, and each major a function
// compares a version against as a literal.
func versionSources(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	fsys := repoFS(t)
	found := map[string]string{}
	for _, file := range repoFiles(t, root) {
		if !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") ||
			strings.HasPrefix(file, "api/gen/") || strings.HasPrefix(file, "internal/docscheck/") ||
			strings.Contains("/"+file, "/testdata/") {
			continue
		}
		src, err := fs.ReadFile(fsys, file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}
		for at, v := range fileVersions(file, f) {
			if prior, ok := found[at]; ok && prior != v {
				t.Errorf("%s spells two majors, %q and %q", at, prior, v)
			}
			found[at] = v
		}
	}
	return found
}

func fileVersions(file string, f *ast.File) map[string]string {
	found := map[string]string{}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok == token.CONST {
				constVersions(file, d, found)
			}
		case *ast.FuncDecl:
			if d.Body != nil {
				majorLiterals(file+"#"+d.Name.Name+"/major", d.Body, found)
			}
		}
	}
	return found
}

func constVersions(file string, d *ast.GenDecl, found map[string]string) {
	for _, spec := range d.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range vs.Names {
			if i >= len(vs.Values) || !versionNameRE.MatchString(name.Name) {
				continue
			}
			if v, ok := stringLiteral(vs.Values[i]); ok && versionValueRE.MatchString(v) {
				found[file+"#"+name.Name] = v
			}
		}
	}
}

// majorLiterals finds `IsVersion(v, "<major>")` and `major == "<major>"`. A
// function that spells two majors is recorded with both, which matches no
// row.
func majorLiterals(at string, body *ast.BlockStmt, found map[string]string) {
	ast.Inspect(body, func(n ast.Node) bool {
		if v, ok := majorLiteral(n); ok {
			if prior, seen := found[at]; seen && prior != v {
				v = prior + " and " + v
			}
			found[at] = v
		}
		return true
	})
}

func majorLiteral(n ast.Node) (string, bool) {
	switch e := n.(type) {
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "IsVersion" && len(e.Args) == 2 {
			return stringLiteral(e.Args[1])
		}
	case *ast.BinaryExpr:
		if e.Op != token.EQL && e.Op != token.NEQ {
			return "", false
		}
		for _, pair := range [][2]ast.Expr{{e.X, e.Y}, {e.Y, e.X}} {
			if id, ok := pair[0].(*ast.Ident); ok && id.Name == "major" {
				return stringLiteral(pair[1])
			}
		}
	}
	return "", false
}

func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	return v, err == nil
}

// frontmatterOf is the page's frontmatter block, its fences included.
func frontmatterOf(page string) string {
	if !strings.HasPrefix(page, "---\n") {
		return ""
	}
	end := strings.Index(page[4:], "\n---\n")
	if end < 0 {
		return ""
	}
	return page[:end+9]
}

// Each change below, to the page or to what the code holds, is one the pin
// above must refuse; the base it changes passes.
func TestVersionsPinRefusesAPageThatDisagrees(t *testing.T) {
	page, err := fs.ReadFile(repoFS(t), versionsDoc)
	if err != nil {
		t.Fatalf("reading %s: %v", versionsDoc, err)
	}
	found := versionSources(t)
	if p := versionProblems(page, found, versionSpecs()); len(p) != 0 {
		t.Fatalf("the base the cases change does not pass: %v", p)
	}
	edit := func(from, to string) func(string, map[string]string) string {
		return func(s string, _ map[string]string) string { return strings.Replace(s, from, to, 1) }
	}
	cases := map[string]struct {
		change func(page string, found map[string]string) string
		want   string
	}{
		"a written version edited":          {edit("| Stop list (`version`) | `1.0` |", "| Stop list (`version`) | `1.1` |"), "written [1.1], the code writes [1.0]"},
		"a read version dropped":            {edit("| — | `0.1`, `0.2` | `experimental` | [supervision.md]", "| — | `0.1` | `experimental` | [supervision.md]"), "the code reads [0.1 0.2]"},
		"a read version the reader refuses": {edit("| — | `0.1`, `0.2` | `experimental` | [supervision.md]", "| — | `0.1`, `0.2`, `0.3` | `experimental` | [supervision.md]"), "0.3 is read, and the reader refuses it"},
		"a major the reader refuses":        {edit("| `1.0` | `1.x` | `stable` |", "| `1.0` | `2.x` | `stable` |"), "the reader refuses it"},
		"a row this test does not know":     {edit("\n\nThe gateway's", "\n| Notes file (`v`) | — | `1` | `experimental` | [x](x.md) |\n\nThe gateway's"), `"Notes file" is a format this test does not know`},
		"a row removed":                     {edit("| Lift (`kind`, `version`) |", "Lift (`kind`, `version`) |"), `has no row for "Lift"`},
		"another row claiming stable":       {edit("| `1.0` | `1.0` | `experimental` |", "| `1.0` | `1.0` | `stable` |"), "only the wire messages are stable"},
		"a wrong format name":               {edit("(`"+findinglog.ExportFormat+"`)", "(`findings-export`)"), `names "findings-export"`},
		"a constant changed in the code": {func(s string, f map[string]string) string {
			f["internal/reaction/lift.go#LiftVersion"] = "1.1"
			return s
		}, "the code writes [1.1 reaction-lift/v1alpha1]"},
		"a constant gone from the code": {func(s string, f map[string]string) string {
			delete(f, "internal/runs/strict.go#checkSchemaVersion/major")
			return s
		}, "checkSchemaVersion/major is no longer in the code"},
		"a constant set apart gone from the code": {func(s string, f map[string]string) string {
			delete(f, "examples/evidence-report/state.go#stateVersion")
			return s
		}, "versionsNotFormats sets apart examples/evidence-report/state.go#stateVersion, which the scan no longer finds"},
		"a version the page lacks": {func(s string, f map[string]string) string {
			f["internal/notes/notes.go#SchemaVersion"] = "0.1"
			return s
		}, `internal/notes/notes.go#SchemaVersion holds version "0.1"`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := maps.Clone(found)
			changed := c.change(string(page), f)
			if changed == string(page) && maps.Equal(f, found) {
				t.Fatal("the change changed nothing")
			}
			problems := versionProblems([]byte(changed), f, versionSpecs())
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, c.want) }) {
				t.Errorf("no problem says %q; got %v", c.want, problems)
			}
		})
	}
}

// The scan keeps what reads as a version under a name that speaks of one,
// and a function spelling two majors matches neither.
func TestVersionScanReadsWhatTheCodeSpells(t *testing.T) {
	src := `package p
const (
	FormatVersion = "0.3"
	DocKind = "notes/v1alpha2"
	APIVersion = "v2beta1"
	PathVersion = "v1alpha"
	kindHeader = "header"
	MaxBytes = "1"
)
func check(v, major string) bool { return major != "2" }
func both(v string) bool { return x.IsVersion(v, "1") || x.IsVersion(v, "2") }
`
	f, err := parser.ParseFile(token.NewFileSet(), "p.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"p.go#FormatVersion": "0.3",
		"p.go#DocKind":       "notes/v1alpha2",
		"p.go#APIVersion":    "v2beta1",
		"p.go#check/major":   "2",
		"p.go#both/major":    "1 and 2",
	}
	if got := fileVersions("p.go", f); !maps.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}
