package docscheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

const (
	portsFile   = "scripts/ports.txt"
	portsCases  = "testdata/ports"
	portsFields = 5
)

// noDoctor names each port whose record says its component has no doctor of
// its own, with that record and the words in it that say so. Only these
// ports may give "none" as their doctor key.
var noDoctor = map[string][2]string{
	"record-log": {"docs/adr/0072-the-collector-keeps-bounded-segments-of-one-project-behind-a-credential.md", "has no `/metrics` or `doctor` of its own"},
}

// portDoc is how a doc comment documents an interface as a port: "Roster is
// the trust roster port: ...", "X is the record-gauge port.", "X is a port,".
var portDoc = regexp.MustCompile(`^([A-Z]\w*) is (?:an?|the(?: [A-Za-z0-9-]+)*) port[:.,;]`)

type portLine struct {
	at                    int
	name, iface, dir, doc string
	fields                []string
}

func readPortLines(data []byte) []portLine {
	var lines []portLine
	for i, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, " ")
		p := portLine{at: i + 1, name: f[0], fields: f}
		if len(f) > 1 {
			p.iface = f[1]
		}
		if len(f) > 3 {
			p.dir = f[3]
		}
		if len(f) > 4 {
			p.doc = f[4]
		}
		lines = append(lines, p)
	}
	return lines
}

// portProblems holds scripts/ports.txt to the tree in fsys: every line whole,
// its interface an exported interface type of its package, its conformance
// directory holding cases with a negative control for every rule, its doctor
// key named; and every conformance directory under testdata/ports and every
// interface goFiles document as a port listed.
func portProblems(fsys fs.FS, goFiles []string) []string {
	data, err := fs.ReadFile(fsys, portsFile)
	if err != nil {
		return []string{err.Error()}
	}
	lines := readPortLines(data)
	if len(lines) == 0 {
		return []string{portsFile + " lists no port"}
	}
	var problems []string
	listedIface, listedDir := map[string]bool{}, map[string]bool{}
	for _, p := range lines {
		listedIface[p.iface], listedDir[p.dir] = true, true
		problems = append(problems, lineProblems(fsys, p)...)
	}
	problems = append(problems, unlistedCaseDirs(fsys, listedDir)...)
	for _, iface := range documentedPorts(fsys, goFiles, &problems) {
		if !listedIface[iface] {
			problems = append(problems, fmt.Sprintf("%s is documented as a port and no line of %s lists it", iface, portsFile))
		}
	}
	return problems
}

// lineProblems holds one line of the list to its fields, its interface, its
// conformance directory and its doctor key.
func lineProblems(fsys fs.FS, p portLine) []string {
	if len(p.fields) != portsFields || slices.Contains(p.fields, "") {
		return []string{fmt.Sprintf("%s:%d: %d field(s), want %d, none of them empty", portsFile, p.at, len(p.fields), portsFields)}
	}
	var problems []string
	if problem := interfaceProblem(fsys, p.iface); problem != "" {
		problems = append(problems, fmt.Sprintf("%s:%d: %s", portsFile, p.at, problem))
	}
	problems = append(problems, conformanceProblems(fsys, p)...)
	if p.doc == "none" && !recordSaysNoDoctor(fsys, p.name) {
		problems = append(problems, fmt.Sprintf("%s:%d: port %s gives doctor key none, and no record says its component has no doctor", portsFile, p.at, p.name))
	}
	return problems
}

// unlistedCaseDirs names each directory under testdata/ports no line lists.
func unlistedCaseDirs(fsys fs.FS, listed map[string]bool) []string {
	entries, err := fs.ReadDir(fsys, portsCases)
	if err != nil {
		return []string{err.Error()}
	}
	var problems []string
	for _, e := range entries {
		if dir := portsCases + "/" + e.Name(); e.IsDir() && !listed[dir] {
			problems = append(problems, fmt.Sprintf("%s holds conformance cases and no line of %s lists it", dir, portsFile))
		}
	}
	return problems
}

// interfaceProblem says why iface, "<package path>.<type>", is not an exported
// interface type declared in that package's Go files, or returns "".
func interfaceProblem(fsys fs.FS, iface string) string {
	dir, name, _ := strings.Cut(iface, ".")
	if !token.IsExported(name) {
		return fmt.Sprintf("%s does not name an exported type", iface)
	}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return fmt.Sprintf("%s: %v", iface, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parseGo(fsys, dir+"/"+e.Name())
		if err != nil {
			return err.Error()
		}
		for _, decl := range file.Decls {
			for _, ts := range typeSpecs(decl) {
				if ts.Name.Name == name {
					if _, ok := ts.Type.(*ast.InterfaceType); ok {
						return ""
					}
					return fmt.Sprintf("%s is a type of %s that is not an interface", iface, dir)
				}
			}
		}
	}
	return fmt.Sprintf("%s is not a type declared in %s", iface, dir)
}

// conformanceProblems refuses a conformance directory that is absent or holds
// no case file, and a rule in it with no negative control. Two schemas are
// read: one file of cases each marked "control" or not, where a rule needs
// both kinds; and one file per rule, with its "steps" and a non-empty
// "negative_control".
func conformanceProblems(fsys fs.FS, p portLine) []string {
	entries, err := fs.ReadDir(fsys, p.dir)
	if err != nil {
		return []string{fmt.Sprintf("port %s: conformance directory %s is absent: %v", p.name, p.dir, err)}
	}
	var problems []string
	cases := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		cases++
		rel := p.dir + "/" + e.Name()
		for _, problem := range caseFileProblems(fsys, rel) {
			problems = append(problems, fmt.Sprintf("port %s: %s: %s", p.name, rel, problem))
		}
	}
	if cases == 0 {
		problems = append(problems, fmt.Sprintf("port %s: conformance directory %s holds no case file", p.name, p.dir))
	}
	return problems
}

func caseFileProblems(fsys fs.FS, rel string) []string {
	data, err := fs.ReadFile(fsys, rel)
	if err != nil {
		return []string{err.Error()}
	}
	var file struct {
		Cases *[]struct {
			Rule    string `json:"rule"`
			Control bool   `json:"control"`
		} `json:"cases"`
		Rule            string            `json:"rule"`
		NegativeControl []json.RawMessage `json:"negative_control"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return []string{err.Error()}
	}
	switch {
	case file.Cases != nil:
		seen := map[string][2]int{}
		for _, c := range *file.Cases {
			n := seen[c.Rule]
			n[boolIndex(c.Control)]++
			seen[c.Rule] = n
		}
		return uncontrolledRules(seen)
	case file.Rule != "" && len(file.NegativeControl) == 0:
		return []string{fmt.Sprintf("rule %q has no negative control", file.Rule)}
	case file.Rule == "":
		return []string{"names neither cases nor a rule"}
	}
	return nil
}

func boolIndex(b bool) int {
	if b {
		return 1
	}
	return 0
}

// uncontrolledRules names each rule of seen, counted as cases and controls,
// that lacks either.
func uncontrolledRules(seen map[string][2]int) []string {
	var problems []string
	for rule, n := range seen {
		if n[0] == 0 || n[1] == 0 {
			problems = append(problems, fmt.Sprintf("rule %q has %d case(s) and %d negative control(s)", rule, n[0], n[1]))
		}
	}
	if len(seen) == 0 {
		problems = append(problems, "holds no case")
	}
	slices.Sort(problems)
	return problems
}

func recordSaysNoDoctor(fsys fs.FS, port string) bool {
	record, ok := noDoctor[port]
	if !ok {
		return false
	}
	data, err := fs.ReadFile(fsys, record[0])
	return err == nil && strings.Contains(strings.Join(strings.Fields(string(data)), " "), record[1])
}

// documentedPorts returns, as "<package path>.<type>", every exported
// interface of goFiles whose doc comment says it is a port.
func documentedPorts(fsys fs.FS, goFiles []string, problems *[]string) []string {
	var found []string
	for _, rel := range goFiles {
		src, err := fs.ReadFile(fsys, rel)
		if err != nil {
			*problems = append(*problems, err.Error())
			continue
		}
		if !bytes.Contains(src, []byte(" port")) {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			*problems = append(*problems, err.Error())
			continue
		}
		for _, decl := range file.Decls {
			for _, name := range portsDeclared(decl) {
				found = append(found, path.Dir(rel)+"."+name)
			}
		}
	}
	return found
}

// portsDeclared names each exported interface of decl whose doc comment says
// it is a port.
func portsDeclared(decl ast.Decl) []string {
	var names []string
	for _, ts := range typeSpecs(decl) {
		doc := ts.Doc
		if gd := decl.(*ast.GenDecl); doc == nil && len(gd.Specs) == 1 {
			doc = gd.Doc
		}
		if _, ok := ts.Type.(*ast.InterfaceType); !ok || doc == nil || !ts.Name.IsExported() {
			continue
		}
		if m := portDoc.FindStringSubmatch(strings.ReplaceAll(doc.Text(), "\n", " ")); m != nil && m[1] == ts.Name.Name {
			names = append(names, ts.Name.Name)
		}
	}
	return names
}

func typeSpecs(decl ast.Decl) []*ast.TypeSpec {
	gd, ok := decl.(*ast.GenDecl)
	if !ok || gd.Tok != token.TYPE {
		return nil
	}
	specs := make([]*ast.TypeSpec, 0, len(gd.Specs))
	for _, s := range gd.Specs {
		specs = append(specs, s.(*ast.TypeSpec))
	}
	return specs
}

func parseGo(fsys fs.FS, rel string) (*ast.File, error) {
	src, err := fs.ReadFile(fsys, rel)
	if err != nil {
		return nil, err
	}
	return parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
}

// productionGoFiles keeps the Go files of files that are neither tests nor
// fixtures nor generated.
func productionGoFiles(files []string) []string {
	var kept []string
	for _, rel := range files {
		if strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") &&
			!strings.Contains("/"+rel, "/testdata/") && !strings.HasPrefix(rel, "api/gen/") {
			kept = append(kept, rel)
		}
	}
	return kept
}

func TestPortsListEveryPortWhole(t *testing.T) {
	root := repoRoot(t)
	goFiles := productionGoFiles(repoFiles(t, root))
	if len(goFiles) == 0 {
		t.Fatal("the repository lists no production Go file, so no doc comment was read")
	}
	for _, problem := range portProblems(repoFS(t), goFiles) {
		t.Error(problem)
	}
	var problems []string
	found := documentedPorts(repoFS(t), goFiles, &problems)
	for _, iface := range []string{"internal/trust.Roster", "internal/operators.Authenticator", "internal/operators.Authorizer", "internal/segmentlog.RecordLog"} {
		if !slices.Contains(found, iface) {
			t.Errorf("%s is not documented as a port, so the documented side would check nothing: found %q", iface, found)
		}
	}
}

// stagePorts copies from the repository what portProblems reads about the
// ports listed today: the list, every conformance file, the Go files of each
// interface's package and the records noDoctor names.
func stagePorts(t *testing.T) fstest.MapFS {
	t.Helper()
	repo := repoFS(t)
	stage := fstest.MapFS{}
	add := func(rel string) {
		data, err := fs.ReadFile(repo, rel)
		if err != nil {
			t.Fatal(err)
		}
		stage[rel] = &fstest.MapFile{Data: data}
	}
	add(portsFile)
	for _, record := range noDoctor {
		add(record[0])
	}
	err := fs.WalkDir(repo, portsCases, func(rel string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			add(rel)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := fs.ReadFile(repo, portsFile)
	for _, p := range readPortLines(data) {
		dir, _, _ := strings.Cut(p.iface, ".")
		names, err := fs.Glob(repo, dir+"/*.go")
		if err != nil || len(names) == 0 {
			t.Fatalf("%s: no Go file to stage: %v", dir, err)
		}
		for _, rel := range names {
			add(rel)
		}
	}
	return stage
}

func stagedGoFiles(stage fstest.MapFS) []string {
	var files []string
	for rel := range stage {
		files = append(files, rel)
	}
	slices.Sort(files)
	return productionGoFiles(files)
}

func replaceIn(t *testing.T, stage fstest.MapFS, rel, old, repl string) {
	t.Helper()
	f, ok := stage[rel]
	if !ok || !bytes.Contains(f.Data, []byte(old)) {
		t.Fatalf("%s does not hold %q, so the plant would change nothing", rel, old)
	}
	stage[rel] = &fstest.MapFile{Data: bytes.Replace(f.Data, []byte(old), []byte(repl), 1)}
}

// addLine appends one line to the staged list, beside the lines it holds.
func addLine(stage fstest.MapFS, line string) {
	stage[portsFile] = &fstest.MapFile{Data: append(slices.Clone(stage[portsFile].Data), []byte(line+"\n")...)}
}

func removeUnder(stage fstest.MapFS, dir string) {
	for rel := range stage {
		if strings.HasPrefix(rel, dir+"/") {
			delete(stage, rel)
		}
	}
}

// dropControls rewrites one cases file so that the first rule's controls are
// cases like the rest, which leaves that rule with no negative control.
func dropControls(t *testing.T, stage fstest.MapFS, rel string) {
	t.Helper()
	var file map[string]any
	if err := json.Unmarshal(stage[rel].Data, &file); err != nil {
		t.Fatal(err)
	}
	cases, _ := file["cases"].([]any)
	if len(cases) == 0 {
		t.Fatalf("%s holds no case to plant in", rel)
	}
	first := cases[0].(map[string]any)["rule"]
	for _, c := range cases {
		if m := c.(map[string]any); m["rule"] == first {
			delete(m, "control")
		}
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	stage[rel] = &fstest.MapFile{Data: data}
}

// TestPortProblemsRefuseEachPlantedDefect plants one defect per case in a
// staged copy and requires exactly one problem, holding the words of its own
// reason.
func TestPortProblemsRefuseEachPlantedDefect(t *testing.T) {
	const (
		trustLine  = "trust-roster internal/trust.Roster file testdata/ports/trust-roster trust"
		recordCase = "testdata/ports/record-log/01-the-budget-refuses.json"
	)
	clean := stagePorts(t)
	if problems := portProblems(clean, stagedGoFiles(clean)); len(problems) != 0 {
		t.Fatalf("the staged copy is refused before any plant: %q", problems)
	}
	for name, c := range map[string]struct {
		plant func(fstest.MapFS)
		want  string
	}{
		"a line lacks its doctor key": {func(s fstest.MapFS) {
			replaceIn(t, s, portsFile, trustLine, strings.TrimSuffix(trustLine, " trust"))
		}, "4 field(s), want 5"},
		"a line has an extra field": {func(s fstest.MapFS) {
			replaceIn(t, s, portsFile, trustLine, trustLine+" extra")
		}, "6 field(s), want 5"},
		"a field is empty": {func(s fstest.MapFS) {
			replaceIn(t, s, portsFile, trustLine, strings.Replace(trustLine, " file ", "  ", 1))
		}, "none of them empty"},
		"the interface is a struct": {func(s fstest.MapFS) {
			addLine(s, "record-log internal/segmentlog.Config segments testdata/ports/record-log none")
		}, "is a type of internal/segmentlog that is not an interface"},
		"the interface is unexported": {func(s fstest.MapFS) {
			addLine(s, "record-log internal/segmentlog.recordLog segments testdata/ports/record-log none")
		}, "does not name an exported type"},
		"the package declares no such type": {func(s fstest.MapFS) {
			addLine(s, "record-log internal/segmentlog.Journal segments testdata/ports/record-log none")
		}, "is not a type declared in internal/segmentlog"},
		"the conformance directory is absent": {func(s fstest.MapFS) {
			removeUnder(s, "testdata/ports/record-log")
		}, "conformance directory testdata/ports/record-log is absent"},
		"the conformance directory holds no case file": {func(s fstest.MapFS) {
			removeUnder(s, "testdata/ports/record-log")
			s["testdata/ports/record-log/README.md"] = &fstest.MapFile{Data: []byte("notes\n")}
		}, "holds no case file"},
		"a case file's rule has no negative control": {func(s fstest.MapFS) {
			replaceIn(t, s, recordCase, `"negative_control"`, `"unused"`)
		}, "has no negative control"},
		"a rule in a cases file has no control": {func(s fstest.MapFS) {
			dropControls(t, s, "testdata/ports/trust-roster/cases.json")
		}, "0 negative control(s)"},
		"doctor key none on a port with a doctor": {func(s fstest.MapFS) {
			replaceIn(t, s, portsFile, trustLine, strings.TrimSuffix(trustLine, "trust")+"none")
		}, "port trust-roster gives doctor key none"},
		"doctor key none and the record no longer says so": {func(s fstest.MapFS) {
			replaceIn(t, s, noDoctor["record-log"][0], "`doctor` of its own", "doctor of its own")
		}, "port record-log gives doctor key none"},
		"a conformance directory no line lists": {func(s fstest.MapFS) {
			s["testdata/ports/planted/cases.json"] = &fstest.MapFile{Data: []byte(`{"cases":[]}`)}
		}, "testdata/ports/planted holds conformance cases and no line"},
		"an interface documented as a hyphenated port no line lists": {func(s fstest.MapFS) {
			s["internal/planted/gauge.go"] = &fstest.MapFile{Data: []byte("package planted\n\n// Gauge is the record-gauge port: what a gauge reads.\ntype Gauge interface{ Read() int }\n")}
		}, "internal/planted.Gauge is documented as a port"},
		"an interface documented as a port by a capitalised name no line lists": {func(s fstest.MapFS) {
			s["internal/planted/meter.go"] = &fstest.MapFile{Data: []byte("package planted\n\n// Meter is the Meter port: what a meter reads.\ntype Meter interface{ Read() int }\n")}
		}, "internal/planted.Meter is documented as a port"},
		"an interface documented as a port alone no line lists": {func(s fstest.MapFS) {
			s["internal/planted/dial.go"] = &fstest.MapFile{Data: []byte("package planted\n\n// Dial is a port: what a dial reads.\ntype Dial interface{ Read() int }\n")}
		}, "internal/planted.Dial is documented as a port"},
		"an interface documented as a port no line lists": {func(s fstest.MapFS) {
			s["internal/planted/gauge.go"] = &fstest.MapFile{Data: []byte("package planted\n\n// Gauge is the gauge port: what a gauge reads.\ntype Gauge interface{ Read() int }\n")}
		}, "internal/planted.Gauge is documented as a port"},
	} {
		t.Run(name, func(t *testing.T) {
			stage := fstest.MapFS{}
			for rel, f := range clean {
				stage[rel] = f
			}
			c.plant(stage)
			problems := portProblems(stage, stagedGoFiles(stage))
			if len(problems) != 1 || !strings.Contains(problems[0], c.want) {
				t.Errorf("problems %q, want exactly one holding %q", problems, c.want)
			}
		})
	}
}
