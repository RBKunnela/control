package docscheck

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

const golangciPath = ".golangci.yml"

// The linters golangci-lint's "standard" default set runs besides those
// enabled by name.
var standardLinters = []string{"errcheck", "govet", "ineffassign", "staticcheck", "unused"}

// enabledLinters reads the linters .golangci.yml runs: its default set, which
// must be one this test knows, and those it enables by name.
func enabledLinters(lines []string) ([]string, error) {
	root, err := parseBlockYAML(lines)
	if err != nil {
		return nil, err
	}
	sections := root.children("linters")
	if len(sections) != 1 {
		return nil, fmt.Errorf("%d linters sections, want 1", len(sections))
	}
	var enabled []string
	for _, d := range sections[0].children("default") {
		if d.value != "standard" {
			return nil, fmt.Errorf("line %d: default %q is not the standard set this test knows", d.line, d.value)
		}
		enabled = append(enabled, standardLinters...)
	}
	for _, list := range sections[0].children("enable") {
		enabled = append(enabled, sequence(list)...)
	}
	if len(enabled) == 0 {
		return nil, fmt.Errorf("no linter is enabled")
	}
	return enabled, nil
}

// nolintProblems judges one comment: a nolint directive that names a linter
// the configuration does not run suppresses nothing, and nolintlint, which
// reports an unused directive, cannot see one for a linter that never ran.
func nolintProblems(comment string, enabled []string) []string {
	text := strings.TrimLeft(strings.TrimPrefix(comment, "//"), " ")
	rest, ok := strings.CutPrefix(text, "nolint:")
	if !ok {
		return nil
	}
	names, _, _ := strings.Cut(rest, "//")
	fields := strings.Fields(names)
	if len(fields) == 0 {
		return []string{"names no linter"}
	}
	var problems []string
	for _, name := range strings.Split(fields[0], ",") {
		if name = strings.TrimSpace(name); !slices.Contains(enabled, name) {
			problems = append(problems, fmt.Sprintf("names %q, which %s does not enable, so it suppresses nothing", name, golangciPath))
		}
	}
	return problems
}

func TestNolintNamesAnEnabledLinter(t *testing.T) {
	fsys := repoFS(t)
	enabled, err := enabledLinters(readLines(t, fsys, golangciPath))
	if err != nil {
		t.Fatalf("%s: %v", golangciPath, err)
	}
	files, directives := 0, 0
	for _, file := range repoFiles(t, repoRoot(t)) {
		if !strings.HasSuffix(file, ".go") || strings.HasPrefix(file, "api/gen/") || strings.Contains("/"+file, "/testdata/") {
			continue
		}
		src, err := fs.ReadFile(fsys, file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		problems, n, err := fileNolintProblems(file, src, enabled)
		if err != nil {
			t.Fatal(err)
		}
		files, directives = files+1, directives+n
		for _, p := range problems {
			t.Error(p)
		}
	}
	if files == 0 || directives == 0 {
		t.Fatalf("read %d Go file(s) and %d nolint directive(s); the walk examined nothing", files, directives)
	}
}

// fileNolintProblems judges every nolint directive in one Go file's comments
// and counts them.
func fileNolintProblems(file string, src []byte, enabled []string) ([]string, int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing %s: %w", file, err)
	}
	var problems []string
	directives := 0
	for _, group := range f.Comments {
		for _, c := range group.List {
			if strings.Contains(c.Text, "nolint:") {
				directives++
			}
			for _, p := range nolintProblems(c.Text, enabled) {
				problems = append(problems, fmt.Sprintf("%s: a nolint directive %s", fset.Position(c.Pos()), p))
			}
		}
	}
	return problems, directives, nil
}

func TestNolintProblems(t *testing.T) {
	enabled := []string{"gosec", "errcheck"}
	for comment, want := range map[string][]string{
		"//nolint:gosec // G304: the test's own directory":     nil,
		"//nolint:gosec,errcheck // both, for a reason":        nil,
		"// nolint:gosec // a reason":                          nil,
		"// a comment that mentions nolint:noctx in prose":     nil,
		"//nolint:noctx // the collector this test started":    {`names "noctx"`},
		"//nolint:gosec,noctx // a reason":                     {`names "noctx"`},
		"//nolint:forcetypeassert // turns holds nothing else": {`names "forcetypeassert"`},
		"//nolint:noctx,forcetypeassert // a reason":           {`names "noctx"`, `names "forcetypeassert"`},
		"//nolint:gosec,errcheck":                              nil,
		"//nolint:noctx":                                       {`names "noctx"`},
		"//nolint: // a reason":                                {"names no linter"},
	} {
		got := nolintProblems(comment, enabled)
		if len(got) != len(want) {
			t.Errorf("%s: %d problems, want %d: %q", comment, len(got), len(want), got)
			continue
		}
		for i, w := range want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%s: problem %q does not say %q", comment, got[i], w)
			}
		}
	}
}

func TestEnabledLinters(t *testing.T) {
	good := "version: \"2\"\nlinters:\n  default: standard\n  enable:\n    - gosec\n    - nolintlint\n  settings:\n    gocyclo:\n      min-complexity: 12\n"
	got, err := enabledLinters(strings.Split(good, "\n"))
	if err != nil || !slices.Equal(got, append(slices.Clone(standardLinters), "gosec", "nolintlint")) {
		t.Fatalf("enabledLinters = %q, %v", got, err)
	}
	for name, c := range map[string]struct{ old, replacement, want string }{
		"another default set": {"default: standard", "default: all", `default "all"`},
		"no linters section":  {"linters:", "linting:", "0 linters sections"},
		"nothing enabled":     {"  default: standard\n  enable:\n    - gosec\n    - nolintlint\n", "", "no linter is enabled"},
	} {
		_, err := enabledLinters(strings.Split(replaceOnce(t, good, c.old, c.replacement), "\n"))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want one saying %q", name, err, c.want)
		}
	}
}
