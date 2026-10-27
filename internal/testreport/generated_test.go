package testreport_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/guardana/control/internal/testreport"
)

// noTestFiles is the stream go test writes for a package with no test files.
func noTestFiles(pkg string) string {
	return `{"Action":"output","Package":"` + pkg + `","Output":"?   \t` + pkg + `\t[no test files]\n"}
{"Action":"skip","Package":"` + pkg + `"}
`
}

func TestSummarizePassesNoTestFilesOnlyUnderGenerated(t *testing.T) {
	const prefix = "example.com/m/api/gen/"
	cases := []struct {
		name, pkg, generated string
		pass                 bool
	}{
		{"a generated package", "example.com/m/api/gen/v1", prefix, true},
		{"a generated package two levels down", "example.com/m/api/gen/a/v1", prefix, true},
		{"the generated directory itself", "example.com/m/api/gen", prefix, false},
		{"a sibling directory", "example.com/m/api/generated/v1", prefix, false},
		{"api/gen of another module", "example.com/other/api/gen/v1", prefix, false},
		{"api/gen deeper in the module", "example.com/m/internal/api/gen/v1", prefix, false},
		{"a package outside it", "example.com/m/internal/thing", prefix, false},
		{"no prefix", "example.com/m/api/gen/v1", "", false},
		{"a prefix without its slash", "example.com/m/api/gen/v1", "example.com/m/api/gen", false},
		{"a prefix without its slash, a longer name", "example.com/m/api/genx/v1", "example.com/m/api/gen", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := testreport.Summarize(strings.NewReader(noTestFiles(tc.pkg)), &bytes.Buffer{}, tc.generated, nil)
			if tc.pass {
				if err != nil || got.NoTestFiles != 0 {
					t.Fatalf("Summarize = %+v, %v; want a pass", got, err)
				}
				return
			}
			if !errors.Is(err, testreport.ErrNoTestFiles) {
				t.Fatalf("Summarize error = %v, want ErrNoTestFiles", err)
			}
			if !strings.HasSuffix(err.Error(), ": "+tc.pkg) {
				t.Errorf("error %q does not name %s", err, tc.pkg)
			}
			if got.NoTestFiles != 1 || got.Packages != 1 {
				t.Errorf("Summary = %+v, want 1 package, refused for having no test files", got)
			}
		})
	}
}

func TestSummarizeNamesEveryPackageWithNoTestFiles(t *testing.T) {
	input := noTestFiles("example.com/m/a") + noTestFiles("example.com/m/api/gen/v1") + noTestFiles("example.com/m/b")
	got, err := testreport.Summarize(strings.NewReader(input), &bytes.Buffer{}, "example.com/m/api/gen/", nil)
	if !errors.Is(err, testreport.ErrNoTestFiles) {
		t.Fatalf("Summarize error = %v, want ErrNoTestFiles", err)
	}
	if !strings.HasSuffix(err.Error(), ": example.com/m/a, example.com/m/b") {
		t.Errorf("error %q does not name exactly the two packages outside generated code", err)
	}
	if got.NoTestFiles != 2 || got.Packages != 3 {
		t.Errorf("Summary = %+v, want 3 packages, 2 refused", got)
	}
}

func TestGeneratedPrefix(t *testing.T) {
	for name, c := range map[string]struct{ gomod, want string }{
		"a plain directive":    {"module example.com/m\n\ngo 1.22\n", "example.com/m/api/gen/"},
		"a quoted path":        {"module \"example.com/m\"\n", "example.com/m/api/gen/"},
		"a comment after it":   {"// header\nmodule example.com/m // the root\n", "example.com/m/api/gen/"},
		"indented, CRLF lines": {"  module example.com/m\r\ngo 1.22\r\n", "example.com/m/api/gen/"},
	} {
		got, err := testreport.GeneratedPrefix([]byte(c.gomod))
		if err != nil || got != c.want {
			t.Errorf("%s: GeneratedPrefix = %q, %v; want %q", name, got, err, c.want)
		}
	}
	for name, gomod := range map[string]string{
		"no directive":       "go 1.22\n",
		"two directives":     "module example.com/m\nmodule example.com/n\n",
		"no path":            "module\n",
		"an empty path":      "module \"\"\n",
		"a block":            "module (\n\texample.com/m\n)\n",
		"two words":          "module example.com/m extra\n",
		"a path with spaces": "module \"example.com/m n\"\n",
		"an empty file":      "",
	} {
		if got, err := testreport.GeneratedPrefix([]byte(gomod)); !errors.Is(err, testreport.ErrModulePath) {
			t.Errorf("%s: GeneratedPrefix = %q, %v; want ErrModulePath", name, got, err)
		}
	}
}
