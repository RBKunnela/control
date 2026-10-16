package docsconfig_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/guardana/control/internal/docscheck/docsconfig"
)

// good is a document every rule accepts; each refusal below is one edit to it.
const good = `{
  "budgets": {"tutorial": 1500, "how-to": 1200, "explanation": 3000, "reference": 1500, "extending": 2000},
  "exempt_types": ["spec", "project"],
  "readme": {"root": 600, "folder": 300},
  "ceilings": {"AGENTS.md": 1059},
  "directories": {"docs": {"type": "project"}, "docs/spec": {"type": "spec", "may_be_empty": true}},
  "page_types": {"docs/contracts.md": "spec"},
  "frozen": ["docs/contracts.md", "docs/adr/"],
  "excluded": [],
  "surfaces": ["api/proto/**"],
  "released": "1.2.3-alpha.1"
}
`

func repoFile(t testing.TB, rel string) []byte {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this file's own path")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(self))))
	data, err := fs.ReadFile(os.DirFS(root), rel)
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return data
}

func TestTheRepositoryFileParses(t *testing.T) {
	c, err := docsconfig.Parse(repoFile(t, "docs/docs.json"))
	if err != nil {
		t.Fatalf("docs/docs.json: %v", err)
	}
	if c.Budgets["how-to"] != 1200 || c.Readme.Root != 600 || c.Directories["docs/guides"].Type != "how-to" {
		t.Errorf("docs/docs.json read as %+v", c)
	}
	if c.Released == "" {
		t.Error("docs/docs.json names no released version")
	}
	if !c.Directories["docs/spec"].MayBeEmpty || c.Directories["docs/guides"].MayBeEmpty {
		t.Errorf("may_be_empty read wrong: %+v", c.Directories)
	}
}

func TestParseReadsEverySection(t *testing.T) {
	c, err := docsconfig.Parse([]byte(good))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Ceilings["AGENTS.md"] != 1059 || c.PageTypes["docs/contracts.md"] != "spec" || len(c.Frozen) != 2 || c.Surfaces[0] != "api/proto/**" || c.Released != "1.2.3-alpha.1" {
		t.Errorf("Parse = %+v", c)
	}
}

// edit makes one change to good; an edit that would change nothing is a
// case that tests nothing, so the loop below checks each one applied.
func edit(old, repl string) string {
	return strings.Replace(good, old, repl, 1)
}

func TestParseRefusals(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"not json":                        {"budgets", "invalid character"},
		"empty":                           {"", "EOF"},
		"text after the document":         {good + "{}", "text after the document"},
		"an unknown key":                  {edit(`"surfaces"`, `"site": 1, "surfaces"`), "unknown field"},
		"a key twice at the top":          {edit(`"excluded": [],`, `"excluded": [], "excluded": [],`), "given twice"},
		"a key twice inside":              {edit(`"root": 600,`, `"root": 600, "root": 600,`), "given twice"},
		"a key twice in a nested object":  {edit(`{"type": "project"}`, `{"type": "project", "type": "project"}`), "given twice"},
		"a member twice in two cases":     {edit(`"folder": 300`, `"folder": 300, "FOLDER": 30`), `"FOLDER" is not spelled as member "folder"`},
		"a member in another case":        {edit(`"folder": 300`, `"Folder": 300`), `"Folder" is not spelled as member "folder"`},
		"a top member in another case":    {edit(`"released":`, `"Released":`), `"Released" is not spelled as member "released"`},
		"a nested member in another case": {edit(`{"type": "project"}`, `{"Type": "project"}`), `"Type" is not spelled as member "type"`},
		"no budgets":                      {edit(`"budgets": {"tutorial": 1500, "how-to": 1200, "explanation": 3000, "reference": 1500, "extending": 2000},`, ``), "budgets is empty"},
		"a budget for no type":            {edit(`"tutorial": 1500`, `"guide": 1500, "tutorial": 1500`), "not a page type"},
		"a zero budget":                   {edit(`"tutorial": 1500`, `"tutorial": 0`), "no positive budget"},
		"a type budgeted and exempt":      {edit(`["spec", "project"]`, `["spec", "project", "tutorial"]`), "has a budget and is exempt"},
		"a type neither":                  {edit(`["spec", "project"]`, `["spec"]`), "has no budget and is not exempt"},
		"an exempt type twice":            {edit(`["spec", "project"]`, `["spec", "project", "spec"]`), "listed twice"},
		"a readme budget of zero":         {edit(`"folder": 300`, `"folder": 0`), "must be positive"},
		"a ceiling of zero":               {edit(`"AGENTS.md": 1059`, `"AGENTS.md": 0`), "no positive count"},
		"an absolute ceiling path":        {edit(`"AGENTS.md": 1059`, `"/AGENTS.md": 1059`), "not a relative slash path"},
		"a parent reference":              {edit(`"AGENTS.md": 1059`, `"../AGENTS.md": 1059`), "not a clean path"},
		"an unclean path":                 {edit(`"AGENTS.md": 1059`, `"docs//x.md": 1059`), "not a clean path"},
		"no directories":                  {edit(`"directories": {"docs": {"type": "project"}, "docs/spec": {"type": "spec", "may_be_empty": true}},`, `"directories": {},`), "directories is empty"},
		"a directory of unknown type":     {edit(`{"type": "project"}`, `{"type": "pages"}`), "not one of"},
		"a page type on no page":          {edit(`"docs/contracts.md": "spec"`, `"docs/contracts": "spec"`), "is not a page"},
		"a page type unknown":             {edit(`"docs/contracts.md": "spec"`, `"docs/contracts.md": "law"`), "not one of"},
		"a frozen path twice":             {edit(`["docs/contracts.md", "docs/adr/"]`, `["docs/contracts.md", "docs/contracts.md"]`), "listed twice"},
		"an empty excluded entry":         {edit(`"excluded": []`, `"excluded": [""]`), "a path is empty"},
		"no surfaces":                     {edit(`["api/proto/**"]`, `[]`), "surfaces is empty"},
		"no released":                     {edit(",\n  \"released\": \"1.2.3-alpha.1\"", ""), "released is empty"},
		"an empty released":               {edit(`"1.2.3-alpha.1"`, `""`), "released is empty"},
		"a null released":                 {edit(`"1.2.3-alpha.1"`, `null`), "released is empty"},
		"a released number":               {edit(`"1.2.3-alpha.1"`, `1.2`), "cannot unmarshal number"},
		"a released with a v":             {edit(`"1.2.3-alpha.1"`, `"v1.2.3-alpha.1"`), `released: "v1.2.3-alpha.1" is not a version`},
		"a released of two parts":         {edit(`"1.2.3-alpha.1"`, `"1.2"`), `released: "1.2" is not a version`},
		"a released with a leading zero":  {edit(`"1.2.3-alpha.1"`, `"1.02.3"`), `released: "1.02.3" is not a version`},
		"a released with a date":          {edit(`"1.2.3-alpha.1"`, `"1.2.3 - 2026-01-02"`), "is not a version"},
		"a released with a space":         {edit(`"1.2.3-alpha.1"`, `" 1.2.3"`), "is not a version"},
		"a released with a newline":       {edit(`"1.2.3-alpha.1"`, `"1.2.3\n"`), "is not a version"},
		"an empty pre-release":            {edit(`"1.2.3-alpha.1"`, `"1.2.3-"`), "is not a version"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.doc == good {
				t.Fatal("the edit changed nothing")
			}
			got, err := docsconfig.Parse([]byte(c.doc))
			if err == nil {
				t.Fatalf("Parse accepted the document: %+v", got)
			}
			if !errors.Is(err, docsconfig.ErrInvalid) {
				t.Errorf("error %v does not wrap ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("refused for %q, want the reason %q", err, c.want)
			}
		})
	}
}

// TestPathKeysDifferingInCaseAreTwoKeys: a map keyed by path is read as
// written, so two paths that differ only in case are two entries.
func TestPathKeysDifferingInCaseAreTwoKeys(t *testing.T) {
	c, err := docsconfig.Parse([]byte(edit(`"AGENTS.md": 1059`, `"AGENTS.md": 1059, "agents.md": 900`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Ceilings["AGENTS.md"] != 1059 || c.Ceilings["agents.md"] != 900 {
		t.Errorf("ceilings = %v", c.Ceilings)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(good))
	f.Add(repoFile(f, "docs/docs.json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := docsconfig.Parse(data)
		if err != nil {
			if !errors.Is(err, docsconfig.ErrInvalid) {
				t.Fatalf("a refusal does not wrap ErrInvalid: %v", err)
			}
			return
		}
		if len(c.Budgets) == 0 || len(c.Directories) == 0 || len(c.Surfaces) == 0 || c.Readme.Root <= 0 || c.Released == "" {
			t.Fatalf("Parse accepted a document a check could not act on: %+v", c)
		}
	})
}

func TestExcludesNamesAPathOrADirectory(t *testing.T) {
	c := docsconfig.Config{Excluded: []string{"docs/notes/", "CHANGELOG.md"}}
	for rel, want := range map[string]bool{
		"docs/notes/a.md":    true,
		"docs/notes/x/b.md":  true,
		"CHANGELOG.md":       true,
		"docs/notes":         false,
		"docs/notesx/a.md":   false,
		"docs/CHANGELOG.md":  false,
		"CHANGELOG.md.bak":   false,
		"docs/concepts/a.md": false,
	} {
		if got := c.Excludes(rel); got != want {
			t.Errorf("Excludes(%q) = %v, want %v", rel, got, want)
		}
	}
}
