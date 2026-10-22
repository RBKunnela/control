package docscheck

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/docscheck/docsconfig"
)

// excludedProblems names every entry of docs.json's excluded that excludes no
// file of files: an exclusion over nothing hides nothing today and would hide
// whatever lands under it later, unseen.
func excludedProblems(cfg docsconfig.Config, files []string) []string {
	var problems []string
	for _, entry := range cfg.Excluded {
		one := docsconfig.Config{Excluded: []string{entry}}
		if !slices.ContainsFunc(files, one.Excludes) {
			problems = append(problems, fmt.Sprintf("excluded names %s, which matches no file the repository lists", entry))
		}
	}
	return problems
}

func TestEveryExclusionMatchesAFile(t *testing.T) {
	data, err := fs.ReadFile(repoFS(t), docsConfigPath)
	if err != nil {
		t.Fatalf("reading %s: %v", docsConfigPath, err)
	}
	cfg, err := docsconfig.Parse(data)
	if err != nil {
		t.Fatalf("%s: %v", docsConfigPath, err)
	}
	if len(cfg.Excluded) == 0 {
		t.Fatalf("%s excludes nothing, so this test examined nothing", docsConfigPath)
	}
	for _, problem := range excludedProblems(cfg, repoFiles(t, repoRoot(t))) {
		t.Errorf("%s: %s", docsConfigPath, problem)
	}
}

func TestExcludedProblems(t *testing.T) {
	files := []string{"CHANGELOG.md", "docs/adr/0001-first.md", "docs/notes.md"}
	for name, c := range map[string]struct {
		excluded []string
		want     []string
	}{
		"a file and a directory":       {[]string{"CHANGELOG.md", "docs/adr/"}, nil},
		"a directory no file is under": {[]string{"docs/adr/", "node_modules/"}, []string{"node_modules/"}},
		"a file the list lacks":        {[]string{"CODE_OF_CONDUCT.md"}, []string{"CODE_OF_CONDUCT.md"}},
		"a prefix without its slash":   {[]string{"docs/ad"}, []string{"docs/ad"}},
		"a directory named as a file":  {[]string{"docs/adr"}, []string{"docs/adr"}},
	} {
		problems := excludedProblems(docsconfig.Config{Excluded: c.excluded}, files)
		if len(problems) != len(c.want) {
			t.Errorf("%s: %d problems, want %d: %q", name, len(problems), len(c.want), problems)
			continue
		}
		for i, entry := range c.want {
			if !strings.Contains(problems[i], "excluded names "+entry+",") {
				t.Errorf("%s: problem %q does not name %s", name, problems[i], entry)
			}
		}
	}
}
