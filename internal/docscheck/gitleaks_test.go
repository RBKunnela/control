package docscheck

import (
	"io/fs"
	"slices"
	"strings"
	"testing"
)

const gitleaksConfigPath = "scripts/gitleaks.toml"

// TestGitleaksConfigIsTheDefaultsAlone pins the scan's configuration, comment
// and blank lines left out, to the built-in rules and allowlist: an exception
// in scripts/gitleaks.toml fails here until this test's pinned text changes in
// the same review. scripts/scan-repo-files-probe.sh shows the scan still finds
// a planted secret.
func TestGitleaksConfigIsTheDefaultsAlone(t *testing.T) {
	data, err := fs.ReadFile(repoFS(t), gitleaksConfigPath)
	if err != nil {
		t.Fatalf("reading %s: %v", gitleaksConfigPath, err)
	}
	var got []string
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSuffix(line, "\n")
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			got = append(got, line)
		}
	}
	if want := []string{"[extend]", "useDefault = true"}; !slices.Equal(got, want) {
		t.Errorf("%s holds %q, want exactly %q", gitleaksConfigPath, got, want)
	}
}
