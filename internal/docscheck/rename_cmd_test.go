package docscheck

import (
	"os/exec"
	"strings"
	"testing"
)

// A cmd directory takes one new name, derived from its own: the slug's or the
// gateway's. Substituting the gateway into the slug's result renames twice a
// slug that holds the old gateway name, and substituting the slug first turns
// the gateway of a one-segment slug into a binary nobody builds.
func TestACmdDirectoryIsRenamedOnce(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is not on PATH, so scripts/lib/cmd-names.sh cannot be run: %v", err)
	}
	for _, c := range []struct {
		dir, oldSlug, newSlug, oldGateway, newGateway, want string
	}{
		{"acme-ctl", "acme-ctl", "zeta-ctl", "acme-gateway", "zeta-gateway", "zeta-ctl"},
		{"acme-gateway", "acme-ctl", "zeta-ctl", "acme-gateway", "zeta-gateway", "zeta-gateway"},
		{"acme-ctl", "acme-ctl", "zeta-acme-gateway", "acme-gateway", "zeta-gateway", "zeta-acme-gateway"},
		{"acme-gateway", "acme", "zeta-ctl", "acme-gateway", "zeta-gateway", "zeta-gateway"},
		{"acme", "acme", "zeta-ctl", "acme-gateway", "zeta-gateway", "zeta-ctl"},
		{"tools", "acme-ctl", "zeta-ctl", "acme-gateway", "zeta-gateway", "tools"},
	} {
		cmd := exec.Command(bash, "-c", `. scripts/lib/cmd-names.sh && renamed_cmd "$@"`, "bash", //nolint:gosec // G204: bash from PATH sourcing this repository's own script
			c.dir, c.oldSlug, c.newSlug, c.oldGateway, c.newGateway)
		cmd.Dir = repoRoot(t)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("renamed_cmd %s: %v", c.dir, err)
		}
		if got := strings.TrimSuffix(string(out), "\n"); got != c.want {
			t.Errorf("cmd/%s with slug %s -> %s and gateway %s -> %s is renamed %q, want %q",
				c.dir, c.oldSlug, c.newSlug, c.oldGateway, c.newGateway, got, c.want)
		}
	}
}
