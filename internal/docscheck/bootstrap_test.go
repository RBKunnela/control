package docscheck

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bootstrapTools are the tools scripts/bootstrap.sh --check reads beside the
// stand-ins.
var bootstrapTools = []string{"bash", "env", "dirname", "sed", "grep"}

// bootstrapOutputs is what each pinned tool prints for its version, in the
// layout the real tool uses, with %s where its version goes.
var bootstrapOutputs = map[string]struct{ key, layout string }{
	"golangci-lint": {"GOLANGCI_LINT_VERSION", "golangci-lint has version %s built with go1.27.3 from 114493f on 2026-09-24T10:54:53Z"},
	"buf":           {"BUF_VERSION", "%s"},
	"actionlint":    {"ACTIONLINT_VERSION", "%s\ninstalled from Homebrew\nbuilt with go1.26.3 compiler for darwin/arm64"},
	"zizmor":        {"ZIZMOR_VERSION", "zizmor %s"},
	"gitleaks":      {"GITLEAKS_VERSION", "gitleaks version %s"},
	"osv-scanner":   {"OSV_SCANNER_VERSION", "osv-scanner version: %s\nosv-scalibr version: 0.5.2\ncommit: n/a"},
	"syft":          {"SYFT_VERSION", "syft %s"},
	"shellcheck":    {"SHELLCHECK_VERSION", "ShellCheck - shell script analysis tool\nversion: %s\nlicense: GNU General Public License, version 3"},
	"goreleaser":    {"GORELEASER_VERSION", "  goreleaser\nGitVersion:    %s\nGitCommit:     0000000"},
	"cosign":        {"COSIGN_VERSION", "  cosign\nGitVersion:    v%s\nGitCommit:     0000000"},
	"uv":            {"UV_VERSION", "uv %s (Homebrew 2026-09-01 aarch64-apple-darwin)"},
}

// bootstrapPins reads the version each tool is pinned to, without its "v",
// and go.mod's go version.
func bootstrapPins(t *testing.T) (map[string]string, string) {
	t.Helper()
	env, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "tool-versions.env"))
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{}
	for tool, out := range bootstrapOutputs {
		m := regexp.MustCompile(`(?m)^` + out.key + `=v?([0-9]+\.[0-9]+\.[0-9]+)$`).FindSubmatch(env)
		if m == nil {
			t.Fatalf("scripts/tool-versions.env pins no %s", out.key)
		}
		pins[tool] = string(m[1])
	}
	mod, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^go ([0-9.]+)$`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("go.mod has no go directive")
	}
	return pins, string(m[1])
}

// runBootstrapCheck runs scripts/bootstrap.sh --check with stand-ins that
// print versions, the pinned one for every tool not in versions, and returns
// its output and exit status.
func runBootstrapCheck(t *testing.T, versions map[string]string) (string, int) {
	t.Helper()
	pins, goVersion := bootstrapPins(t)
	bin := t.TempDir()
	for _, tool := range bootstrapTools {
		if err := os.Symlink(settingsTool(t, tool), filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	stand := map[string]string{"go": "go version go" + goVersion + " linux/amd64"}
	for tool, out := range bootstrapOutputs {
		v, ok := versions[tool]
		if !ok {
			v = pins[tool]
		}
		stand[tool] = fmt.Sprintf(out.layout, v)
	}
	for tool, out := range stand {
		body := "#!/usr/bin/env bash\n"
		if tool == "uv" {
			body += "[[ \"$1\" == --version ]] || exit 0\n"
		}
		body += "printf '%s\\n' '" + out + "'\n"
		if err := os.WriteFile(filepath.Join(bin, tool), []byte(body), 0o700); err != nil { //nolint:gosec // G306: the stand-in has to be executable
			t.Fatal(err)
		}
	}
	cmd := exec.Command(settingsTool(t, "bash"), filepath.Join(repoRoot(t), "scripts", "bootstrap.sh"), "--check") //nolint:gosec // G204: bash from PATH running this repository's own script
	cmd.Env = []string{"PATH=" + bin, "HOME=" + bin}
	out, err := fileOutput(t, cmd, true)
	return out, exitCode(t, err)
}

// TestBootstrapComparesTheWholeVersion: every tool at its pin passes; a tool
// that reports its pinned release with a prerelease or build suffix, or one
// more component, is another build and fails, named with what it reported,
// and so does one whose version is the tail of another word.
func TestBootstrapComparesTheWholeVersion(t *testing.T) {
	t.Parallel()
	pins, _ := bootstrapPins(t)
	for _, c := range []struct{ tool, version, want string }{
		{"golangci-lint", pins["golangci-lint"], ""},
		{"golangci-lint", pins["golangci-lint"] + "-rc.1", "want " + pins["golangci-lint"] + ", have " + pins["golangci-lint"] + "-rc.1"},
		{"golangci-lint", pins["golangci-lint"] + "-dev", "want " + pins["golangci-lint"] + ", have " + pins["golangci-lint"] + "-dev"},
		{"golangci-lint", pins["golangci-lint"] + "+dirty", "want " + pins["golangci-lint"] + ", have " + pins["golangci-lint"] + "+dirty"},
		{"golangci-lint", pins["golangci-lint"] + ".1", "want " + pins["golangci-lint"] + ", have " + pins["golangci-lint"] + ".1"},
		{"golangci-lint", "rc" + pins["golangci-lint"], "no version number in the output of golangci-lint --version"},
		{"cosign", pins["cosign"] + "-rc.1", "want " + pins["cosign"] + ", have " + pins["cosign"] + "-rc.1"},
		{"shellcheck", pins["shellcheck"] + "+dirty", "want " + pins["shellcheck"] + ", have " + pins["shellcheck"] + "+dirty"},
		{"uv", pins["uv"] + "-dev", "want " + pins["uv"] + ", have " + pins["uv"] + "-dev"},
	} {
		t.Run(c.tool+" "+c.version, func(t *testing.T) {
			t.Parallel()
			out, code := runBootstrapCheck(t, map[string]string{c.tool: c.version})
			if c.want == "" {
				if code != 0 || !strings.Contains(out, "bootstrap --check: go and 13 tools match their pins; nothing installed\n") {
					t.Fatalf("every tool at its pin: exit %d, output\n%s", code, out)
				}
				return
			}
			want := "FAIL " + c.tool + ": " + c.want + "\n"
			if code != 1 || !strings.Contains(out, want) || !strings.Contains(out, "1 of 13 tools failed the version check\n") {
				t.Errorf("exit %d, want 1 and %q; output\n%s", code, want, out)
			}
		})
	}
}
