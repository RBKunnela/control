package docscheck

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

const (
	mcpClientGuide  = "docs/guides/connect-an-existing-mcp-setup.md"
	mcpClientScript = "scripts/check-mcp-client.sh"
)

// subcommandWord is one word of a command's name, before its first flag,
// path or placeholder.
var subcommandWord = regexp.MustCompile(`^[a-z]+$`)

// guideCommand is one command a code block of the guide runs: the binary,
// its subcommand words and the token after them, so "trail <file>" and
// "trail export" stay two commands, and the flags the line passes.
type guideCommand struct {
	prefix string
	flags  []string
}

// joinedLines is text with each line that ends in a backslash joined to the
// next, as a shell reads it.
func joinedLines(text string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutSuffix(line, `\`); ok {
			cur.WriteString(rest + " ")
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	return out
}

func isBinary(field string) bool { return field == brand.CLI || field == brand.Gateway }

func flagsOf(fields []string) []string {
	var out []string
	for _, f := range fields {
		if name, ok := strings.CutPrefix(f, "--"); ok && name != "" {
			name, _, _ = strings.Cut(name, "=")
			out = append(out, "--"+name)
		}
	}
	return out
}

// guideCommands is every command a code block of the guide runs through one
// of the product's binaries. A binary named anywhere but at the start of a
// command line, behind a prefix such as sudo, is reported, since this test
// could not hold the script to it.
func guideCommands(t *testing.T, text string) []guideCommand {
	t.Helper()
	var out []guideCommand
	fenced := false
	for _, line := range joinedLines(text) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			fenced = !fenced
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(trimmed, "$ "))
		if !fenced || len(fields) == 0 {
			continue
		}
		if !isBinary(fields[0]) {
			if slices.ContainsFunc(fields, isBinary) {
				t.Errorf("%s runs a binary behind a prefix this test cannot follow: %q", mcpClientGuide, trimmed)
			}
			continue
		}
		words := []string{fields[0]}
		for _, f := range fields[1:] {
			words = append(words, f)
			if !subcommandWord.MatchString(f) {
				break
			}
		}
		out = append(out, guideCommand{prefix: strings.Join(words, " "), flags: flagsOf(fields)})
	}
	if len(out) == 0 {
		t.Fatalf("%s holds no command of either binary in a code block", mcpClientGuide)
	}
	return out
}

// TestTheMCPClientCheckRunsEveryCommandOfTheGuide: the check that runs the
// guide end to end names each command the guide's code blocks run, with
// every flag the guide passes it, so a step added to the guide, or a flag,
// fails here until the check names it too. It compares text: a command the
// script names but never reaches still passes.
func TestTheMCPClientCheckRunsEveryCommandOfTheGuide(t *testing.T) {
	root := repoRoot(t)
	guide, err := os.ReadFile(filepath.Join(root, mcpClientGuide)) //nolint:gosec // G304: a path this repository names
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(root, mcpClientScript)) //nolint:gosec // G304: a path this repository names
	if err != nil {
		t.Fatal(err)
	}
	names := strings.NewReplacer(`"${control}"`, brand.CLI, `"${gateway}"`, brand.Gateway)
	var lines []string
	for _, line := range joinedLines(string(script)) {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines = append(lines, names.Replace(line))
		}
	}
	for _, command := range guideCommands(t, string(guide)) {
		named := regexp.MustCompile(`(^\s*|\$\()` + regexp.QuoteMeta(command.prefix) + `(\s|\)|$)`)
		if !slices.ContainsFunc(lines, func(line string) bool {
			return named.MatchString(line) && !slices.ContainsFunc(command.flags, func(f string) bool {
				return !slices.Contains(flagsOf(strings.Fields(line)), f)
			})
		}) {
			t.Errorf("%s runs %q with %v, and %s names no such line", mcpClientGuide, command.prefix, command.flags, mcpClientScript)
		}
	}
}
