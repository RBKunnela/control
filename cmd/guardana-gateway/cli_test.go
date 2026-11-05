package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/docscheck/frontmatter"
)

const cliPage = "docs/reference/cli.md"

// TestCLIPage pins the CLI reference to the help this binary prints: the
// fenced block inside the generated block whose marker names this test is
// helpText(), byte for byte, so a flag added or reworded without the page
// goes red.
func TestCLIPage(t *testing.T) {
	root, pin := repoRootAndPin(t)
	data, err := fs.ReadFile(os.DirFS(root), cliPage)
	if err != nil {
		t.Fatalf("reading %s: %v", cliPage, err)
	}
	block, err := helpBlock(string(data), pin)
	if err != nil {
		t.Fatalf("%s: %v", cliPage, err)
	}
	if want := helpText(); block != want {
		t.Errorf("%s: the block marked %q is not what the binary prints\n--- page\n%s--- binary\n%s", cliPage, pin, block, want)
	}
}

// repoRootAndPin resolves the repository and this package's pin, `go test
// ./cmd/<this> -run TestCLIPage`, from this file's own compiled-in path and
// refuses to guess: a root with no go.mod would pin the page of some other
// tree.
func repoRootAndPin(t *testing.T) (string, string) {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this file's own path")
	}
	dir := filepath.Dir(self)
	root := filepath.Dir(filepath.Dir(dir))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root %q holds no go.mod: %v", root, err)
	}
	return root, "go test ./" + path.Join(filepath.Base(filepath.Dir(dir)), filepath.Base(dir)) + " -run TestCLIPage"
}

// helpBlock returns the text of the fenced block inside the generated block
// whose marker names pin, with its trailing newline. No marker, no fence
// inside it, or a block or fence that never closes is an error, never an
// empty block.
func helpBlock(page, pin string) (string, error) {
	lines := strings.Split(strings.ReplaceAll(page, "\r\n", "\n"), "\n")
	marker := frontmatter.GeneratedOpen + pin + " -->"
	i := slices.IndexFunc(lines, func(l string) bool { return strings.TrimSpace(l) == marker })
	if i < 0 {
		return "", fmt.Errorf("no marker %q", marker)
	}
	inside := lines[i+1:]
	closed := slices.IndexFunc(inside, func(l string) bool { return strings.TrimSpace(l) == frontmatter.GeneratedClose })
	if closed < 0 {
		return "", fmt.Errorf("the generated block %q never closes", pin)
	}
	inside = inside[:closed]
	open := slices.IndexFunc(inside, func(l string) bool { return strings.HasPrefix(l, "```") })
	if open < 0 {
		return "", fmt.Errorf("no fenced block inside the generated block %q", pin)
	}
	body := inside[open+1:]
	end := slices.Index(body, "```")
	if end < 0 {
		return "", errors.New("the fenced block never closes")
	}
	return strings.Join(body[:end], "\n") + "\n", nil
}

func TestHelpBlockRefusesWhatItCannotFind(t *testing.T) {
	const pin = "go test ./x -run T"
	open := frontmatter.GeneratedOpen + pin + " -->\n"
	good := "# CLI\n\n## a\n\nText.\n\n" + open + "```\nusage: x\n```\n" + frontmatter.GeneratedClose + "\n"
	if block, err := helpBlock(good, pin); err != nil || block != "usage: x\n" {
		t.Errorf("helpBlock(good) = %q, %v; want %q", block, err, "usage: x\n")
	}
	for name, c := range map[string]struct{ page, want string }{
		"no marker":            {strings.Replace(good, open, "", 1), "no marker"},
		"another pin's marker": {strings.Replace(good, pin, "go test ./y -run T", 1), "no marker"},
		"unclosed block":       {strings.Replace(good, frontmatter.GeneratedClose+"\n", "", 1), "never closes"},
		"fence after the block": {
			strings.Replace(good, "```\nusage: x\n```\n"+frontmatter.GeneratedClose+"\n", frontmatter.GeneratedClose+"\n```\nusage: x\n```\n", 1),
			"no fenced block inside",
		},
		"unclosed fence": {strings.Replace(good, "```\n"+frontmatter.GeneratedClose, frontmatter.GeneratedClose, 1), "never closes"},
	} {
		if _, err := helpBlock(c.page, pin); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one containing %q", name, err, c.want)
		}
	}
}

// answers is how each command answers when it is given nothing, and when it
// is given what it refuses: run and doctor a configuration file that is not
// there, collect an address off the loopback, trail a file that is not there,
// scenario run a scenario that is not there.
// The refusal is stdout and stderr together: run refuses on stderr under its
// own name, doctor prints its first check's verdict. A name that reached some
// other command's branch shows here. A listed name with no entry is a command
// with no branch of its own, and the test refuses to start.
type answer struct {
	bare    string
	refused func(missing string) []string
	refusal string
	status  int
}

var answers = map[string]answer{
	"run": {
		bare:    brand.Gateway + " run: --config names the configuration file to read\n",
		refused: func(missing string) []string { return []string{"--config", missing} },
		refusal: brand.Gateway + ": run: ",
		status:  exitFail,
	},
	"doctor": {
		bare:    brand.Gateway + " doctor: --config names the configuration file to read\n",
		refused: func(missing string) []string { return []string{"--config", missing} },
		refusal: "fail    configuration ",
		status:  exitFail,
	},
	"collect": {
		bare: brand.Gateway + " collect: --listen names the loopback address to listen on\n",
		refused: func(missing string) []string {
			return []string{"--listen", "192.0.2.1:0", "--dir", missing, "--tenant", "t", "--project", "p", "--credential-file", missing}
		},
		refusal: brand.Gateway + ": collect: ",
		status:  exitFail,
	},
	"trail": {
		bare:    brand.Gateway + " trail: name one trail file or directory of segments to read\n",
		refused: func(missing string) []string { return []string{missing} },
		refusal: brand.Gateway + ": trail: ",
		status:  exitFail,
	},
	"prune": {
		bare:    brand.Gateway + " prune: --through names the last sealed segment to prune, from 1\n",
		refused: func(missing string) []string { return []string{"--through", "1", missing} },
		refusal: brand.Gateway + ": prune: ",
		status:  exitFail,
	},
	"spool": {
		bare:    brand.Gateway + " spool: the one thing to do with a spool here is drain its quarantine: " + brand.Gateway + " spool " + spoolForm + "\n",
		refused: func(missing string) []string { return []string{"drain", missing, missing + ".drained"} },
		refusal: brand.Gateway + ": spool drain: ",
		status:  exitFail,
	},
	"scenario": {
		bare: brand.Gateway + " scenario: the one thing to do with scenarios is run them: " + brand.Gateway + " scenario " + scenarioForm + "\n",
		refused: func(missing string) []string {
			return []string{"run", "--config", missing, "--trail", missing, missing}
		},
		refusal: brand.Gateway + ": scenario: could not run: ",
		status:  exitCouldNotRun,
	},
	"dev": {
		bare:    brand.Gateway + " dev: --config names the demo's configuration file\n",
		refused: func(missing string) []string { return []string{"--config", missing, "--policy", missing} },
		refusal: brand.Gateway + ": dev: ",
		status:  exitFail,
	},
}

// TestEveryListedCommandDispatches: the list the help prints is the list run
// dispatches. Each name reaches its own flag parser and then its own command;
// a name the list does not hold gets the help alone.
func TestEveryListedCommandDispatches(t *testing.T) {
	requireBranches(t)
	missing := filepath.Join(t.TempDir(), "none.json")
	var unlisted []string
	for _, c := range commands {
		want := answers[c.name]
		var stdout, stderr bytes.Buffer
		status := run(context.Background(), []string{c.name}, &stdout, &stderr)
		if status != exitUsage || stderr.String() != want.bare {
			t.Errorf("%q answered %d with %q, want %d with %q", c.name, status, stderr.String(), exitUsage, want.bare)
		}
		stdout.Reset()
		stderr.Reset()
		status = run(context.Background(), append([]string{c.name}, want.refused(missing)...), &stdout, &stderr)
		if got := stdout.String() + stderr.String(); status != want.status || !strings.HasPrefix(got, want.refusal) {
			t.Errorf("%q refused answered %d with %q, want %d and a line starting %q", c.name, status, got, want.status, want.refusal)
		}
		unlisted = append(unlisted, strings.ToUpper(c.name), c.name[:len(c.name)-1])
	}
	for _, name := range append(unlisted, "check") {
		var stdout, stderr bytes.Buffer
		status := run(context.Background(), []string{name}, &stdout, &stderr)
		if status != exitUsage || stderr.String() != helpText() {
			t.Errorf("%q answered %d with %q, want %d with the help", name, status, stderr.String(), exitUsage)
		}
	}
}

// requireBranches refuses to test a list that is empty or holds a name with
// no branch of its own.
func requireBranches(t *testing.T) {
	t.Helper()
	if len(commands) == 0 {
		t.Fatal("the command list is empty")
	}
	for _, c := range commands {
		if c.declare == nil {
			t.Fatalf("%q is listed and has no branch", c.name)
		}
		if _, ok := answers[c.name]; !ok {
			t.Fatalf("%q is listed and this test does not know its answers", c.name)
		}
	}
}

// TestUsageLineNamesEveryCommand: the first line of the help holds one form
// per listed command, in the list's order, and nothing else; each command
// then has its own section, which lists every flag its form names.
func TestUsageLineNamesEveryCommand(t *testing.T) {
	text := helpText()
	first, rest, ok := strings.Cut(text, "\n")
	if !ok {
		t.Fatalf("the help is one line: %q", text)
	}
	prefix, suffix := "usage: "+brand.Gateway+" [", "]"
	if !strings.HasPrefix(first, prefix) || !strings.HasSuffix(first, suffix) {
		t.Fatalf("usage line %q is not %q...%q", first, prefix, suffix)
	}
	var names []string
	for _, form := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(first, prefix), suffix), " | ") {
		name, args, _ := strings.Cut(form, " ")
		names = append(names, name)
		section := sectionOf(rest, name)
		for _, word := range strings.Fields(args) {
			if flagName, isFlag := strings.CutPrefix(word, "--"); isFlag && !strings.Contains(section, "\n  -"+flagName+" ") {
				t.Errorf("the form %q names --%s and its section does not:\n%s", form, flagName, section)
			}
		}
	}
	var listed []string
	for _, c := range commands {
		listed = append(listed, c.name)
		if !strings.Contains(rest, "\n"+c.name+"\n") {
			t.Errorf("the help holds no section for %q:\n%s", c.name, text)
		}
	}
	if !slices.Equal(names, listed) {
		t.Errorf("the usage line names %q, the list holds %q", names, listed)
	}
}

// sectionOf is the help's section of one command: its name's line and the
// lines up to the next blank one.
func sectionOf(rest, name string) string {
	_, after, ok := strings.Cut(rest, "\n"+name+"\n")
	if !ok {
		return ""
	}
	section, _, _ := strings.Cut(after, "\n\n")
	return "\n" + section
}
