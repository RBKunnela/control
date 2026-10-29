package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
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

// ownRefusal is how each listed command answers a path that is not there: the
// arguments that reach its own branch, and the one stderr line it writes under
// its own name, so a name that reached some other command's branch shows. A
// listed command with no entry here is one this test does not exercise, and it
// refuses to start rather than pass over it.
var ownRefusal = map[string]func(missing string) []string{
	"policy lint":    func(m string) []string { return []string{m} },
	"policy test":    func(m string) []string { return []string{m} },
	"policy explain": func(m string) []string { return []string{m} },
	"policy keygen":  func(m string) []string { return []string{"--out", filepath.Dir(m)} },
	"policy sign":    func(m string) []string { return []string{"--key", m, "--out", m + ".bundle", m} },
	"policy renew": func(m string) []string {
		return []string{"--key", m, "--bundle", m, "--bundle-public-key", m, "--floor", m, "--out", filepath.Join(m, "s")}
	},
	"policy state init": func(m string) []string {
		return []string{"--kind", "signer", "--bundle-id", "orders-policy", filepath.Join(m, "floors")}
	},
	"policy state reset": func(m string) []string {
		return []string{"--kind", "signer", "--bundle-id", "orders-policy", "--empty", "--reason", "r", m}
	},
	"approvals list":    func(m string) []string { return []string{m} },
	"approvals approve": func(m string) []string { return []string{"--approver-id", "someone", m, "AP1"} },
	"approvals reject":  func(m string) []string { return []string{"--approver-id", "someone", m, "AP1"} },
	"pause init":        func(m string) []string { return []string{filepath.Join(m, "pause.json")} },
	"pause add":         func(m string) []string { return []string{"--global", m} },
	"pause remove":      func(m string) []string { return []string{m, "P1"} },
	"pause list":        func(m string) []string { return []string{m} },
	"runs open": func(m string) []string {
		return append(openFlags(who, "1h"), m)
	},
	"runs close": func(m string) []string { return []string{m, "run-" + strings.Repeat("0", 32)} },
	"runs list":  func(m string) []string { return []string{m} },
	"console":    func(m string) []string { return []string{"--approvals", m, "--approver-id", "someone"} },
	"observe import": func(m string) []string {
		return []string{"--source", m, "--log", m, m}
	},
	"observe export": func(m string) []string { return []string{m} },
	"coverage":       func(m string) []string { return []string{"--inventory", m} },
	"procedure lint": func(m string) []string { return []string{m} },
	"procedure test": func(m string) []string { return []string{m} },
	"supervise": func(m string) []string {
		return []string{"--procedure", m, "--runs", m, "--run", "run-" + strings.Repeat("0", 32), "--findings", m}
	},
	"notify":          func(m string) []string { return []string{"--findings", m, "--state", m, "--", m} },
	"findings export": func(m string) []string { return []string{"--findings", m} },
	"route sign":      func(m string) []string { return []string{"--key", m, "--out", m + ".route", m} },
	"stops init":      func(m string) []string { return []string{"--route", m, "--public-key", m, m} },
	"stops lift": func(m string) []string {
		return []string{"--route", m, "--public-key", m, "--key", m, "--run", "run-" + strings.Repeat("0", 32), m}
	},
	"stops list": func(m string) []string { return []string{"--route", m, "--public-key", m, m} },
	"react": func(m string) []string {
		return []string{"--findings", m, "--runs", m, "--route", m, "--public-key", m, "--stops", m}
	},
	"hook": func(m string) []string { return []string{"--profile-file", m, "--socket", m, "--state-dir", m} },
}

// refusalStatus is the status a command refuses a missing path with where it
// is not exitFail: the observe commands keep the export's contract, in which
// 2 says nothing was written and 1 is a whole result that holds a refusal, and
// coverage's 2 says no map was printed and 1 is a whole map with a gap, and
// supervise's 2 says nothing was judged or written and 1 is a judged run that
// is not a pass, notify's 2 says no program ran and 1 is a delivery that
// failed, findings export's 2 says nothing was exported and 1 is a whole
// export with a gap, and the procedure commands' 2 says nothing was judged
// and 1 is a case that failed, and hook's 2 is what a runtime blocks a call
// on.
var refusalStatus = map[string]int{
	"observe import": exitUsage, "observe export": exitUsage, "coverage": exitUsage, "supervise": exitUsage,
	"notify": exitUsage, "findings export": exitUsage, "procedure lint": exitUsage, "procedure test": exitUsage,
	"hook": exitUsage,
}

// TestEveryListedCommandDispatches: the list the help prints is the list run
// dispatches. Each command's words reach its own command; words the list does
// not hold, with or without arguments, get the help alone.
func TestEveryListedCommandDispatches(t *testing.T) {
	if len(commands) == 0 {
		t.Fatal("the command list is empty")
	}
	missing := filepath.Join(t.TempDir(), "none")
	for _, c := range commands {
		words := c.words()
		args, known := ownRefusal[words]
		if c.run == nil || !known {
			t.Fatalf("%q is listed and has no branch or no refusal this test knows", words)
		}
		var stdout, stderr bytes.Buffer
		status := run(append(strings.Fields(words), args(missing)...), &stdout, &stderr)
		wantStatus, ok := refusalStatus[words]
		if !ok {
			wantStatus = exitFail
		}
		if want := brand.CLI + ": " + words + ": "; status != wantStatus || !strings.HasPrefix(stderr.String(), want) {
			t.Errorf("%q answered %d with %q, want %d and a line starting %q", words, status, stderr.String(), wantStatus, want)
		}
	}
	for _, args := range unlistedInvocations(missing) {
		var stdout, stderr bytes.Buffer
		status := run(args, &stdout, &stderr)
		if status != exitUsage || stderr.String() != helpText() {
			t.Errorf("%q answered %d with %q, want %d with the help", args, status, stderr.String(), exitUsage)
		}
	}
}

// unlistedInvocations builds the calls that name no listed command: a name
// misspelled in its last word by its case or its last letter, a group that is
// not one, a name cut short, and a listed command given the wrong number of
// bare arguments. A command reached by its group alone is misspelled in that
// word.
func unlistedInvocations(missing string) [][]string {
	var out [][]string
	for _, c := range commands {
		if c.name == "" {
			for _, group := range []string{strings.ToUpper(c.group), c.group[:len(c.group)-1]} {
				out = append(out, []string{group}, []string{group, missing})
			}
			continue
		}
		words := strings.Fields(c.words())
		last := words[len(words)-1]
		for _, name := range []string{strings.ToUpper(last), last[:len(last)-1]} {
			misspelled := append(slices.Clone(words[:len(words)-1]), name)
			out = append(out, misspelled, append(misspelled, missing))
		}
		out = append(out, append(append([]string{strings.ToUpper(c.group)}, words[1:]...), missing))
		if c.flags == nil {
			out = append(out, words, append(slices.Clone(words), missing, missing))
		}
	}
	return append(out, []string{"explain"}, []string{"policy"}, []string{"approvals"}, []string{"pause"}, []string{"runs"},
		[]string{"policy", "state"}, []string{"policy", "state", missing}, []string{"route"}, []string{"stops"},
		[]string{"stops", missing}, []string{"procedure"})
}

// TestHelpNamesEveryCommand: the help opens with one line per listed command,
// in the list's order, each naming the binary and the words that reach it,
// and it says who may answer an approval and who may pause a call at all.
func TestHelpNamesEveryCommand(t *testing.T) {
	lines := strings.Split(strings.TrimSuffix(helpText(), "\n"), "\n")
	if len(lines) < len(commands)+1 || lines[0] != "usage:" {
		t.Fatalf("the help does not open with a usage line and one form per command: %q", helpText())
	}
	prefix := "  " + brand.CLI + " "
	forms := formLines(lines[1:])
	if len(forms) != len(commands) {
		t.Fatalf("the help holds %d forms for %d commands: %q", len(forms), len(commands), forms)
	}
	for i, c := range commands {
		line := forms[i]
		words, want := strings.Fields(strings.TrimPrefix(line, prefix)), strings.Fields(c.words())
		if !strings.HasPrefix(line, prefix) || len(words) <= len(want) || !slices.Equal(words[:len(want)], want) {
			t.Errorf("form %q does not name %s", line, c.words())
		}
	}
	// A form wider than a terminal wraps, and a wrapped usage line is read as
	// two commands.
	for _, line := range lines {
		if len(line) > 100 {
			t.Errorf("help line %q is %d columns", line, len(line))
		}
	}
	for _, authority := range []string{
		"Write access to the approvals directory is the approval authority",
		"Write access to the pause file is the authority to pause a call and to lift a pause.",
		"Write access to the runs directory is the authority to open and to close a run",
		"Write access to a floor directory is the authority to lower its floors;\npolicy state reset is the one way that records why.",
		"Only the lift key lifts a stop while a plane runs; write access to the stops directory\n" +
			"adds any stop the route allows and, across a restart, can start a new list with none.",
	} {
		if !strings.Contains(helpText(), authority) {
			t.Errorf("the help does not say %q", authority)
		}
	}
}

// formContinues is how a form too wide for one line starts its next one:
// indented past the binary's name, so it never reads as a command of its own.
const formContinues = "      "

// formLines is the first line of each form in the usage block, which ends at
// the first empty line. A line indented as formContinues continues the form
// above it.
func formLines(lines []string) []string {
	var forms []string
	for _, line := range lines {
		if line == "" {
			break
		}
		if !strings.HasPrefix(line, formContinues) || len(forms) == 0 {
			forms = append(forms, line)
		}
	}
	return forms
}

func TestFormLinesJoinsAContinuation(t *testing.T) {
	got := formLines([]string{"  x a --b", formContinues + "--c <d>", "  x e", "", "  x f"})
	if want := []string{"  x a --b", "  x e"}; !slices.Equal(got, want) {
		t.Errorf("formLines = %q, want %q", got, want)
	}
	if got := formLines([]string{formContinues + "--c"}); len(got) != 1 {
		t.Errorf("a continuation with no form above it is not counted: %q", got)
	}
}

// TestEveryFlagShowsInItsForm: the form the help prints for a command names
// every flag that command parses. The help and docs/reference/cli.md are the
// only places a flag is written down, so one missing from the form is one
// nobody can find.
func TestEveryFlagShowsInItsForm(t *testing.T) {
	seen := 0
	for _, c := range commands {
		if c.flags == nil {
			continue
		}
		c.flags(c.words(), io.Discard).VisitAll(func(f *flag.Flag) {
			seen++
			if !namesFlag(c.arguments, f.Name) {
				t.Errorf("%s parses --%s and its form %q does not name it", c.words(), f.Name, c.arguments)
			}
		})
	}
	if seen == 0 {
		t.Fatal("no listed command declares a flag, so this test examined nothing")
	}
}

// namesFlag reports whether form names --name as a whole word: followed by a
// space, by the bracket that closes an optional flag, by the line break of a
// wrapped form, or by nothing.
func namesFlag(form, name string) bool {
	flagWord := "--" + name
	return strings.Contains(form, flagWord+" ") || strings.Contains(form, flagWord+"]") ||
		strings.Contains(form, flagWord+"\n") || strings.HasSuffix(form, flagWord)
}

func TestNamesFlagMatchesWholeWordsOnly(t *testing.T) {
	for _, c := range []struct {
		form, name string
		want       bool
	}{
		{"--out <dir>", "out", true},
		{"[--until-stdin-closes]", "until-stdin-closes", true},
		{"<f> --global", "global", true},
		{"--agent\n      --ttl", "agent", true},
		{"--agents\n      --ttl", "agent", false},
		{"--outer <dir>", "out", false},
		{"[--until-stdin-closes-x]", "until-stdin-closes", false},
		{"--global-x", "global", false},
	} {
		if got := namesFlag(c.form, c.name); got != c.want {
			t.Errorf("namesFlag(%q, %q) = %v, want %v", c.form, c.name, got, c.want)
		}
	}
}
