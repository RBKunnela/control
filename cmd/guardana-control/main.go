// Command line entry point for the product. Without arguments it answers with
// the version and the status line; the `policy` commands (lint, test,
// explain, keygen, sign, renew and state), the `approvals` commands, the
// `pause` commands, the `runs` commands, `observe`, `coverage`, the
// `procedure` commands (lint and test), `supervise`, `notify`, `findings
// export`, `route sign`, the `stops` commands (init, lift and list), `react`,
// and `console`, the page that answers approvals and writes pauses, are the
// commands with behaviour, and docs/guides/write-and-test-a-policy.md,
// docs/guides/test-a-procedure.md and docs/reference/cli.md are their pages.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/keytext"
	"github.com/guardana/control/internal/policykey"
)

// Written by the linker (-ldflags "-X main.version=..."), never by this
// program. An unstamped build reports "dev" rather than a release number it
// cannot back up.
var version = "dev"

const statusLine = "docs/status.md says what this build does and what it does not"

// Exit statuses. A usage error is neither a pass nor a refusal of the input,
// so it has the third status the Go flag package uses for one.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches args and returns the exit status. The writers are the
// caller's, so a test reads what the program wrote. Key text given as an
// argument of any command is refused here, before a flag parser, a file
// refusal or a success line could repeat it.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return printVersion(stdout, stderr)
	}
	i := slices.IndexFunc(commands, func(c subcommand) bool { return c.reachedBy(args) })
	if i < 0 {
		return usage(stderr)
	}
	words := commands[i].words()
	rest := args[len(strings.Fields(words)):]
	if err := policykey.CheckArguments(rest); err != nil {
		return usageError(stderr, words, err.Error())
	}
	if commands[i].flags == nil && len(rest) != 1 {
		return usage(stderr)
	}
	return commands[i].run(rest, stdout, stderr)
}

// subcommand is one thing the binary does: the words run dispatches and the
// help lists, the form of what follows them as the help spells it, the flag
// set the command parses, and the function those words reach. A command with
// an empty name is reached by its group word alone.
type subcommand struct {
	group, name, arguments string
	// flags declares the command's flags, writing the flag package's own
	// diagnostics to out. It is nil for a command that takes none, and a test
	// holds every flag it declares to the form above, which is what the help
	// and the page show.
	flags func(command string, out io.Writer) *flag.FlagSet
	// run takes what follows the two words. A command with no flag set is
	// reached with exactly one argument, which run checks before calling it,
	// and a command with one parses what it was given itself. Either way it
	// returns an exit status and writes every diagnostic itself.
	run func(args []string, stdout, stderr io.Writer) int
}

// words is what reaches the command and what it reports itself under.
func (c subcommand) words() string {
	if c.name == "" {
		return c.group
	}
	return c.group + " " + c.name
}

// reachedBy reports whether args begin with the command's words.
func (c subcommand) reachedBy(args []string) bool {
	words := strings.Fields(c.words())
	return len(args) >= len(words) && slices.Equal(args[:len(words)], words)
}

// commands is the one listing: the help and the dispatch are both rendered
// from it, in this order.
var commands = []subcommand{
	{"policy", "lint", "<file>", nil, func(args []string, _, stderr io.Writer) int { return lint(args[0], stderr) }},
	{"policy", "test", "<dir>", nil, func(args []string, stdout, stderr io.Writer) int { return policyTest(args[0], stdout, stderr) }},
	{"policy", "explain", "<case>", nil, func(args []string, stdout, stderr io.Writer) int { return policyExplain(args[0], stdout, stderr) }},
	{"policy", "keygen", keygenForm, keygenFlagSet, keygenCommand},
	{"policy", "sign", signForm, signFlagSet, signCommand},
	{"policy", "renew", renewForm, renewFlagSet, renewCommand},
	{"policy", "state init", stateInitForm, stateInitFlagSet, stateInitCommand},
	{"policy", "state reset", stateResetForm, stateResetFlagSet, stateResetCommand},
	{"approvals", "list", "<dir>", nil, func(args []string, stdout, stderr io.Writer) int { return approvalsList(args[0], stdout, stderr) }},
	{"approvals", "approve", answerForm, answerFlagSet, approveCommand},
	{"approvals", "reject", answerForm, answerFlagSet, rejectCommand},
	{"pause", "init", "<file>", nil, pauseInitCommand},
	{"pause", "add", pauseAddForm, pauseAddFlagSet, pauseAddCommand},
	{"pause", "remove", pauseRemoveForm, pauseRemoveFlagSet, pauseRemoveCommand},
	{"pause", "list", "<file>", nil, pauseListCommand},
	{"runs", "open", runsOpenForm, runsOpenFlagSet, runsOpenCommand},
	{"runs", "close", runsCloseForm, runsCloseFlagSet, runsCloseCommand},
	{"runs", "list", "<dir>", nil, runsListCommand},
	{"observe", "import", observeImportForm, observeImportFlagSet, observeImportCommand},
	{"observe", "export", observeExportForm, observeExportFlagSet, observeExportCommand},
	{"coverage", "", coverageForm, coverageFlagSet, coverageCommand},
	{"procedure", "lint", "<file>", nil, func(args []string, stdout, stderr io.Writer) int { return procedureLint(args[0], stdout, stderr) }},
	{"procedure", "test", "<cases>", nil, func(args []string, stdout, stderr io.Writer) int { return procedureTest(args[0], stdout, stderr) }},
	{"supervise", "", superviseForm, superviseFlagSet, superviseCommand},
	{"notify", "", notifyForm, notifyFlagSet, notifyCommand},
	{"findings", "export", findingsExportForm, findingsExportFlagSet, findingsExportCommand},
	{"route", "sign", routeSignForm, routeSignFlagSet, routeSignCommand},
	{"stops", "init", stopsInitForm, stopsInitFlagSet, stopsInitCommand},
	{"stops", "lift", stopsLiftForm, stopsLiftFlagSet, stopsLiftCommand},
	{"stops", "list", stopsListForm, stopsListFlagSet, stopsListCommand},
	{"react", "", reactForm, reactFlagSet, reactCommand},
	{"hook", "", hookForm, hookFlagSet, hookCommand},
	{"console", "", consoleForm, consoleFlagSet, consoleCommand},
}

func printVersion(stdout, stderr io.Writer) int {
	if _, err := fmt.Fprintf(stdout, "%s %s\n%s\n", brand.Name, version, statusLine); err != nil {
		// A failed write to stdout is reported on stderr and by the exit
		// status. Exiting 0 would claim output that never arrived.
		return fail(stderr, "version", fmt.Errorf("writing to standard output: %w", err))
	}
	return exitOK
}

// helpText is what usage prints: one form per listed command, then what an
// operator has to know before answering an approval, pausing a call, opening
// a run or lowering a floor at all.
// docs/reference/cli.md holds the same text and a test diffs the two.
func helpText() string {
	var b strings.Builder
	b.WriteString("usage:\n")
	for _, c := range commands {
		b.WriteString("  " + brand.CLI + " " + c.words() + " " + c.arguments + "\n")
	}
	b.WriteString("\n" + approvalAuthority + "\n" + pauseAuthority + "\n" + runsAuthority + "\n" + floorAuthority + "\n" +
		stopsAuthority + "\n")
	return b.String()
}

func usage(stderr io.Writer) int {
	_, _ = io.WriteString(stderr, helpText())
	return exitUsage
}

// fail writes the command's refusal to stderr as one line and returns the
// failure status.
func fail(stderr io.Writer, command string, err error) int {
	writeLine(stderr, brand.CLI+": "+command+": "+oneLine(err.Error()))
	return exitFail
}

// usageError writes a refusal of the command's own arguments and returns the
// usage status, which is neither a pass nor a refusal of what was named.
func usageError(stderr io.Writer, command, message string) int {
	writeLine(stderr, brand.CLI+": "+command+": "+oneLine(message))
	return exitUsage
}

// writeLine is a best-effort write of a diagnostic: when stderr itself cannot
// be written, there is nowhere left to report that, and the exit status the
// caller returns still says the command failed.
func writeLine(w io.Writer, line string) {
	_, _ = io.WriteString(w, line+"\n")
}

// oneLine is every message either binary prints, as policykey.Printable
// gives it: on one line, out of the terminal's hands, with no key text.
func oneLine(s string) string { return policykey.Printable(s) }

// commandFlags is one command's empty flag set, writing to out.
func commandFlags(command string, out io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(brand.CLI+" "+command, flag.ContinueOnError)
	flags.SetOutput(keytext.Writer(out))
	return flags
}
