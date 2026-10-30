// Command line entry point for the inline gateway. `run` serves one plane and
// `doctor` checks a configuration without serving; docs/guides/run-the-gateway.md
// is their page. `collect` receives a plane's evidence into a trail file and
// `trail` checks one; docs/guides/watch-a-plane-without-a-collector.md is
// theirs. `scenario run` holds a running plane to scenario files, and
// docs/reference/scenario-format.md is its page. `dev` lays out and runs a
// local plane with its page, and docs/reference/dev.md is its page.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/keytext"
	"github.com/guardana/control/internal/policykey"
)

// Written by the linker (-ldflags "-X main.version=..."), never by this
// program. An unstamped build reports "dev" rather than a release number it
// cannot back up.
var version = "dev"

// Exit statuses. A usage error is neither a pass nor a refusal of the
// configuration, so it has the third status the Go flag package uses for one.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches args and returns the exit status. The writers are the
// caller's, so a test reads what the program wrote. Key text given as an
// argument of any command is refused here, before the flag parser, a file
// refusal or a success line could repeat it.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return printVersion(stdout, stderr)
	}
	i := slices.IndexFunc(commands, func(c subcommand) bool { return c.name == args[0] })
	if i < 0 {
		return usage(stderr)
	}
	flags := commandFlags(args[0], stderr)
	if err := policykey.CheckArguments(args[1:]); err != nil {
		writeLine(stderr, flags.Name()+": "+err.Error())
		return exitUsage
	}
	command := commands[i].declare(flags)
	if err := flags.Parse(args[1:]); err != nil {
		return exitUsage
	}
	return command(ctx, flags.Args(), stdout, stderr)
}

// configured is a command that reads one configuration file. A command with
// no configuration has nothing to serve or to check, so --config is required
// and there is no search of default locations: a plane has to say which
// configuration it runs.
func configured(command func(ctx context.Context, path string, stdout, stderr io.Writer) int) declareFunc {
	return func(flags *flag.FlagSet) commandFunc {
		path := flags.String("config", "", "the configuration file to read")
		return func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
			switch {
			case *path == "":
				writeLine(stderr, flags.Name()+": --config names the configuration file to read")
				return exitUsage
			case len(args) > 0:
				writeLine(stderr, flags.Name()+": unexpected argument "+oneLine(args[0]))
				return exitUsage
			}
			return command(ctx, *path, stdout, stderr)
		}
	}
}

// declareRun is run's flags: the configuration, as for every configured
// command, and the token file a stdio plane with a runs directory serves its
// one run under.
func declareRun(flags *flag.FlagSet) commandFunc {
	tokenPath := flags.String("run-token-file", "", "a stdio plane with runs.dir: the file holding the token of the one run it serves")
	return configured(func(ctx context.Context, path string, stdout, stderr io.Writer) int {
		return serve(ctx, path, *tokenPath, stdout, stderr)
	})(flags)
}

func printVersion(stdout, stderr io.Writer) int {
	if _, err := fmt.Fprintf(stdout, "%s %s (%s)\n%s\n", brand.Gateway, version, brand.Name, statusLine); err != nil {
		// A failed write to stdout is reported on stderr and by the exit
		// status. Exiting 0 would claim output that never arrived.
		return fail(stderr, "version", fmt.Errorf("writing to standard output: %w", err))
	}
	return exitOK
}

const statusLine = "docs/status.md says what this build enforces and what it does not"

// subcommand is one thing the binary does: the name run dispatches and the
// help lists, what follows the name on the usage line, what declares its
// flags and returns the command they configure, and what it may do to the
// state it is pointed at.
type subcommand struct {
	name    string
	form    string
	declare declareFunc
	effect  effect
}

// effect is what a command may do to the files it is pointed at. The zero
// value classifies nothing, and a test refuses a command left at it.
type effect uint8

const (
	_ effect = iota
	// inspects leaves the bytes, mode, modification time, link count and
	// owner of everything it reads as they were, whether or not a writer
	// holds it; a test holds every such command to that over a damaged tree.
	inspects
	// writes may change what it is pointed at.
	writes
)

// declareFunc declares a command's flags on the set and returns the command,
// which reads them once they are parsed and takes the arguments left over.
// The help and the parser both declare from here, so a flag added shows on
// the page.
type declareFunc func(flags *flag.FlagSet) commandFunc

type commandFunc func(ctx context.Context, args []string, stdout, stderr io.Writer) int

// commands is the one listing: the usage line, the help and the dispatch are
// all rendered from it, in this order.
var commands = []subcommand{
	{"run", "--config <file> [--run-token-file <file>]", declareRun, writes},
	{"doctor", "--config <file>", configured(doctor), inspects},
	{"collect", "--listen <addr> --out <file>", declareCollect, writes},
	{"trail", trailForm, declareTrail, inspects},
	{"scenario", scenarioForm, declareScenario, writes},
	{"dev", devForm, declareDev, writes},
}

// commandFlags is one command's empty flag set, writing to out.
func commandFlags(command string, out io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(brand.Gateway+" "+command, flag.ContinueOnError)
	flags.SetOutput(keytext.Writer(out))
	return flags
}

// helpText is what usage prints: the usage line, then each command's flags
// as the flag package spells them. docs/reference/cli.md holds the same text
// and a test diffs the two.
func helpText() string {
	var b strings.Builder
	b.WriteString(usageLine())
	for _, c := range commands {
		b.WriteString("\n" + c.name + "\n")
		flags := commandFlags(c.name, &b)
		c.declare(flags)
		flags.PrintDefaults()
	}
	return b.String()
}

// usageLine is the first line of the help, one form per listed command.
func usageLine() string {
	forms := make([]string, 0, len(commands))
	for _, c := range commands {
		forms = append(forms, c.name+" "+c.form)
	}
	return "usage: " + brand.Gateway + " [" + strings.Join(forms, " | ") + "]\n"
}

func usage(stderr io.Writer) int {
	_, _ = io.WriteString(stderr, helpText())
	return exitUsage
}

// fail writes the command's refusal to stderr as one line and returns the
// failure status.
func fail(stderr io.Writer, command string, err error) int {
	writeLine(stderr, brand.Gateway+": "+command+": "+oneLine(err.Error()))
	return exitFail
}

// writeLine is a best-effort write of a diagnostic: when the writer itself
// cannot be written, there is nowhere left to report that, and the exit status
// the caller returns still says the command failed.
func writeLine(w io.Writer, line string) {
	_, _ = io.WriteString(w, line+"\n")
}

// oneLine is every message either binary prints, as policykey.Printable
// gives it: on one line, out of the terminal's hands, with no key text.
func oneLine(s string) string { return policykey.Printable(s) }
