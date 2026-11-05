package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/internal/pause"
)

// The names these commands report themselves under, and how the help spells
// what follows them. The add form is cut in two lines because a help line
// wider than a terminal wraps and reads as two commands.
const (
	pauseInitName   = "pause init"
	pauseAddName    = "pause add"
	pauseRemoveName = "pause remove"
	pauseListName   = "pause list"
	pauseAddForm    = "(--global | --provider <p> [--action <k> [--name <n>]]\n      | --run <id> | --agent <id> | --principal <id>) [--reason <r>] <f>"
	pauseRemoveForm = "<file> <id>"
)

// pauseAuthority is what the help and docs/reference/cli.md both say about
// who may pause: nothing but the file's permissions stands between a process
// and every pause in it.
const pauseAuthority = "Write access to the pause file is the authority to pause a call and to lift a pause."

// pauseLockWait bounds how long a writer waits for another writer's lock on
// the pause file's directory. A running plane never takes it.
const pauseLockWait = 10 * time.Second

// scopeFlags is what pause add is told about the calls to pause.
type scopeFlags struct {
	global                         bool
	provider, action, name, reason string
	run, agent, principal          string
}

func pauseAddFlags(command string, out io.Writer) (*flag.FlagSet, *scopeFlags) {
	flags := commandFlags(command, out)
	var s scopeFlags
	flags.BoolVar(&s.global, "global", false, "pause every call")
	flags.StringVar(&s.provider, "provider", "", "the upstream, by its configured name, whose calls to pause")
	flags.StringVar(&s.action, "action", "", "tool, prompt or resource: pause only calls of this kind to the provider")
	flags.StringVar(&s.name, "name", "", "the tool, by the name the plane routes by; a prompt or a resource is paused by its provider only")
	flags.StringVar(&s.run, "run", "", "the opened run whose calls to pause, or the root whose every run to pause")
	flags.StringVar(&s.agent, "agent", "", "the agent, as the listener's configuration names it, whose calls to pause")
	flags.StringVar(&s.principal, "principal", "", "the principal, as the listener's configuration names it, whose calls to pause")
	flags.StringVar(&s.reason, "reason", "", "why, for whoever lifts the pause; it decides nothing")
	return flags, &s
}

func pauseAddFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := pauseAddFlags(command, out)
	return flags
}

// pauseRemoveFlagSet declares no flag. It is there so the command is reached
// with its two arguments and parses them itself.
func pauseRemoveFlagSet(command string, out io.Writer) *flag.FlagSet {
	return commandFlags(command, out)
}

// scope reads the one scope the flags name, or says why they name none or
// more than one. The values themselves are judged by internal/pause.
func (s scopeFlags) scope() (pause.Scope, string) {
	if scope, problem, ok := s.identityScope(); ok {
		return scope, problem
	}
	switch {
	case s.global && s.provider == "" && s.action == "" && s.name == "":
		return pause.Scope{Kind: pause.ScopeGlobal}, ""
	case s.global, s.provider == "":
		return pause.Scope{}, oneScope
	case s.action == "" && s.name != "":
		return pause.Scope{}, "--name names a tool, and needs --action tool"
	case s.action == "":
		return pause.Scope{Kind: pause.ScopeProvider, Provider: s.provider}, ""
	}
	return pause.Scope{Kind: pause.ScopeAction, Provider: s.provider, Action: s.action, Name: s.name}, ""
}

const oneScope = "names one scope: --global, --provider <name>, --action <kind> with --provider <name>, --run <id>, --agent <id> or --principal <id>"

// identityScope is the run, agent or principal scope the flags name, or why
// they name it beside another; ok is false when they name none of the three.
func (s scopeFlags) identityScope() (pause.Scope, string, bool) {
	kind, id, named := s.identity()
	switch {
	case named == 0:
		return pause.Scope{}, "", false
	case named > 1 || s.global || s.provider+s.action+s.name != "":
		return pause.Scope{}, oneScope, true
	}
	return pause.Scope{Kind: kind, ID: id}, "", true
}

// identity is the run, agent or principal scope the flags name, and how many
// of the three they set. An empty value is no scope, as for --provider.
func (s scopeFlags) identity() (pause.ScopeKind, string, int) {
	var kind pause.ScopeKind
	var id string
	named := 0
	for _, f := range []struct {
		kind pause.ScopeKind
		id   string
	}{{pause.ScopeRun, s.run}, {pause.ScopeAgent, s.agent}, {pause.ScopePrincipal, s.principal}} {
		if f.id != "" {
			kind, id, named = f.kind, f.id, named+1
		}
	}
	return kind, id, named
}

func pauseInitCommand(args []string, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), pauseLockWait)
	defer cancel()
	if err := pause.Init(ctx, args[0]); err != nil {
		return fail(stderr, pauseInitName, err)
	}
	return report(stdout, stderr, pauseInitName, "created "+oneLine(args[0])+", which pauses nothing")
}

// pauseAddCommand adds one entry under an id it draws itself and prints that
// id alone, which is what pause remove takes.
func pauseAddCommand(args []string, stdout, stderr io.Writer) int {
	flags, s := pauseAddFlags(pauseAddName, stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		return usageError(stderr, pauseAddName, "takes the pause file, with every flag before it")
	}
	scope, problem := s.scope()
	if problem != "" {
		return usageError(stderr, pauseAddName, problem)
	}
	e := pause.Entry{ID: rand.Text(), Scope: scope, CreatedAt: time.Now().UTC(), Reason: s.reason}
	if err := e.Check(); err != nil {
		return fail(stderr, pauseAddName, fmt.Errorf("the entry: %w", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), pauseLockWait)
	defer cancel()
	if err := pause.Add(ctx, flags.Arg(0), e); err != nil {
		return fail(stderr, pauseAddName, err)
	}
	return report(stdout, stderr, pauseAddName, e.ID)
}

func pauseRemoveCommand(args []string, stdout, stderr io.Writer) int {
	flags := pauseRemoveFlagSet(pauseRemoveName, stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 2 {
		return usageError(stderr, pauseRemoveName, "takes the pause file and the id of the entry to remove")
	}
	ctx, cancel := context.WithTimeout(context.Background(), pauseLockWait)
	defer cancel()
	if err := pause.Remove(ctx, flags.Arg(0), flags.Arg(1)); err != nil {
		return fail(stderr, pauseRemoveName, err)
	}
	return report(stdout, stderr, pauseRemoveName, "removed "+oneLine(flags.Arg(1)))
}

// pauseListCommand prints one line per entry, reason included: the reason is
// for the operator, and this is the operator's own view of the file. The file
// is read with every check a plane's read makes, so whatever refuses it here
// is a state a plane reading it blocks every call under, and it says so.
func pauseListCommand(args []string, stdout, stderr io.Writer) int {
	doc, err := pause.List(args[0])
	if err != nil {
		return fail(stderr, pauseListName, fmt.Errorf("%w; a plane reading this file blocks every call", err))
	}
	if len(doc.Entries) == 0 {
		return report(stdout, stderr, pauseListName, "no entries")
	}
	var b strings.Builder
	for _, e := range doc.Entries {
		fmt.Fprintf(&b, "%s %s created %s reason %s\n", oneLine(e.ID), oneLine(scopeText(e.Scope)),
			e.CreatedAt.UTC().Format(time.RFC3339), oneLine(strconv.Quote(e.Reason)))
	}
	return report(stdout, stderr, pauseListName, strings.TrimSuffix(b.String(), "\n"))
}

// scopeText is a scope as a listing prints it.
func scopeText(s pause.Scope) string {
	switch s.Kind {
	case pause.ScopeGlobal:
		return "global"
	case pause.ScopeProvider:
		return "provider " + s.Provider
	case pause.ScopeRun, pause.ScopeAgent, pause.ScopePrincipal:
		return string(s.Kind) + " " + s.ID
	}
	if s.Name == "" {
		return s.Action + " " + s.Provider
	}
	return s.Action + " " + s.Provider + "/" + s.Name
}

// report writes a command's result to stdout. A write that fails is a
// failure; for a command that writes the pause file it also says the change
// was made all the same.
func report(stdout, stderr io.Writer, command, text string) int {
	if _, err := io.WriteString(stdout, text+"\n"); err != nil {
		if command != pauseListName {
			err = fmt.Errorf("%w; the pause file was changed as asked", err)
		}
		return fail(stderr, command, fmt.Errorf("writing to standard output: %w", err))
	}
	return exitOK
}
