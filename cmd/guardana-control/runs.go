package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/guardana/control/internal/runs"
)

// The names these commands report themselves under, and how the help spells
// what follows them. The open form carries no value placeholders: with them
// the line is wider than a terminal, and runsAuthority says what each takes.
const (
	runsOpenName  = "runs open"
	runsCloseName = "runs close"
	runsListName  = "runs list"
	runsOpenForm  = "--project --tenant --principal-type --principal --agent\n      --ttl [--parent] <dir>"
	runsCloseForm = "<dir> <run-id>"
)

// runsAuthority is what the help and docs/reference/cli.md both say about who
// may open a run and what its token is worth.
const runsAuthority = "Write access to the runs directory is the authority to open and to close a run;\n" +
	"a token acts as its run until it expires or is closed, and runs open prints it once."

// runsListBound is the most records runs list prints.
const runsListBound = 1000

// openRuns opens a runs directory with open, waiting at most runsLockWait for
// another operator command's lock.
func openRuns(open func(context.Context, string) (*runs.Admin, error), dir string) (*runs.Admin, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runsLockWait)
	defer cancel()
	return open(ctx, dir)
}

// runsLockWait bounds how long a command waits for another operator command's
// lock on the directory. A plane never takes it.
const runsLockWait = 10 * time.Second

// openFlagValues is what runs open is told about the run to open.
type openFlagValues struct {
	who    runs.Identity
	parent string
	ttl    time.Duration
}

// requiredOpenFlags are the flags runs open refuses to run without. An empty
// value given is not a missing flag: internal/runs refuses it as the identity
// it is.
var requiredOpenFlags = [...]string{"project", "tenant", "principal-type", "principal", "agent", "ttl"}

func runsOpenFlags(command string, out io.Writer) (*flag.FlagSet, *openFlagValues) {
	flags := commandFlags(command, out)
	var v openFlagValues
	flags.StringVar(&v.who.ProjectID, "project", "", "the project whose planes the token resolves on: their project_id")
	flags.StringVar(&v.who.TenantID, "tenant", "", "the tenant the run is for")
	flags.StringVar(&v.who.PrincipalType, "principal-type", "", "the type of the principal the run acts for")
	flags.StringVar(&v.who.PrincipalID, "principal", "", "the principal the run acts for")
	flags.StringVar(&v.who.AgentID, "agent", "", "the agent that presents the token")
	flags.DurationVar(&v.ttl, "ttl", 0, "how long the run lives, from one minute to 720 hours")
	flags.StringVar(&v.parent, "parent", "", "the open run of the same project and tenant to open this one under")
	return flags, &v
}

func runsOpenFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := runsOpenFlags(command, out)
	return flags
}

// runsCloseFlagSet declares no flag. It is there so the command is reached
// with its two arguments and parses them itself.
func runsCloseFlagSet(command string, out io.Writer) *flag.FlagSet {
	return commandFlags(command, out)
}

// runsOpenCommand opens one run and prints its token, which is the only copy:
// the directory keeps its hash.
func runsOpenCommand(args []string, stdout, stderr io.Writer) int {
	flags, v := runsOpenFlags(runsOpenName, stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		return usageError(stderr, runsOpenName, "takes the runs directory, with every flag before it")
	}
	given := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for _, name := range requiredOpenFlags {
		if !given[name] {
			return usageError(stderr, runsOpenName, "--"+name+" is missing; every flag but --parent is required")
		}
	}
	admin, err := openRuns(runs.InitAdmin, flags.Arg(0))
	if err != nil {
		return fail(stderr, runsOpenName, err)
	}
	status := openAndPrint(admin, *v, stdout, stderr)
	if err := admin.Close(); err != nil && status == exitOK {
		return fail(stderr, runsOpenName, err)
	}
	return status
}

func openAndPrint(admin *runs.Admin, v openFlagValues, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), runsLockWait)
	defer cancel()
	rec, token, err := admin.Open(ctx, runs.OpenRequest{Who: v.who, Parent: v.parent, TTL: v.ttl, Now: time.Now()})
	if err != nil {
		return fail(stderr, runsOpenName, withheldRunID(err, "--parent"))
	}
	out := fmt.Sprintf("run_id: %s\nroot: %s\nexpires_at: %s\ntoken: %s\n", rec.ID, rec.Root, stampOf(rec.ExpiresAt), token)
	if _, err := io.WriteString(stdout, out); err != nil {
		return fail(stderr, runsOpenName, fmt.Errorf("writing to standard output: %w; run %s is open and nobody holds its token, so close it", err, rec.ID))
	}
	return exitOK
}

func runsCloseCommand(args []string, stdout, stderr io.Writer) int {
	flags := runsCloseFlagSet(runsCloseName, stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 2 {
		return usageError(stderr, runsCloseName, "takes the runs directory and a run id")
	}
	admin, err := openRuns(runs.OpenAdmin, flags.Arg(0))
	if err != nil {
		return fail(stderr, runsCloseName, err)
	}
	status := closeAndPrint(admin, flags.Arg(1), stdout, stderr)
	if err := admin.Close(); err != nil && status == exitOK {
		return fail(stderr, runsCloseName, err)
	}
	return status
}

func closeAndPrint(admin *runs.Admin, id string, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), runsLockWait)
	defer cancel()
	if err := admin.CloseRun(ctx, id, time.Now()); err != nil {
		return fail(stderr, runsCloseName, withheldRunID(err, "the argument"))
	}
	if _, err := io.WriteString(stdout, "closed "+id+"\n"); err != nil {
		return fail(stderr, runsCloseName, fmt.Errorf("writing to standard output: %w; the run was closed as asked", err))
	}
	return exitOK
}

// withheldRunID replaces the refusal of a malformed run id, which repeats the
// value, with one that does not: a value that is no run id may be a token or
// its secret, pasted where the id belongs.
func withheldRunID(err error, what string) error {
	if errors.Is(err, runs.ErrRunID) {
		return fmt.Errorf(`%s is not a run id, "run-" and 32 lower-case hex digits; it is not repeated, since it may be a token`, what)
	}
	return err
}

// runsListCommand prints one line per run, never its secret or the secret's
// hash. A listing the bound stopped fails after the lines it printed: it is
// neither the whole directory nor an empty one.
func runsListCommand(args []string, stdout, stderr io.Writer) int {
	admin, err := openRuns(runs.OpenAdmin, args[0])
	if err != nil {
		return fail(stderr, runsListName, err)
	}
	status := printRuns(admin, stdout, stderr)
	if err := admin.Close(); err != nil && status == exitOK {
		return fail(stderr, runsListName, err)
	}
	return status
}

func printRuns(admin *runs.Admin, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), runsLockWait)
	defer cancel()
	l, err := admin.List(ctx, runsListBound)
	if err != nil {
		return fail(stderr, runsListName, err)
	}
	now := time.Now()
	var b strings.Builder
	for _, r := range l.Records {
		fmt.Fprintf(&b, "%s %s root %s project_id %s tenant_id %s principal_type %s principal_id %s agent_id %s opened_at %s expires_at %s\n",
			oneLine(r.ID), runState(r, now), oneLine(r.Root), oneLine(r.Who.ProjectID), oneLine(r.Who.TenantID), oneLine(r.Who.PrincipalType),
			oneLine(r.Who.PrincipalID), oneLine(r.Who.AgentID), stampOf(r.OpenedAt), stampOf(r.ExpiresAt))
	}
	if len(l.Records) == 0 {
		b.WriteString("no runs\n")
	}
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		return fail(stderr, runsListName, fmt.Errorf("writing to standard output: %w", err))
	}
	if !l.Complete {
		return fail(stderr, runsListName, fmt.Errorf("%w; it stops at %d runs", errIncomplete, runsListBound))
	}
	return exitOK
}

// runState is the state a token for the run meets at now: a closed run stays
// closed whatever its expiry, and a run expires at its expiry, not after it.
func runState(r runs.Record, now time.Time) string {
	switch {
	case r.Closed():
		return "closed"
	case !now.Before(r.ExpiresAt):
		return "expired"
	}
	return "open"
}

// stampOf is a time as the runs directory records it, in UTC.
func stampOf(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
