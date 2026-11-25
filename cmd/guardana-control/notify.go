package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/guardana/control/internal/notify"
)

const (
	notifyName = "notify"
	notifyForm = "--findings <dir> --state <dir> [--init] [--timeout <duration>]\n" +
		"      [--env <name>]... -- <program> [<arg>]..."
	notifyUsage = "takes --findings and --state once each, then -- and the program to deliver to"
)

const defaultNotifyTimeout = 30 * time.Second

type notifyArgs struct {
	findings, state, env valueList
	init                 bool
	timeout              time.Duration
}

func notifyFlags(command string, out io.Writer) (*flag.FlagSet, *notifyArgs) {
	flags := commandFlags(command, out)
	a := &notifyArgs{}
	flags.Var(&a.findings, "findings", "the findings log `dir`; given once")
	flags.Var(&a.state, "state", "the state `dir`, owner-only, that names what was delivered; given once")
	flags.BoolVar(&a.init, "init", false, "start a state in a directory that holds none, delivering every alert again")
	flags.DurationVar(&a.timeout, "timeout", defaultNotifyTimeout, "how long one delivery may run before its process group is killed")
	flags.Var(&a.env, "env", "pass the variable `name` of this environment, which must be set, to the program; repeatable")
	return flags, a
}

func notifyFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := notifyFlags(command, out)
	return flags
}

// notifyCommand delivers each alert of the findings log the state has not
// marked to the program. It exits 0 when no delivery failed, 1 when one did,
// the log ends in a write no report closed and no writer holds, or the run
// stopped after a program ran, and 2, printing nothing, on a usage error or a
// refusal before any program ran.
func notifyCommand(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runNotify(ctx, args, stdout, stderr)
}

func runNotify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, err := notifyOptions(args)
	if err != nil {
		return usageError(stderr, notifyName, err.Error())
	}
	// The command's own writers, so the program's output reaches the
	// operator and no pipe is left for nobody to drain.
	o.Stdout, o.Stderr = stdout, stderr
	sum, err := notify.Run(ctx, o)
	if err != nil && !notifyStarted(sum, err) {
		return usageError(stderr, notifyName, err.Error())
	}
	if _, werr := io.WriteString(stdout, strings.Join(notifyLines(sum), "\n")+"\n"); werr != nil {
		return fail(stderr, notifyName, fmt.Errorf("writing to standard output: %w", werr))
	}
	if err != nil {
		return fail(stderr, notifyName, err)
	}
	if sum.Failed != 0 || sum.Unclosed != 0 {
		return exitFail
	}
	return exitOK
}

// notifyOptions reads the flags before the first -- and the program and its
// arguments after it; notify.Run refuses a timeout that is not above zero.
func notifyOptions(args []string) (notify.Options, error) {
	sep := slices.Index(args, "--")
	if sep < 0 || sep == len(args)-1 {
		return notify.Options{}, errors.New("no program after --; " + notifyUsage)
	}
	flags, a := notifyFlags(notifyName, io.Discard)
	if err := flags.Parse(args[:sep]); err != nil {
		return notify.Options{}, errors.New(err.Error() + "; " + notifyUsage)
	}
	if flags.NArg() != 0 || len(a.findings) != 1 || len(a.state) != 1 {
		return notify.Options{}, errors.New(notifyUsage)
	}
	return notify.Options{
		FindingsDir: a.findings[0], StateDir: a.state[0], Init: a.init,
		Program: args[sep+1], Args: args[sep+2:], Timeout: a.timeout, Env: a.env,
	}, nil
}

// notifyStarted reports whether a run that ended in err had run a program:
// then what it delivered is printed, and the status is not the one that says
// nothing happened. A mark that failed and a run interrupted both follow a
// program's start without counting it.
func notifyStarted(sum notify.Summary, err error) bool {
	return sum.Delivered+sum.Failed > 0 || errors.Is(err, notify.ErrMark) || errors.Is(err, context.Canceled)
}

// notifyLines names each failed delivery by its key and why, never by what
// the record holds, then counts what the run did.
func notifyLines(sum notify.Summary) []string {
	var out []string
	for _, f := range sum.Failures {
		out = append(out, "failed "+oneLine(f.Key)+": "+oneLine(f.Err.Error()))
	}
	if sum.Unclosed != 0 {
		out = append(out, fmt.Sprintf("unclosed: %d bytes after the last write a report closed, and no writer holds the log", sum.Unclosed))
	}
	return append(out, fmt.Sprintf("%d delivered, %d already delivered, %d failed, %d inform left",
		sum.Delivered, sum.AlreadyDelivered, sum.Failed, sum.Inform))
}
