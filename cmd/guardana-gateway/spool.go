package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/guardana/control/internal/spool"
)

const spoolForm = "drain <dir> <out>"

// declareSpool is the spool command, whose one action drains the quarantine
// of a spool no plane holds.
func declareSpool(flags *flag.FlagSet) commandFunc {
	return func(_ context.Context, args []string, stdout, stderr io.Writer) int {
		if len(args) != 3 || args[0] != "drain" {
			writeLine(stderr, flags.Name()+": the one thing to do with a spool here is drain its quarantine: "+flags.Name()+" "+spoolForm)
			return exitUsage
		}
		return drainQuarantine(args[1], args[2], stdout, stderr)
	}
}

// drainQuarantine moves the quarantine of the spool in dir into out, a new
// file, and says what moved. A plane holding the spool is refused, so the
// plane is stopped first; the records then count against the budget no more.
func drainQuarantine(dir, out string, stdout, stderr io.Writer) int {
	d, err := spool.Drain(dir, out)
	if err != nil {
		return fail(stderr, "spool drain", err)
	}
	if _, err := fmt.Fprintf(stdout, "spool drain: %d record(s), %d byte(s), moved from the quarantine into %s; %d torn byte(s) cut\n",
		d.Records, d.Bytes, oneLine(strconv.Quote(out)), d.Torn); err != nil {
		return fail(stderr, "spool drain", fmt.Errorf("writing to standard output: %w; the quarantine was drained as asked", err))
	}
	return exitOK
}
