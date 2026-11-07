package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/recovery"
)

// The names the state commands report themselves under, and what follows
// them.
const (
	stateBackupName  = "state backup"
	stateRestoreName = "state restore"
	stateForm        = "<config> <dir>"
)

// stateFlagSet declares no flag: both commands take the plane's
// configuration and the backup's directory.
func stateFlagSet(command string, out io.Writer) *flag.FlagSet { return commandFlags(command, out) }

// stateArgs loads the configuration args name, with this process's
// environment, which is the plane's when the command runs as the plane's
// account, and returns it with the backup's directory.
func stateArgs(command string, args []string, stderr io.Writer) (*gatewayconfig.Config, string, int) {
	flags := stateFlagSet(command, stderr)
	if err := flags.Parse(args); err != nil {
		return nil, "", exitUsage
	}
	if flags.NArg() != 2 {
		return nil, "", usageError(stderr, command, "takes the plane's configuration and the backup's directory")
	}
	cfg, err := gatewayconfig.Load(flags.Arg(0), os.Environ())
	if err != nil {
		return nil, "", fail(stderr, command, err)
	}
	return cfg, flags.Arg(1), exitOK
}

func stateBackupCommand(args []string, stdout, stderr io.Writer) int {
	cfg, dir, code := stateArgs(stateBackupName, args, stderr)
	if code != exitOK {
		return code
	}
	taken, err := recovery.Backup(context.Background(), cfg, dir, time.Now())
	if err != nil {
		return fail(stderr, stateBackupName, err)
	}
	lines := []string{fmt.Sprintf("backed up %d files into %s", len(taken.Manifest.Entries), dir)}
	for _, key := range taken.Absent {
		lines = append(lines, key+": configured, and nothing stands there to back up")
	}
	if err := writeLines(stdout, lines); err != nil {
		return fail(stderr, stateBackupName, err)
	}
	return exitOK
}

func stateRestoreCommand(args []string, stdout, stderr io.Writer) int {
	cfg, dir, code := stateArgs(stateRestoreName, args, stderr)
	if code != exitOK {
		return code
	}
	report, err := recovery.Restore(context.Background(), cfg, dir, time.Now())
	if err != nil {
		var written []string
		for _, done := range report.Done {
			written = append(written, "done before the failure: "+done)
		}
		return fail(stderr, stateRestoreName, errors.Join(err, writeLines(stdout, written)))
	}
	lines := restoreLines(cfg.Approvals.Authority == gatewayconfig.AuthoritySigned, report)
	if err := writeLines(stdout, lines); err != nil {
		return fail(stderr, stateRestoreName, err)
	}
	return exitOK
}

// restoreLines is what a restore that ended prints: what it did per key, each
// signed file to put back, the way back to a stop list two or more serials
// above a floor put back at the backup's, under signed what putting back an
// older file brings back, then the stamp's residual and the next step.
func restoreLines(signed bool, report recovery.Report) []string {
	lines := append([]string{}, report.Done...)
	for _, key := range report.PutBack {
		lines = append(lines, key+": an operator's signed file, never written by a restore; put back the newest signed copy you hold, the backup's only when you hold none newer")
		if key == "reaction.stops" {
			lines = append(lines, "reaction.stops: a stop list floor at the backup's serial takes a later list only when that list names the backup's list head as its previous, "+
				"so it refuses one two or more serials above; let the plane take each list of the chain in serial order, "+
				"or move reaction.stops_floor_dir aside, make it again with "+brand.CLI+" "+stopsFloorInitName+" and put back the newest list, which a floor with no serial takes")
		}
	}
	if signed {
		lines = append(lines, "a floor raised only to the backup's serial takes an older signed file put back, the roster, the route, the pause file and the stop list among them, and with it a grant revoked, a route changed or a pause signed after the backup")
	}
	return append(lines,
		"a statement issued before the restore at a higher serial than the floor still confirms, within policy.max_stale",
		"next: "+brand.Gateway+" doctor --config <config> names each signed file the raised floors refuse")
}
