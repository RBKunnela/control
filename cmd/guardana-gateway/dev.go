package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/policywatch"
)

const devForm = "--config <file> --policy <file> [--decision-point=silent] [--state <dir>] [--scenario <file>]..."

// fileList is a flag given once per file.
type fileList []string

func (l *fileList) String() string { return strings.Join(*l, " ") }

func (l *fileList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// silentDecisionPoint is the one value --decision-point takes.
const silentDecisionPoint = "silent"

// decisionPointFlag is --decision-point, which refuses any value but silent.
type decisionPointFlag struct{ value *string }

func (f decisionPointFlag) String() string {
	if f.value == nil {
		return ""
	}
	return *f.value
}

func (f decisionPointFlag) Set(v string) error {
	if v != silentDecisionPoint {
		return fmt.Errorf("%q is not %s, the one value it takes", v, silentDecisionPoint)
	}
	*f.value = v
	return nil
}

type devOptions struct {
	config, policy, state string
	decisionPoint         string
	scenarios             fileList
}

func declareDev(flags *flag.FlagSet) commandFunc {
	var o devOptions
	flags.StringVar(&o.config, "config", "", "the demo's configuration, without the keys dev sets")
	flags.StringVar(&o.policy, "policy", "", "the policy document dev signs in memory")
	flags.Var(decisionPointFlag{&o.decisionPoint}, "decision-point",
		"`silent` makes the plane's decision point a loopback port dev binds and never answers, so every question times out; dev then owns every pdp key")
	flags.StringVar(&o.state, "state", "", "a new directory for the plane's state; by default a temporary one")
	flags.Var(&o.scenarios, "scenario", "a scenario `file` to run on a plane of its own; repeatable")
	return func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
		switch {
		case o.config == "":
			writeLine(stderr, flags.Name()+": --config names the demo's configuration file")
			return exitUsage
		case o.policy == "":
			writeLine(stderr, flags.Name()+": --policy names the policy document to sign")
			return exitUsage
		case len(args) > 0:
			writeLine(stderr, flags.Name()+": unexpected argument "+oneLine(args[0]))
			return exitUsage
		}
		return dev(ctx, o, stdout, stderr)
	}
}

// dev refuses what it must before anything is created or bound: a platform
// without process groups, a variable of the product's in its environment, an
// existing --state, a policy document it cannot read or sign, a demo
// configuration that sets what dev owns, and a sibling approver of another
// version. Then it runs the scenarios, or one plane and its page.
func dev(ctx context.Context, o devOptions, stdout, stderr io.Writer) int {
	if err := refusePlatform(runtime.GOOS); err != nil {
		return fail(stderr, "dev", err)
	}
	if err := refuseEnvironment(os.Environ()); err != nil {
		return fail(stderr, "dev", err)
	}
	if err := refuseState(o.state); err != nil {
		return fail(stderr, "dev", err)
	}
	document, err := readBounded(o.policy, policywatch.MaxBundleFileBytes)
	if err == nil {
		err = checkSignable(document)
	}
	if err != nil {
		return fail(stderr, "dev", fmt.Errorf("--policy: %w", err))
	}
	in := devInputs{config: o.config, document: document, silent: o.decisionPoint == silentDecisionPoint}
	if err := checkDemo(in, o.state); err != nil {
		return fail(stderr, "dev", err)
	}
	if in.control, err = findSibling(ctx, brand.CLI, "", defaultScenarioTimeout); err != nil {
		return fail(stderr, "dev", err)
	}
	if len(o.scenarios) > 0 {
		return devScenarios(ctx, in, o, stdout, stderr)
	}
	return devServe(ctx, in, o, stdout, stderr)
}

// devServe runs one plane and its page until an interrupt or until any part
// stops, and then stops them all: the plane's listeners, a bounded drain of
// its exporter, the collector, and the page last. It exits 1 when a part
// stopped on its own, the page included whatever its status.
func devServe(ctx context.Context, in devInputs, o devOptions, stdout, stderr io.Writer) int {
	d, err := startDevPlane(ctx, in, o.state, stderr)
	if err != nil {
		return fail(stderr, "dev", err)
	}
	pg, err := startPage(in.control, d.state, stderr)
	if err != nil {
		left, herr := d.halt()
		d.reportLeft(stdout, left)
		return fail(stderr, "dev", errors.Join(err, herr))
	}
	d.describe(stdout, pg.line, o)
	var died string
	select {
	case <-ctx.Done():
	case <-d.done:
		died = "the plane stopped"
	case err := <-d.coll.served:
		died = "the collector stopped: " + errText(err)
	case <-pg.exited:
		died = brand.CLI + " console exited"
	}
	left, herr := d.halt()
	perr := pg.halt()
	d.reportLeft(stdout, left)
	if died != "" {
		return fail(stderr, "dev", errors.Join(fmt.Errorf("%s, so dev stopped every part", died), herr, perr))
	}
	if err := errors.Join(herr, perr); err != nil {
		return fail(stderr, "dev", err)
	}
	return exitOK
}

// describe prints where every part of the plane is, one `name: value` line
// each.
func (d *devPlane) describe(stdout io.Writer, page string, o devOptions) {
	snap := d.plane.holder.Current()
	st := d.state
	for _, l := range [][2]string{
		{"mcp", "http://" + d.cfg.Listener.Address},
		{"healthz", "http://" + d.cfg.Health.Address + "/healthz"},
		{"metrics", "http://" + d.cfg.Health.Address + "/metrics"},
		{"page", strings.TrimPrefix(page, "page: ")},
		{"state", st.dir},
		{"settings", st.path(stateSettings)},
		{"approvals", st.path(stateApprovals)},
		{"holds", st.path(stateHolds)},
		{"spool", st.path(stateSpool)},
		{"trail", st.path(stateTrail)},
		{"pause", st.path(statePause)},
		{"bundle_file", st.path(stateBundle)},
		{"statement", st.path(stateStatement)},
		{"state_dir", st.path(stateFloors)},
		{"mode", d.cfg.ModeName},
		{"bundle", snap.Ref().GetBundleId()},
		{"digest", snap.Ref().GetDigest()},
		{"key_id", d.keyID},
		{"key", "made in this process to sign the bundle, cleared once it signed, and never written"},
		{"freshness_key_id", d.cfg.Policy.FreshnessKeyID},
		{"freshness_key", "made in this process apart from the bundle key, held in memory to renew the statement, and never written"},
		{"renewal", d.renewal},
		{"trail_command", brand.Gateway + " trail " + shellWord(st.path(stateTrail))},
		{"approvals_command", brand.CLI + " approvals list " + shellWord(st.path(stateApprovals))},
		{"pause_command", brand.CLI + " pause add --global -- " + shellWord(st.path(statePause))},
		{"scenario_command", scenarioCommand(o)},
	} {
		writeLine(stdout, l[0]+": "+oneLine(l[1]))
	}
}

// reportLeft says how much of the spool the collector never acknowledged,
// which the trail file therefore lacks.
func (d *devPlane) reportLeft(stdout io.Writer, left int64) {
	writeLine(stdout, fmt.Sprintf("unshipped: %d bytes the collector did not acknowledge are left in %s; the trail file lacks what they hold",
		left, oneLine(d.state.path(stateSpool))))
}

// scenarioCommand is the command that runs a scenario on a plane made as
// this one was.
func scenarioCommand(o devOptions) string {
	cmd := brand.Gateway + " dev --config " + shellWord(o.config) + " --policy " + shellWord(o.policy)
	if o.decisionPoint != "" {
		cmd += " --decision-point=" + shellWord(o.decisionPoint)
	}
	return cmd + " --scenario <file>"
}

// supported reports whether dev runs on goos: it starts the page in a
// process group of its own, so the terminal's interrupt reaches dev alone,
// and that needs the systems the unix build constraint names.
func supported(goos string) bool {
	switch goos {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris":
		return true
	}
	return false
}

// refusePlatform refuses a goos without process groups, by name.
func refusePlatform(goos string) error {
	if supported(goos) {
		return nil
	}
	return fmt.Errorf("dev runs on Linux and macOS, and this is %s: dev starts its page in a process group of its own, which %s lacks", goos, goos)
}

// shellWord is s as one word of a POSIX shell.
func shellWord(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=+@%,") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func errText(err error) string {
	if err == nil {
		return "no error"
	}
	return err.Error()
}
