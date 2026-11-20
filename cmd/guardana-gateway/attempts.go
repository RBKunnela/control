package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/guardana/control/internal/attempts"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/policywatch"
	"github.com/guardana/control/internal/scenario"
)

const attemptsForm = "run --manifest <file> --report <file> [--state <dir>]"

func declareAttempts(flags *flag.FlagSet) commandFunc {
	manifest := flags.String("manifest", "", "the attempt manifest to run, attempt-manifest/v1alpha1")
	report := flags.String("report", "", "the report to write, attempt-report/v1alpha1; a file that exists is refused")
	state := flags.String("state", "", "a new directory for every run's state and journals; by default a temporary one")
	return func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
		if len(args) == 0 || args[0] != "run" {
			writeLine(stderr, flags.Name()+": the one thing to do with attempts is run them: "+flags.Name()+" "+attemptsForm)
			return exitUsage
		}
		if err := flags.Parse(args[1:]); err != nil {
			return exitUsage
		}
		switch {
		case *manifest == "":
			writeLine(stderr, flags.Name()+": --manifest names the attempt manifest to run")
			return exitUsage
		case *report == "":
			writeLine(stderr, flags.Name()+": --report names the report to write")
			return exitUsage
		case flags.NArg() > 0:
			writeLine(stderr, flags.Name()+": unexpected argument "+oneLine(flags.Arg(0)))
			return exitUsage
		}
		return runAttempts(ctx, attemptOptions{manifest: *manifest, report: *report, state: *state}, stdout, stderr)
	}
}

type attemptOptions struct {
	manifest, report, state string
}

// attemptSet is everything a run of a manifest is made from, read and
// checked before any plane starts.
type attemptSet struct {
	m         *attempts.Manifest
	raw       []byte
	dir       string
	scenarios map[string]*scenario.Scenario
	document  []byte
	config    string
	control   sibling
	// servers is the server the demo declares for each tool, "" where it
	// declares none or more than one; upstreams is every server's name;
	// declared is every tool as server/tool.
	servers   map[string]string
	upstreams []string
	declared  []string
	binaries  []attempts.FileDigest
	files     []attempts.FileDigest
}

func attemptsCouldNotRun(stderr io.Writer, err error) int {
	writeLine(stderr, brand.Gateway+": attempts: could not run: "+oneLine(err.Error()))
	return attempts.ExitIncomplete
}

// runAttempts refuses what it must before anything is created or bound,
// writes the header, runs every attempt on every plane in every repetition,
// one at a time, each on a plane of its own, writes each run's line as it
// ends, and writes the summary last.
func runAttempts(ctx context.Context, o attemptOptions, stdout, stderr io.Writer) int {
	set, err := prepareAttempts(ctx, o)
	if err != nil {
		return attemptsCouldNotRun(stderr, err)
	}
	report, err := attempts.CreateReport(o.report)
	if err != nil {
		return attemptsCouldNotRun(stderr, err)
	}
	defer func() { _ = report.Close() }()
	state, err := makeAttemptState(o.state)
	if err != nil {
		return attemptsCouldNotRun(stderr, err)
	}
	started := time.Now().UTC()
	header := set.header(o.manifest, state, started)
	if err := report.Write(header); err != nil {
		return attemptsCouldNotRun(stderr, err)
	}
	var results []*attempts.RunResult
	exercised := map[string]bool{}
	n := 0
	for rep := 1; rep <= set.m.Repetitions; rep++ {
		for _, p := range set.m.Planes {
			for _, a := range set.m.Attempts {
				n++
				dir := filepath.Join(state, fmt.Sprintf("%d-%s-%s-%d", n, a.ID, p.ID, rep))
				run := set.runOne(ctx, a, p, rep, dir)
				res := attempts.Evaluate(set.m, run)
				for _, s := range run.Steps {
					if s.Sent {
						exercised[s.Server+"/"+s.Tool] = true
					}
				}
				if err := report.Write(attempts.LineOf(a.Scenario, res)); err != nil {
					return attemptsCouldNotRun(stderr, err)
				}
				results = append(results, res)
			}
		}
	}
	summary := set.summarize(ctx, results, header, exercised, started)
	if err := report.Write(summary); err != nil {
		return attemptsCouldNotRun(stderr, err)
	}
	printSummary(stdout, o.report, summary)
	return summary.Exit
}

// prepareAttempts reads the manifest, every scenario, the policy and the
// demo's configuration under each plane's settings, finds the approver's
// binary, and measures every file and binary the run depends on.
func prepareAttempts(ctx context.Context, o attemptOptions) (*attemptSet, error) {
	if err := refuseBeforeReading(o); err != nil {
		return nil, err
	}
	m, raw, err := attempts.ReadManifestFile(o.manifest)
	if err != nil {
		return nil, fmt.Errorf("--manifest: %w", err)
	}
	abs, err := filepath.Abs(o.manifest)
	if err != nil {
		return nil, err
	}
	set := &attemptSet{m: m, raw: raw, dir: filepath.Dir(abs), scenarios: map[string]*scenario.Scenario{}}
	for _, a := range m.Attempts {
		if _, ok := set.scenarios[a.Scenario]; ok {
			continue
		}
		if set.scenarios[a.Scenario], err = scenario.ReadFile(set.path(a.Scenario)); err != nil {
			return nil, fmt.Errorf("%s: %w", a.Scenario, err)
		}
	}
	if err := m.Bind(set.scenarios); err != nil {
		return nil, err
	}
	if set.document, err = readBounded(set.path(m.Policy), policywatch.MaxBundleFileBytes); err == nil {
		err = checkSignable(set.document)
	}
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", m.Policy, err)
	}
	set.config = set.path(m.Demo)
	if err := set.readDemo(); err != nil {
		return nil, err
	}
	if set.control, err = findSibling(ctx, brand.CLI, "", defaultScenarioTimeout); err != nil {
		return nil, err
	}
	return set, set.measure()
}

// refuseBeforeReading refuses a platform dev does not run on, a variable of
// the product's in the environment, a state directory that exists and a
// report that exists.
func refuseBeforeReading(o attemptOptions) error {
	if err := refusePlatform(runtime.GOOS); err != nil {
		return err
	}
	if err := refuseEnvironment(os.Environ()); err != nil {
		return err
	}
	if err := refuseState(o.state); err != nil {
		return err
	}
	if _, err := os.Lstat(o.report); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("--report %s: it exists, and a report is written to a new file", o.report)
	}
	return nil
}

// path is a path the manifest names, on this system, from the manifest's
// directory.
func (set *attemptSet) path(p string) string {
	return filepath.Join(set.dir, filepath.FromSlash(p))
}

// inputs is what the plane of configuration p is made from.
func (set *attemptSet) inputs(p attempts.Plane) devInputs {
	return devInputs{config: set.config, document: set.document, control: set.control,
		silent: p.DecisionPoint == attempts.DecisionPointSilent, mode: p.Mode}
}

// makeAttemptState makes the directory every run's state goes under: dir,
// which must not exist, or a new temporary one.
func makeAttemptState(dir string) (string, error) {
	var err error
	if dir == "" {
		dir, err = os.MkdirTemp("", brand.Gateway+"-attempts-")
	} else {
		err = os.Mkdir(dir, 0o700)
	}
	if err != nil {
		return "", fmt.Errorf("--state: %w", err)
	}
	return filepath.Abs(dir)
}

// printSummary prints what the summary line counts, one line each.
func printSummary(stdout io.Writer, report string, s attempts.Summary) {
	writeLine(stdout, fmt.Sprintf("attempts: %d runs selected, %d started, %d not run", s.Runs.Selected, s.Runs.Started, s.Runs.NotRun))
	for _, p := range s.Planes {
		var obs, absent, notSent, unknown, runs int
		for _, e := range p.Effects {
			obs, absent, notSent, unknown, runs = obs+e.Observed, absent+e.VerifiedAbsent, notSent+e.AbsentNotSent, unknown+e.Unknown, runs+e.Runs
		}
		l := p.Legitimate
		writeLine(stdout, fmt.Sprintf("plane %s (%s, %s): effects over %d: observed %d, verified absent %d, absent and not sent %d, unknown %d; "+
			"legitimate steps over %d: completed %d, held %d, blocked %d, unknown %d",
			oneLine(p.Plane), p.Mode, p.Role, runs, obs, absent, notSent, unknown, l.Steps, l.Completed, l.Held, l.Blocked, l.Unknown))
	}
	met := "met"
	if !s.ThresholdsMet {
		met = "missed"
	}
	writeLine(stdout, fmt.Sprintf("thresholds: %s; unknown: %d; absent and not sent: %d", met, s.Unknown, s.AbsentNotSent))
	if !s.BelongsToCommit {
		writeLine(stdout, "the result belongs to no commit: this build records no commit, or a modified tree")
	}
	if !s.Complete {
		writeLine(stdout, "incomplete: "+oneLine(fmt.Sprint(s.Incomplete)))
	}
	writeLine(stdout, "report: "+oneLine(report))
}

// distinct is the sorted distinct values of xs, without the empty one.
func distinct(xs []string) []string {
	out := append([]string{}, xs...)
	slices.Sort(out)
	return slices.DeleteFunc(slices.Compact(out), func(s string) bool { return s == "" })
}
