package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/scenario"
)

// defaultScenarioTimeout bounds each wait on the plane when --timeout is not
// given.
const defaultScenarioTimeout = 10 * time.Second

// The exits of scenario run beside exitOK: a scenario that differed, and one
// that could not run, which a gate treats as a failure too.
const (
	exitDiffered    = 1
	exitCouldNotRun = 2
)

const scenarioForm = "run --config <file> --trail <file> [--control <file>] [--timeout <d>] <path>..."

func declareScenario(flags *flag.FlagSet) commandFunc {
	config := flags.String("config", "", "the plane's configuration, which names its listener, its /healthz, its approvals directory and its pause file")
	trail := flags.String("trail", "", "the trail file, or directory of trail segments, the plane's collector writes")
	control := flags.String("control", "", "the "+brand.CLI+" that answers approvals and pauses; by default the one beside this binary")
	timeout := flags.Duration("timeout", defaultScenarioTimeout, "the bound on each wait: the spool's drain, a pause read, a run of "+brand.CLI+", and a call past the upstream's own timeout")
	return func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
		if len(args) == 0 || args[0] != "run" {
			writeLine(stderr, flags.Name()+": the one thing to do with scenarios is run them: "+flags.Name()+" "+scenarioForm)
			return exitUsage
		}
		if err := flags.Parse(args[1:]); err != nil {
			return exitUsage
		}
		switch {
		case *config == "":
			writeLine(stderr, flags.Name()+": --config names the plane's configuration file")
			return exitUsage
		case *trail == "":
			writeLine(stderr, flags.Name()+": --trail names the trail file the plane's collector writes")
			return exitUsage
		case *timeout <= 0:
			writeLine(stderr, flags.Name()+": --timeout must be above zero")
			return exitUsage
		case flags.NArg() == 0:
			writeLine(stderr, flags.Name()+": name the scenario files or directories to run")
			return exitUsage
		}
		opts := scenarioOptions{config: *config, trail: *trail, control: *control, timeout: *timeout}
		return runScenarios(ctx, opts, flags.Args(), stdout, stderr)
	}
}

type scenarioOptions struct {
	config, trail, control string
	timeout                time.Duration
}

// runner runs scenarios against one plane, as an MCP client of its listener
// and a reader of the trail file its collector writes.
type runner struct {
	plane   planeTarget
	trail   string
	control sibling
	timeout time.Duration
	http    *http.Client
	out     io.Writer
}

// runScenarios reads every scenario before running any, so a scenario this
// plane cannot meet stops the run before the plane is touched, and then runs
// each in order. It exits 1 when any scenario differed, else 2 when any could
// not run, else 0.
func runScenarios(ctx context.Context, opts scenarioOptions, paths []string, stdout, stderr io.Writer) int {
	loaded, err := loadScenarios(paths, stdout)
	if err != nil {
		return couldNotRun(stderr, err)
	}
	if loaded == nil {
		return exitCouldNotRun
	}
	r, err := newRunner(ctx, opts, loaded, stdout)
	if err != nil {
		return couldNotRun(stderr, err)
	}
	differed, stopped := false, false
	for _, s := range loaded {
		switch r.run(ctx, s) {
		case exitDiffered:
			differed = true
		case exitCouldNotRun:
			stopped = true
		}
	}
	switch {
	case differed:
		return exitDiffered
	case stopped:
		return exitCouldNotRun
	}
	return exitOK
}

// loadScenarios reads every scenario the paths name. A file the reader
// refuses is reported on its own line and loads nothing, which is nil with no
// error.
func loadScenarios(paths []string, stdout io.Writer) ([]*scenario.Scenario, error) {
	files, err := scenarioFiles(paths)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no scenario: the arguments name no *.json file")
	}
	loaded := make([]*scenario.Scenario, 0, len(files))
	for _, file := range files {
		s, err := scenario.ReadFile(file)
		if err != nil {
			writeLine(stdout, oneLine(file)+" could not run: "+oneLine(err.Error()))
			continue
		}
		loaded = append(loaded, s)
	}
	if len(loaded) != len(files) {
		return nil, nil
	}
	return loaded, nil
}

// newRunner reaches the plane the configuration names, and finds the
// approver's binary when a scenario has a step only an operator can take.
func newRunner(ctx context.Context, opts scenarioOptions, loaded []*scenario.Scenario, stdout io.Writer) (*runner, error) {
	cfg, err := gatewayconfig.Load(opts.config, os.Environ())
	if err != nil {
		return nil, err
	}
	target, err := targetOf(cfg)
	if err != nil {
		return nil, err
	}
	r := &runner{plane: target, trail: opts.trail, timeout: opts.timeout, http: &http.Client{}, out: stdout}
	if slices.ContainsFunc(loaded, operates) {
		if r.control, err = findSibling(ctx, brand.CLI, opts.control, opts.timeout); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func couldNotRun(stderr io.Writer, err error) int {
	writeLine(stderr, brand.Gateway+": scenario: could not run: "+oneLine(err.Error()))
	return exitCouldNotRun
}

// scenarioFiles is every file the arguments name, in the order given, a
// directory's *.json files in name order.
func scenarioFiles(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				out = append(out, filepath.Join(p, e.Name()))
			}
		}
	}
	return out, nil
}

// operates reports whether a scenario has a step only an operator can take.
func operates(s *scenario.Scenario) bool {
	return slices.ContainsFunc(s.Steps, func(st scenario.Step) bool { return st.Call == nil })
}

// line writes one line of a scenario's report.
func (r *runner) line(s *scenario.Scenario, text string) {
	writeLine(r.out, oneLine(s.ID)+" "+text)
}

func stepKind(st scenario.Step) string {
	switch {
	case st.Call != nil:
		return "call"
	case st.Approve != nil:
		return "approve"
	case st.Reject != nil:
		return "reject"
	case st.Pause != nil:
		return "pause"
	}
	return "unpause"
}

// run runs one scenario and reports each step and the scenario. A step that
// differs or cannot run ends the scenario; the pause entries it added are
// removed either way.
func (r *runner) run(ctx context.Context, s *scenario.Scenario) int {
	p := &play{r: r, s: s, added: map[int]string{}}
	status, why := exitOK, p.start(ctx)
	if why != nil {
		status = exitCouldNotRun
	}
	for i := 0; status == exitOK && i < len(s.Steps); i++ {
		diffs, err := p.step(ctx, i)
		switch {
		case err != nil:
			r.line(s, fmt.Sprintf("step[%d] %s: could not run: %s", i, stepKind(s.Steps[i]), oneLine(err.Error())))
			status, why = exitCouldNotRun, fmt.Errorf("step[%d]: %w", i, err)
		case len(diffs) > 0:
			for _, d := range diffs {
				r.line(s, d.String())
			}
			status = exitDiffered
		default:
			r.line(s, fmt.Sprintf("step[%d] %s: ok", i, stepKind(s.Steps[i])))
		}
	}
	if err := p.finish(ctx); err != nil {
		r.line(s, "could not remove the pause entries it added: "+oneLine(err.Error()))
		if status == exitOK {
			status, why = exitCouldNotRun, err
		}
	}
	switch status {
	case exitOK:
		r.line(s, "passed")
	case exitDiffered:
		r.line(s, "failed")
	default:
		r.line(s, "could not run: "+oneLine(why.Error()))
	}
	return status
}
