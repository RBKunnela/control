package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/scenario"
)

// devScenarios reads every scenario before running any, then runs each on a
// plane of its own, laid out afresh and stopped once the scenario ends, with
// no page. It exits 1 when any scenario differed, else 2 when any could not
// run or its plane stopped on its own or did not stop cleanly, else 0.
func devScenarios(ctx context.Context, in devInputs, o devOptions, stdout, stderr io.Writer) int {
	loaded, err := loadScenarios(o.scenarios, stdout)
	if err != nil {
		return couldNotRun(stderr, err)
	}
	if loaded == nil {
		return exitCouldNotRun
	}
	if o.state != "" {
		if err := os.Mkdir(o.state, 0o700); err != nil {
			return couldNotRun(stderr, fmt.Errorf("--state: %w", err))
		}
	}
	differed, stopped := false, false
	for i, s := range loaded {
		dir := ""
		if o.state != "" {
			dir = filepath.Join(o.state, fmt.Sprintf("%d-%s", i+1, s.ID))
		}
		switch devScenario(ctx, in, dir, s, stdout, stderr) {
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

// devScenario runs one scenario on a plane of its own under dir.
func devScenario(ctx context.Context, in devInputs, dir string, s *scenario.Scenario, stdout, stderr io.Writer) int {
	d, err := startDevPlane(ctx, in, dir, stderr)
	if err != nil {
		writeLine(stdout, oneLine(s.ID)+" could not run: its plane did not start: "+oneLine(err.Error()))
		return exitCouldNotRun
	}
	writeLine(stdout, oneLine(s.ID)+" plane: state in "+oneLine(d.state.dir))
	status := exitCouldNotRun
	target, err := targetOf(d.cfg)
	target.operatorKey, target.inbox = d.state.operatorKeyFile(), d.state.path(stateInbox)
	if err == nil {
		r := &runner{plane: target, trail: d.state.path(stateTrail), control: in.control,
			timeout: defaultScenarioTimeout, http: &http.Client{}, out: stdout}
		status = r.run(ctx, s)
	} else {
		writeLine(stdout, oneLine(s.ID)+" could not run: "+oneLine(err.Error()))
	}
	select {
	case <-d.done:
		writeLine(stdout, oneLine(s.ID)+" could not run: its plane stopped while the scenario ran")
		if status == exitOK {
			status = exitCouldNotRun
		}
	default:
	}
	if _, err := d.halt(); err != nil {
		writeLine(stderr, brand.Gateway+": dev: stopping the plane of "+oneLine(s.ID)+": "+oneLine(err.Error()))
		writeLine(stdout, oneLine(s.ID)+" could not run: its plane did not stop cleanly")
		if status == exitOK {
			status = exitCouldNotRun
		}
	}
	return status
}
