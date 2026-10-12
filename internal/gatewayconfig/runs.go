package gatewayconfig

import (
	"fmt"
	"path/filepath"
)

// RunsConfig names the runs directory an operator opens runs in (ADR-0034).
type RunsConfig struct {
	// Dir is the runs directory. Empty serves local runs (ADR-0021); set, every
	// call needs a run the operator opened there.
	Dir string
}

// checkRuns keeps the runs directory apart from every directory a plane or an
// approver writes and from the pause file's, since a file another writer puts
// there is one the runs directory refuses; and it refuses flow.max_runs beside
// a runs directory, whose opened runs that bound does not apply to, an empty
// principal type, which no run can be opened for, and a bound on one run's
// holds that is not below the plane's, or is set with no opened run to bound.
func (c *Config) checkRuns() error {
	if c.Runs.Dir == "" {
		if c.wasSet("approvals.max_held_per_run") {
			return fmt.Errorf("approvals.max_held_per_run: set, and no runs.dir opens a run for it to bound")
		}
		return nil
	}
	if c.wasSet("flow.max_runs") {
		return fmt.Errorf("flow.max_runs: set, and runs.dir serves opened runs, which it does not bound")
	}
	if c.Approvals.MaxHeldPerRun >= c.Approvals.MaxHeld {
		return fmt.Errorf("approvals.max_held_per_run: %d is at or above approvals.max_held, %d, so one run could hold every request the plane holds",
			c.Approvals.MaxHeldPerRun, c.Approvals.MaxHeld)
	}
	if c.Listener.PrincipalType == "" {
		return fmt.Errorf("listener.principal.type: empty, and every run is opened for a principal type, so no run would ever match")
	}
	runs := c.Resolve(c.Runs.Dir)
	others := []struct{ key, dir string }{
		{"evidence.dir", c.Evidence.Dir},
		{"approvals.dir", c.Approvals.Dir},
		{"approvals.hold_journal_dir", c.Approvals.HoldJournalDir},
	}
	if c.Pause.File != "" {
		others = append(others, struct{ key, dir string }{"pause.file", filepath.Dir(c.Pause.File)})
	}
	for _, other := range others {
		if other.dir == "" {
			continue
		}
		overlap, err := sharesDir(runs, c.Resolve(other.dir))
		if err != nil {
			return fmt.Errorf("runs.dir: %w", err)
		}
		if overlap {
			return fmt.Errorf("runs.dir: %q shares a path with %s %q; the runs directory holds run records and their state only (ADR-0034)",
				c.Runs.Dir, other.key, other.dir)
		}
	}
	return nil
}
