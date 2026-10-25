package observe

import (
	"fmt"
	"maps"
	"slices"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
)

// MaxDoubtedRunIDs bounds the runs one import report names in doubt; past it
// the report puts every run of its source in doubt instead.
const MaxDoubtedRunIDs = 64

// Doubt gathers the runs claimed by the copies an import refused: a span the
// importer refused, or an observation the log held under its id with other
// content. Its zero value holds none.
type Doubt struct {
	runs  map[string]bool
	every bool
}

// Claim adds the run a refused copy claimed. A copy that claims none, or a
// claim that is not a run id, could be any run's, so it puts every run in
// doubt; so does a run past MaxDoubtedRunIDs.
func (d *Doubt) Claim(run string) {
	if d.every {
		return
	}
	if !ValidRunID(run) {
		d.every, d.runs = true, nil
		return
	}
	if d.runs == nil {
		d.runs = map[string]bool{}
	}
	d.runs[run] = true
	if len(d.runs) > MaxDoubtedRunIDs {
		d.every, d.runs = true, nil
	}
}

// ClaimOf adds the run o claims, or every run when it claims none.
func (d *Doubt) ClaimOf(o *observev1.Observation) {
	d.Claim(o.GetCorrelation().GetRunId())
}

// Merge adds what r already puts in doubt, as DoubtedRuns reads it.
func (d *Doubt) Merge(r *observev1.ImportReport) {
	if doubtsEveryRun(r) {
		d.every, d.runs = true, nil
	}
	for _, run := range r.GetDoubtedRunIds() {
		d.Claim(run)
	}
}

// Fill writes d into r, replacing what r said, with the schema version its
// members call for.
func (d *Doubt) Fill(r *observev1.ImportReport) {
	r.SchemaVersion, r.EveryRunDoubted, r.DoubtedRunIds = SchemaVersion, d.every, nil
	if !d.every && len(d.runs) > 0 {
		r.DoubtedRunIds = slices.Sorted(maps.Keys(d.runs))
	}
	if added02(r) != "" {
		r.SchemaVersion = SchemaVersion02
	}
}

// DoubtedRuns reads what the import reports of d's source among records put
// in doubt: every run, or the runs they name in ascending order. A report
// counts when it names d's source, tenant and project, as LastHeard reads
// them, under whichever descriptor digest wrote it. A 0.1 report names no
// run, so one that counts a refused span or a conflict puts every run in
// doubt.
func DoubtedRuns(d *observev1.SourceDescriptor, records []*observev1.Record) (bool, []string) {
	runs := map[string]bool{}
	for _, rec := range records {
		r := rec.GetImportReport()
		if r == nil || r.GetSource().GetSourceId() != d.GetSourceId() || r.GetTenantId() != d.GetTenantId() ||
			r.GetProjectId() != d.GetProjectId() {
			continue
		}
		if doubtsEveryRun(r) {
			return true, nil
		}
		for _, run := range r.GetDoubtedRunIds() {
			runs[run] = true
		}
	}
	return false, slices.Sorted(maps.Keys(runs))
}

// doubtsEveryRun reports a report that puts every run in doubt: one that
// says so, or one that counts a refused span or a conflict and names no run.
func doubtsEveryRun(r *observev1.ImportReport) bool {
	counted := r.GetCounts().GetRefused() > 0 || r.GetCounts().GetConflict() > 0
	return r.GetEveryRunDoubted() || (counted && len(r.GetDoubtedRunIds()) == 0)
}

// checkDoubt holds a report's runs in doubt to the one form a writer gives
// them: run ids in ascending order, each once, at most MaxDoubtedRunIDs, and
// none beside every_run_doubted.
func checkDoubt(r *observev1.ImportReport) error {
	runs := r.GetDoubtedRunIds()
	switch {
	case len(runs) > MaxDoubtedRunIDs:
		return fmt.Errorf("%w: doubted_run_ids: %d run ids, limit %d", ErrLine, len(runs), MaxDoubtedRunIDs)
	case r.GetEveryRunDoubted() && len(runs) > 0:
		return fmt.Errorf("%w: doubted_run_ids: set while every_run_doubted is", ErrLine)
	}
	for i, run := range runs {
		switch {
		case !ValidRunID(run):
			return fmt.Errorf("%w: doubted_run_ids[%d]: %s is not \"run-\" and 32 lowercase hex digits",
				ErrLine, i, quoted(run, maxIdentifierBytes))
		case i > 0 && runs[i-1] >= run:
			return fmt.Errorf("%w: doubted_run_ids[%d]: not after the run id before it", ErrLine, i)
		}
	}
	return nil
}
