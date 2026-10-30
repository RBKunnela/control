package observe

import (
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
)

// Liveness is what a source's import reports say of it at one time. The zero
// value is NeverHeard, so a liveness nobody judged is never live.
type Liveness int

// The states of a source at a time.
const (
	// NeverHeard is a source no import report of its own says was heard.
	NeverHeard Liveness = iota
	// Lapsed is a source last heard more than its heartbeat before the time.
	Lapsed
	// Ahead is a source last heard after the time: as of it, the source's
	// clock and the time's disagree, or it was heard later.
	Ahead
	// Live is a source last heard within its heartbeat before the time.
	Live
)

// LastHeard is the newest event time an import report of the source names,
// each taken no later than its report's receive time, and false when none
// does. A report counts only when it names the descriptor's source, tenant,
// project and kind and carries both times: a report another tenant's import,
// or an import of another kind, wrote is not this source heard.
func LastHeard(d *observev1.SourceDescriptor, records []*observev1.Record) (time.Time, bool) {
	var last time.Time
	heard := false
	for _, r := range records {
		rep := r.GetImportReport()
		latest, received := rep.GetLatestEventTime(), rep.GetReceivedTime()
		if !Reports(d, rep) || !latest.IsValid() || !received.IsValid() {
			continue
		}
		t := latest.AsTime()
		if rt := received.AsTime(); t.After(rt) {
			t = rt
		}
		if !heard || t.After(last) {
			last, heard = t, true
		}
	}
	return last, heard
}

// LivenessAt judges a source last heard at last, when heard, with a
// heartbeat of heartbeatSeconds, as of at. Every time is the caller's.
func LivenessAt(last time.Time, heard bool, heartbeatSeconds uint32, at time.Time) Liveness {
	switch {
	case !heard:
		return NeverHeard
	case last.After(at):
		return Ahead
	case at.Sub(last) > time.Duration(heartbeatSeconds)*time.Second:
		return Lapsed
	}
	return Live
}

// Reports reports whether r is an import report of d's source: one naming its
// source id, tenant, project and kind, under whichever descriptor digest
// wrote it.
func Reports(d *observev1.SourceDescriptor, r *observev1.ImportReport) bool {
	return r != nil && r.GetSource().GetSourceId() == d.GetSourceId() && r.GetTenantId() == d.GetTenantId() &&
		r.GetProjectId() == d.GetProjectId() && RecordKind(r.GetSource()) == d.GetKind()
}
