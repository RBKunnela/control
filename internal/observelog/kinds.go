package observelog

import (
	"fmt"
	"strconv"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

// sourceKey is a source as a record names it: its tenant, project and id.
type sourceKey struct{ tenant, project, source string }

// sourceKinds is the kind each source's records in the log are of, so a log
// never holds one source's records under two kinds.
type sourceKinds map[sourceKey]string

func kindOf(r *observev1.Record) (sourceKey, string) {
	if o := r.GetObservation(); o != nil {
		return sourceKey{o.GetTenantId(), o.GetProjectId(), o.GetSource().GetSourceId()}, observe.RecordKind(o.GetSource())
	}
	ir := r.GetImportReport()
	return sourceKey{ir.GetTenantId(), ir.GetProjectId(), ir.GetSource().GetSourceId()}, observe.RecordKind(ir.GetSource())
}

// note records the kinds of records read back from the file. A source whose
// records already disagree keeps the first kind its records name.
func (k sourceKinds) note(records []*observev1.Record) {
	for _, r := range records {
		key, kind := kindOf(r)
		if _, ok := k[key]; !ok {
			k[key] = kind
		}
	}
}

// admit returns the kinds a write of records would add, or ErrKind when one
// of them names a source the log, or an earlier one of records, holds under
// another kind.
func (k sourceKinds) admit(records []*observev1.Record) (sourceKinds, error) {
	added := sourceKinds{}
	for _, r := range records {
		key, kind := kindOf(r)
		held, ok := k[key]
		if !ok {
			held, ok = added[key]
		}
		switch {
		case ok && held != kind:
			return nil, fmt.Errorf("%w: source %s holds records of kind %s, and this write is of kind %s",
				ErrKind, strconv.QuoteToASCII(key.source), strconv.QuoteToASCII(held), strconv.QuoteToASCII(kind))
		case !ok:
			added[key] = kind
		}
	}
	return added, nil
}

func batchRecords(obs []*observev1.Observation, report *observev1.ImportReport) []*observev1.Record {
	out := make([]*observev1.Record, 0, len(obs)+1)
	for _, o := range obs {
		out = append(out, &observev1.Record{Record: &observev1.Record_Observation{Observation: o}})
	}
	return append(out, &observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: report}})
}
