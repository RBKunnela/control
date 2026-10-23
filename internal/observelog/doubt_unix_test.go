//go:build unix

package observelog

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

const (
	runX = "run-0123456789abcdef0123456789abcdef"
	runY = "run-11111111111111111111111111111111"
	runZ = "run-22222222222222222222222222222222"
)

// claiming is the span's observation with the tool named name, claimed for
// run, or claiming none when run is "".
func claiming(span, name, run string) *observev1.Observation {
	o := observation(span, name, "2026-10-04T10:05:00Z")
	if run != "" {
		o.Correlation.Basis, o.Correlation.RunId = observev1.Basis_BASIS_CLAIMED, run
	}
	return o
}

// lastReport is the report the log's last line holds.
func lastReport(t *testing.T, dir string) *observev1.ImportReport {
	t.Helper()
	recs := records(t, filepath.Join(dir, FileName))
	return recs[len(recs)-1].GetImportReport()
}

// TestAConflictPutsTheRunsOfBothCopiesInDoubt: the report of a write names,
// beside the runs the import's own report named, the runs claimed by the
// copies the log refused as conflicts and by the copies it kept under their
// ids, whether kept by this write or an earlier one, a reopened log
// included; not by duplicates. A refused copy that claims no run puts every
// run in doubt, a kept one that claims none adds no run.
func TestAConflictPutsTheRunsOfBothCopiesInDoubt(t *testing.T) {
	for name, c := range map[string]struct {
		named []string
		every bool
		obs   []*observev1.Observation
		want  []string
		all   bool
	}{
		"no conflict": {nil, false, []*observev1.Observation{claiming(spanB, "read_file", runY), claiming(spanB, "read_file", runY)}, nil, false},
		"a refused copy claiming Z": {nil, false, []*observev1.Observation{claiming(spanB, "read_file", runY),
			claiming(spanB, "drop_table", runZ), claiming(spanB, "drop_table", runZ)}, []string{runY, runZ}, false},
		"a kept copy of Y, written before": {nil, false, []*observev1.Observation{claiming(spanA, "drop_table", runZ)}, []string{runY, runZ}, false},
		"a kept copy claiming none":        {nil, false, []*observev1.Observation{claiming(spanB, "read_file", ""), claiming(spanB, "drop_table", runZ)}, []string{runZ}, false},
		"the import's own and a conflict's": {[]string{runY}, false, []*observev1.Observation{claiming(spanA, "drop_table", runX)},
			[]string{runX, runY}, false},
		"a refused copy claiming none": {nil, false, []*observev1.Observation{claiming(spanA, "drop_table", "")}, nil, true},
		"the import's every run":       {nil, true, []*observev1.Observation{claiming(spanA, "drop_table", runX)}, nil, true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := logDir(t)
			l := openLog(t, dir)
			write(t, l, report("2026-10-04T10:05:00Z"), claiming(spanA, "read_file", runY))
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			l = openLog(t, dir)
			rep := report("2026-10-04T10:06:00Z")
			rep.DoubtedRunIds, rep.EveryRunDoubted = c.named, c.every
			if c.every || len(c.named) > 0 {
				rep.SchemaVersion = "0.2"
			}
			write(t, l, rep, c.obs...)
			got := lastReport(t, dir)
			if got.GetEveryRunDoubted() != c.all || !slices.Equal(got.GetDoubtedRunIds(), c.want) {
				t.Fatalf("every %v, runs %v; want %v, %v", got.GetEveryRunDoubted(), got.GetDoubtedRunIds(), c.all, c.want)
			}
			want := "0.1"
			if c.all || len(c.want) > 0 {
				want = "0.2"
			}
			if got.GetSchemaVersion() != want {
				t.Fatalf("schema_version %q, want %q", got.GetSchemaVersion(), want)
			}
		})
	}
}

// TestAConflictPastTheBoundPutsEveryRunInDoubt: an import that named 64
// runs, the kept copy's among them, and a conflict that claims a 65th names
// none, and every run is in doubt.
func TestAConflictPastTheBoundPutsEveryRunInDoubt(t *testing.T) {
	var named []string
	for i := 1; i <= 64; i++ {
		named = append(named, fmt.Sprintf("run-%032x", i+0x100))
	}
	for name, c := range map[string]struct {
		run   string
		every bool
	}{"a run already named": {named[0], false}, "a 65th run": {runX, true}} {
		t.Run(name, func(t *testing.T) {
			dir := logDir(t)
			l := openLog(t, dir)
			write(t, l, report("2026-10-04T10:05:00Z"), claiming(spanA, "read_file", named[0]))
			rep := report("2026-10-04T10:06:00Z")
			rep.SchemaVersion, rep.DoubtedRunIds = "0.2", slices.Clone(named)
			write(t, l, rep, claiming(spanA, "drop_table", c.run))
			if got := lastReport(t, dir); got.GetEveryRunDoubted() != c.every || (len(got.GetDoubtedRunIds()) == 64) == c.every {
				t.Fatalf("every %v, %d runs named; want every %v", got.GetEveryRunDoubted(), len(got.GetDoubtedRunIds()), c.every)
			}
		})
	}
}

// TestAReportInDoubtTheCodecRefusesRefusesTheWrite: a report whose runs in
// doubt are in a form the codec refuses is refused as ErrRecord, and the
// write leaves the file as it was, rather than having its runs put in order.
func TestAReportInDoubtTheCodecRefusesRefusesTheWrite(t *testing.T) {
	var many []string
	for i := 1; i <= 65; i++ {
		many = append(many, fmt.Sprintf("run-%032x", i))
	}
	for name, edit := range map[string]func(r *observev1.ImportReport){
		"out of order":       func(r *observev1.ImportReport) { r.DoubtedRunIds = []string{runY, runX} },
		"a run twice":        func(r *observev1.ImportReport) { r.DoubtedRunIds = []string{runX, runX} },
		"not a run id":       func(r *observev1.ImportReport) { r.DoubtedRunIds = []string{"run-1"} },
		"65 runs":            func(r *observev1.ImportReport) { r.DoubtedRunIds = many },
		"runs and every run": func(r *observev1.ImportReport) { r.DoubtedRunIds, r.EveryRunDoubted = []string{runX}, true },
		"a run under 0.1":    func(r *observev1.ImportReport) { r.SchemaVersion, r.DoubtedRunIds = "0.1", []string{runX} },
		"0.2 naming no run":  func(r *observev1.ImportReport) { r.DoubtedRunIds = nil },
	} {
		t.Run(name, func(t *testing.T) {
			dir := logDir(t)
			l := openLog(t, dir)
			write(t, l, report("2026-10-04T10:05:00Z"), claiming(spanA, "read_file", runY))
			before := contents(t, filepath.Join(dir, FileName))
			rep := report("2026-10-04T10:06:00Z")
			rep.SchemaVersion, rep.DoubtedRunIds = "0.2", []string{runZ}
			edit(rep)
			if _, err := l.Write([]*observev1.Observation{claiming(spanA, "drop_table", runX)}, rep); !errors.Is(err, ErrRecord) {
				t.Fatalf("Write = %v, want ErrRecord", err)
			}
			if after := contents(t, filepath.Join(dir, FileName)); string(after) != string(before) {
				t.Fatalf("the refused write changed the file")
			}
		})
	}
}

// TestTheExportCarriesA02ReportAsARecord: a report naming runs in doubt is
// exported as an import_report, its line as written; one marked "0.2" that
// names none is no line a writer leaves, and a gap.
func TestTheExportCarriesA02ReportAsARecord(t *testing.T) {
	r := report("2026-10-04T10:06:00Z")
	r.SchemaVersion, r.DoubtedRunIds = "0.2", []string{runX}
	line, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: r}})
	if err != nil {
		t.Fatalf("MarshalLine: %v", err)
	}
	if got := gapReason(t, string(line)); got != "" {
		t.Errorf("a 0.2 report is a %q gap, want a record", got)
	}
	none := strings.Replace(string(line), `,"doubtedRunIds":["`+runX+`"]`, "", 1)
	if none == string(line) {
		t.Fatal("the line names no run to take out")
	}
	if got := gapReason(t, none); got != gapMalformed {
		t.Errorf("a 0.2 report naming no run is a %q gap, want %q", got, gapMalformed)
	}
}

// TestAReportOfEveryRunStaysSoThroughAConflict: a caller's 0.1 report that
// counts a refused span and names no run doubts every run, and a conflict
// the write finds does not narrow it to the conflict's runs. The write's
// own conflicts, which it names, are not read as unnamed ones.
func TestAReportOfEveryRunStaysSoThroughAConflict(t *testing.T) {
	for name, c := range map[string]struct {
		counts *observev1.ImportCounts
		every  bool
		runs   []string
	}{
		"a refusal named by no run":  {&observev1.ImportCounts{Read: 1, Refused: 1}, true, nil},
		"a conflict named by no run": {&observev1.ImportCounts{Read: 1, Conflict: 1}, true, nil},
		"nothing refused":            {&observev1.ImportCounts{Read: 1}, false, []string{runX, runY}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := logDir(t)
			l := openLog(t, dir)
			write(t, l, report("2026-10-04T10:05:00Z"), claiming(spanA, "read_file", runY))
			rep := report("2026-10-04T10:06:00Z")
			rep.Counts = c.counts
			write(t, l, rep, claiming(spanA, "drop_table", runX))
			got := lastReport(t, dir)
			if got.GetEveryRunDoubted() != c.every || !slices.Equal(got.GetDoubtedRunIds(), c.runs) || got.GetSchemaVersion() != "0.2" {
				t.Fatalf("schema %s, every %v, runs %v; want 0.2, %v, %v", got.GetSchemaVersion(), got.GetEveryRunDoubted(), got.GetDoubtedRunIds(), c.every, c.runs)
			}
		})
	}
}
