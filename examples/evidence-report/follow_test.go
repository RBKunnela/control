package main

import (
	"fmt"
	"strings"
	"testing"
)

const (
	rowR = "acme\tdemo\tR\trun-R\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tcompleted\t-"
	rowK = "acme\tdemo\tK\trun-K\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tcompleted\t-"
	rowG = "acme\tdemo\tG\trun-G\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tcompleted\t-"
	rowN = "acme\tdemo\tN\trun-N\trefund\tDENY\tRULE_DENY\t=\tno\t-\tblocked\t-"
	rowM = "acme\tdemo\tM\trun-M\tread_order\t-\t-\t-\tno\t-\tunknown\t" +
		"event M3 follows M2, which this export does not hold"

	rowA = "acme\tdemo\tA\trun-A\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tcompleted\t-"
	rowB = "acme\tdemo\tB\trun-B\trefund\tDENY\tRULE_DENY\t=\tno\t-\tblocked\t-"
	rowC = "acme\tdemo\tC\trun-C\texport_orders\tINDETERMINATE\tRULE_UNDETERMINED,PDP_TIMEOUT\t=\tno\t-\tblocked\t-"
	rowD = "acme\tdemo\tD\trun-D\tread_order\tALLOW\tRULE_ALLOW\tDENY PAUSED\tno\t-\tblocked\t-"
	rowE = "acme\tdemo\tE\trun-E\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\tDENY APPROVAL_EXPIRED\tyes\texpired\tblocked\t-"
)

// step is one export fed to a state, and what the run must print and log.
type followStep struct {
	export string
	code   int
	rows   []string
	totals string
	// alerts are the alert lines the run raises, each with %s where the
	// record's cursor stands, filled from the committed export by offset.
	alerts []expectedAlert
}

type expectedAlert struct {
	line   string
	offset int64
}

func (a expectedAlert) in(t *testing.T, export string) string {
	t.Helper()
	if !strings.Contains(a.line, "%s") {
		return a.line
	}
	return fmt.Sprintf(a.line, cursorOf(t, export, a.offset))
}

func gapAlert(offset int64, reason string) expectedAlert {
	return expectedAlert{fmt.Sprintf(`{"v":1,"alert":"evidence_gap","offset":%d,"cursor":"%%s","note":"%s"}`, offset, reason), offset}
}

func totalsLine(requests, completed, blocked, open, unknown, gaps, duplicates, conflicting int, trailer string) string {
	return fmt.Sprintf("totals: requests %d, completed %d, failed 0, uncertain 0, aborted 0, blocked %d, open %d, unknown %d; "+
		"gaps %d, duplicates %d, conflicting %d, refused 0; %s", requests, completed, blocked, open, unknown, gaps, duplicates, conflicting, trailer)
}

const (
	reached    = "trailer end reached"
	notReached = "trailer end not reached"
)

// runSteps feeds each export to one fresh state and checks every run, and
// returns the alert lines the runs raised, in order.
func runSteps(t *testing.T, steps []followStep) (raised string) {
	t.Helper()
	dir := newState(t)
	for _, s := range steps {
		got := consume(t, dir, fixture(t, s.export))
		if got.code != s.code {
			t.Errorf("%s: exit %d, want %d; stderr:\n%s", s.export, got.code, s.code, got.stderr)
		}
		rows, totals := table(t, got.stdout)
		if strings.Join(rows, "\n") != strings.Join(s.rows, "\n") {
			t.Errorf("%s: rows:\n%s\nwant:\n%s", s.export, strings.Join(rows, "\n"), strings.Join(s.rows, "\n"))
		}
		if totals != s.totals {
			t.Errorf("%s: totals:\n%s\nwant:\n%s", s.export, totals, s.totals)
		}
		var want strings.Builder
		for _, a := range s.alerts {
			want.WriteString(a.in(t, s.export) + "\n")
		}
		if alerts := alertLines(got.stderr); alerts != want.String() {
			t.Errorf("%s: alerts:\n%s\nwant:\n%s", s.export, alerts, want.String())
		}
		if rest := strings.TrimSpace(strings.ReplaceAll(got.stderr, name+": alert ", "")); alertLines(got.stderr) == "" && rest != "" {
			t.Errorf("%s: stderr holds more than alerts: %q", s.export, got.stderr)
		}
		raised += want.String()
	}
	if log := alertLog(t, dir); log != raised {
		t.Errorf("alerts.jsonl:\n%s\nwant the alerts raised:\n%s", log, raised)
	}
	return raised
}

// TestFollowRepeats: an exact repeat within one export is a duplicate record,
// counted and not alerted, and the request it repeats ends once.
func TestFollowRepeats(t *testing.T) {
	runSteps(t, []followStep{{export: "repeat.jsonl", rows: []string{rowR}, totals: totalsLine(1, 1, 0, 0, 0, 0, 1, 0, reached)}})
}

// TestFollowConflicts: one event id with two lines is a conflicting_event
// when the lines fall in two exports, and the exporter's gap when they fall
// in one; either way the request goes on from the line read first.
func TestFollowConflicts(t *testing.T) {
	t.Run("across exports", func(t *testing.T) {
		runSteps(t, []followStep{
			{export: "conflict-1.jsonl", totals: totalsLine(1, 0, 0, 1, 0, 0, 0, 0, notReached)},
			{export: "conflict-2.jsonl", code: 1, rows: []string{rowK}, totals: totalsLine(1, 1, 0, 0, 0, 0, 0, 1, reached),
				alerts: []expectedAlert{{`{"v":1,"alert":"conflicting_event","tenant":"acme","project":"demo","request":"K","run":"run-K",` +
					`"event":"K2","offset":634,"cursor":"%s","occurred_at":"2026-10-02T10:00:26Z","note":"event K2 was read before with other content"}`, 634}}},
		})
	})
	t.Run("within one export", func(t *testing.T) {
		runSteps(t, []followStep{{export: "conflict.jsonl", code: 1, rows: []string{rowK}, totals: totalsLine(1, 1, 0, 0, 0, 1, 0, 0, reached),
			alerts: []expectedAlert{gapAlert(634, "conflicting_event_id")}}})
	})
}

// TestFollowGaps: each gap record raises one evidence_gap with its reason and
// offset, the partial tail without a cursor, which no newline ends.
func TestFollowGaps(t *testing.T) {
	runSteps(t, []followStep{{export: "gaps.jsonl", code: 1, rows: []string{rowG},
		totals: totalsLine(1, 1, 0, 0, 0, 3, 0, 0, "trailer 15 bytes cut, no writer holds them"),
		alerts: []expectedAlert{gapAlert(305, "malformed"), gapAlert(646, "unsupported_version"),
			{`{"v":1,"alert":"evidence_gap","offset":1540,"note":"partial_tail"}`, 1540}}}})
}

// TestFollowMissingEvent: a middle event the trail never held breaks its
// request where the next one names it, once, and the events after it raise
// nothing more.
func TestFollowMissingEvent(t *testing.T) {
	runSteps(t, []followStep{{export: "missing.jsonl", code: 1, rows: []string{rowM, rowN}, totals: totalsLine(2, 0, 1, 0, 1, 0, 0, 0, reached),
		alerts: []expectedAlert{{`{"v":1,"alert":"lifecycle_unknown","tenant":"acme","project":"demo","request":"M","run":"run-M",` +
			`"event":"M3","offset":933,"cursor":"%s","occurred_at":"2026-10-02T10:00:37Z",` +
			`"note":"event M3 follows M2, which this export does not hold"}`, 933}}}})
}

var (
	alertC2 = expectedAlert{`{"v":1,"alert":"indeterminate","tenant":"acme","project":"demo","request":"C","run":"run-C","event":"C2",` +
		`"offset":2159,"cursor":"%s","occurred_at":"2026-10-02T10:00:08Z","verdict":"INDETERMINATE","reasons":["RULE_UNDETERMINED","PDP_TIMEOUT"]}`, 2159}
	alertGap = gapAlert(2875, "malformed")
	alertD3  = expectedAlert{`{"v":1,"alert":"plane_block","tenant":"acme","project":"demo","request":"D","run":"run-D","event":"D3",` +
		`"offset":4176,"cursor":"%s","occurred_at":"2026-10-02T10:00:13Z","verdict":"ALLOW","reasons":["RULE_ALLOW"],"block":"DENY PAUSED"}`, 4176}
	alertE4 = expectedAlert{`{"v":1,"alert":"approval_expired","tenant":"acme","project":"demo","request":"E","run":"run-E","event":"E4",` +
		`"offset":5447,"cursor":"%s","occurred_at":"2026-10-02T10:00:17Z"}`, 5447}
	alertE5 = expectedAlert{`{"v":1,"alert":"plane_block","tenant":"acme","project":"demo","request":"E","run":"run-E","event":"E5",` +
		`"offset":5738,"cursor":"%s","occurred_at":"2026-10-02T10:00:18Z","verdict":"REQUIRE_APPROVAL","reasons":["APPROVAL_REQUIRED"],` +
		`"block":"DENY APPROVAL_EXPIRED"}`, 5738}
)

// outageSteps is the outage: one export of the trail as it stood, then the
// trail grows while the consumer is down and is read in exports of four
// records, which stop before its end until the last.
var outageSteps = []followStep{
	{export: "outage-1.jsonl", rows: []string{rowB}, totals: totalsLine(3, 0, 1, 2, 0, 0, 0, 0, reached)},
	{export: "outage-2.jsonl", code: 1, rows: []string{rowC, rowA}, totals: totalsLine(2, 1, 1, 0, 0, 1, 0, 0, notReached),
		alerts: []expectedAlert{alertC2, alertGap}},
	{export: "outage-3.jsonl", code: 1, rows: []string{rowD}, totals: totalsLine(1, 0, 1, 0, 0, 0, 1, 0, notReached),
		alerts: []expectedAlert{alertD3}},
	{export: "outage-4.jsonl", code: 1, totals: totalsLine(1, 0, 0, 1, 0, 0, 0, 0, notReached), alerts: []expectedAlert{alertE4}},
	{export: "outage-5.jsonl", code: 1, rows: []string{rowE}, totals: totalsLine(2, 0, 1, 1, 0, 0, 0, 0, reached), alerts: []expectedAlert{alertE5}},
}

// TestFollowOutage: the request that straddles the outage ends completed once,
// the line repeated across two exports is dropped as a duplicate, and the
// alerts are the one-shot export's, in its order.
func TestFollowOutage(t *testing.T) {
	split := runSteps(t, outageSteps)
	oneShot := runSteps(t, []followStep{{export: "outage.jsonl", code: 1, rows: []string{rowB, rowC, rowA, rowD, rowE},
		totals: totalsLine(6, 1, 4, 1, 0, 1, 1, 0, reached), alerts: []expectedAlert{alertC2, alertGap, alertD3, alertE4, alertE5}}})
	if split != oneShot {
		t.Errorf("the outage raised:\n%s\nthe one-shot export:\n%s", split, oneShot)
	}
}
