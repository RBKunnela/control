package main

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
)

const (
	rowAllowed      = "t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tcompleted\t-"
	rowDenied       = "t\tp\tr2\trun-r2\trefund\tDENY\tRULE_DENY\t=\tno\t-\tblocked\t-"
	rowApproved     = "t\tp\tr3\trun-r3\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\t-\tyes\tapproved\tcompleted\t-"
	rowRejected     = "t\tp\tr4\trun-r4\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\tDENY APPROVAL_REJECTED\tyes\trejected\tblocked\t-"
	rowExpired      = "t\tp\tr5\trun-r5\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\tDENY APPROVAL_EXPIRED\tyes\texpired\tblocked\t-"
	rowFailed       = "t\tp\tr6\trun-r6\texport_orders\tALLOW\tRULE_ALLOW\t-\tno\t-\tfailed\t-"
	rowUndetermined = "t\tp\tr7\trun-r7\texport_orders\tINDETERMINATE\tRULE_UNDETERMINED,PDP_TIMEOUT\t=\tno\t-\tblocked\t-"

	oneCompleted = "totals: requests 1, completed 1, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 0; "
	endReached   = "; trailer end reached"
)

func swapped(events []string, i, j int) []string {
	out := append([]string(nil), events...)
	out[i], out[j] = out[j], out[i]
	return out
}

func without(events []string, i int) []string {
	return append(append([]string(nil), events[:i]...), events[i+1:]...)
}

func interleaved(a, b []string) []string {
	var out []string
	for i := 0; i < len(a) || i < len(b); i++ {
		if i < len(a) {
			out = append(out, a[i])
		}
		if i < len(b) {
			out = append(out, b[i])
		}
	}
	return out
}

type reportCase struct {
	name   string
	in     string
	rows   []string
	totals string
	code   int
	// stderr is a phrase the diagnostics must hold; empty wants none at all.
	stderr string
}

func TestReport(t *testing.T) {
	r1 := chain("r1", allowed...)
	clean := concat(swapped(r1, 1, 2), interleaved(chain("r2", denied...), chain("r3", approved...)),
		chain("r4", rejected...), chain("r5", expired...), chain("r6", failed...), chain("r7", undetermined...))
	cases := []reportCase{
		{name: "clean lifecycles joined by their links, not the file's order", in: newExport("1.0").event(clean...).whole(),
			rows: []string{rowAllowed, rowDenied, rowApproved, rowRejected, rowExpired, rowFailed, rowUndetermined},
			totals: "totals: requests 7, completed 2, failed 1, uncertain 0, aborted 0, blocked 4, open 0, unknown 0; " +
				"gaps 0, duplicates 0, conflicting 0, refused 0" + endReached},
		{name: "a higher minor is read", in: newExport("1.7").event(r1...).whole(),
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 0" + endReached},
		{name: "a missing middle event breaks the chain", in: newExport("1.0").event(without(r1, 1)...).event(chain("r2", denied...)...).whole(),
			rows: []string{"t\tp\tr1\trun-r1\tread_order\t-\t-\t-\tno\t-\tunknown\tevent r1-3 follows r1-2, which this export does not hold", rowDenied},
			totals: "totals: requests 2, completed 0, failed 0, uncertain 0, aborted 0, blocked 1, open 0, unknown 1; " +
				"gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
			code: 1, stderr: "not every request"},
		{name: "a missing last event leaves the request open", in: newExport("1.0").event(r1[:3]...).event(chain("r8", held...)...).whole(),
			rows: []string{"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\topen\tno event ends the action",
				"t\tp\tr8\trun-r8\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\t-\tyes\tpending\topen\tno event ends the action"},
			totals: "totals: requests 2, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 2, unknown 0; " +
				"gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
			code: 1, stderr: "not every request"},
		{name: "a gap record", in: newExport("1.0").event(r1...).gap("malformed").whole(),
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 1, duplicates 0, conflicting 0, refused 0" + endReached,
			code: 1, stderr: "gap"},
		{name: "an exact duplicate is dropped", in: newExport("1.0").event(r1...).duplicate("r1-2", 100).whole(),
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 1, conflicting 0, refused 0" + endReached},
		{name: "a duplicate naming an event the export did not write there", in: newExport("1.0").event(r1...).duplicate("r1-2", 200).whole(),
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1" + endReached,
			code: 1, stderr: "duplicate"},
		{name: "an event repeated byte for byte is dropped", in: newExport("1.0").event(r1...).event(r1[1]).whole(),
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 1, conflicting 0, refused 0" + endReached},
		{name: "one event id with two contents", in: newExport("1.0").event(r1...).event(strings.Replace(r1[3], "x1", "x9", 1)).whole(),
			rows: []string{"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\tevent r1-4 is held twice with different content"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 1; " +
				"gaps 0, duplicates 0, conflicting 1, refused 0" + endReached,
			code: 1, stderr: "different content"},
		{name: "an unknown record type", in: newExport("1.0").event(r1...).raw(`{"type":"annotation","offset":900}`).whole(),
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1" + endReached,
			code: 1, stderr: "a type this reader does not know"},
		{name: "an unknown major", in: newExport("2.0").event(r1...).whole(), code: 1, stderr: "major 2"},
		{name: "a version that is not MAJOR.MINOR", in: newExport("1").event(r1...).whole(), code: 1, stderr: "MAJOR.MINOR"},
		{name: "another format", in: strings.Replace(newExport("1.0").event(r1...).whole(), exportFormat, "other.evidence-export", 1),
			code: 1, stderr: "format"},
		{name: "no header", in: strings.Join(newExport("1.0").event(r1...).lines[1:], "\n") + "\n", code: 1, stderr: "header"},
		{name: "no input", in: "", code: 1, stderr: "header"},
		{name: "a cut export has no trailer", in: newExport("1.0").event(r1...).cut(),
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 0; no trailer read, the export is not whole",
			code: 1, stderr: "cut"},
		{name: "a trailer without its newline was cut", in: strings.TrimSuffix(newExport("1.0").event(r1...).whole(), "\n"),
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1; no trailer read, the export is not whole",
			code: 1, stderr: "cut"},
	}
	cases = append(cases, trailerCases(r1)...)
	cases = append(cases, eventCases(r1)...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc) })
	}
}

func trailerCases(r1 []string) []reportCase {
	x := newExport("1.0").event(r1...)
	cutTail := newExport("1.0").event(r1...).partialTail()
	return []reportCase{
		{name: "a trailer short of the file's end", in: x.cut() + x.trailerLine(false, 0) + "\n",
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 0; trailer end not reached",
			code: 1, stderr: "end"},
		{name: "a line still being written", in: x.cut() + x.heldTrailerLine(true, 20, true) + "\n",
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 0; trailer 20 bytes still being written",
			code: 1, stderr: "the trailer says 20 bytes are still being written: export again once they end"},
		{name: "a cut line no writer holds", in: cutTail.cut() + cutTail.trailerLine(true, 20) + "\n",
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 1, duplicates 0, conflicting 0, refused 0; trailer 20 bytes cut, no writer holds them",
			code: 1, stderr: "the trailer says the 20 bytes after the last newline are a cut line no writer holds: the file is damaged there"},
		{name: "a trailer without writer_held", in: x.cut() + strings.Replace(x.trailerLine(true, 0), `"writer_held":false,`, "", 1) + "\n",
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1; no trailer read, the export is not whole",
			code: 1, stderr: "writer_held"},
		{name: "a trailer counting other records", in: x.cut() + strings.Replace(x.trailerLine(true, 0), `"event":4`, `"event":5`, 1) + "\n",
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1; no trailer read, the export is not whole",
			code: 1, stderr: "counts"},
		{name: "a trailer without end_reached", in: x.cut() + strings.Replace(x.trailerLine(true, 0), `"end_reached":true,`, "", 1) + "\n",
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1; no trailer read, the export is not whole",
			code: 1, stderr: "end_reached"},
		{name: "a record after the trailer", in: x.whole() + `{"type":"gap","offset":900,"reason":"malformed"}` + "\n",
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1" + endReached,
			code: 1, stderr: "after the trailer"},
		{name: "a second header", in: newExport("1.0").raw(newExport("1.0").lines[0]).event(r1...).whole(),
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1" + endReached,
			code: 1, stderr: "second header"},
	}
}

func eventCases(r1 []string) []reportCase {
	backwards := newExport("1.0").event(r1...).raw(`{"type":"gap","offset":100,"cursor":"v1:` + exportSource + `:200:` + digest("\n") + `","reason":"malformed"}`)
	return []reportCase{
		{name: "an event of another major", in: newExport("1.0").event(r1[:3]...).event(strings.Replace(r1[3], `"1.0"`, `"2.0"`, 1)).whole(),
			rows:   []string{"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\topen\tno event ends the action"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 1, unknown 0; gaps 0, duplicates 0, conflicting 0, refused 1" + endReached,
			code:   1, stderr: "schema_version"},
		{name: "an event with a field the contract does not name", in: newExport("1.0").event(r1[:3]...).event(strings.Replace(r1[3], "}", `,"granted":true}`, 1)).whole(),
			rows:   []string{"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\topen\tno event ends the action"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 1, unknown 0; gaps 0, duplicates 0, conflicting 0, refused 1" + endReached,
			code:   1, stderr: "an event the contract does not read"},
		{name: "offsets out of the file's order", in: backwards.cut() + strings.Replace(backwards.trailerLine(true, 0), `"gap":0`, `"gap":1`, 1) + "\n",
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1" + endReached,
			code: 1, stderr: "offset"},
		{name: "two events follow one", in: newExport("1.0").event(r1...).event(evt("r1", "r1-x", "r1-1", "POLICY_DECIDED", decided("ALLOW", "RULE_ALLOW"))).whole(),
			rows:   []string{"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\tevents r1-2 and r1-x both follow r1-1"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 1; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
			code:   1, stderr: "not every request"},
		{name: "two events start one request", in: newExport("1.0").event(r1...).event(evt("r1", "r1-y", "", "ACTION_PROPOSED", proposed("read_order"))).whole(),
			rows:   []string{"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\tevents r1-1 and r1-y both start the request"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 1; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
			code:   1, stderr: "not every request"},
		{name: "a step the lifecycle does not take", in: newExport("1.0").event(chain("r1", allowed[0], allowed[2], allowed[3])...).whole(),
			rows:   []string{"t\tp\tr1\trun-r1\tread_order\t-\t-\t-\tno\t-\tunknown\tACTION_STARTED cannot follow ACTION_PROPOSED"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 1; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
			code:   1, stderr: "not every request"},
		{name: "a kind this reader cannot place", in: newExport("1.0").event(r1[:3]...).event(strings.Replace(r1[3], `"EVENT_KIND_ACTION_COMPLETED"`, "99", 1)).whole(),
			rows:   []string{"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\tevent r1-4 has kind 99, which this reader cannot place"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 1; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
			code:   1, stderr: "not every request"},
		{name: "a decision event without its decision", in: newExport("1.0").event(chain("r1", allowed[0], step{"POLICY_DECIDED", ""}, allowed[2], allowed[3])...).whole(),
			rows:   []string{"t\tp\tr1\trun-r1\tread_order\t-\t-\t-\tno\t-\tunknown\tevent r1-2 is POLICY_DECIDED and carries no decision"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 1; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
			code:   1, stderr: "not every request"},
		{name: "an answer that is neither yes nor no", in: newExport("1.0").event(chain("r3", approved[0], approved[1], approved[2], step{"APPROVAL_DECIDED", approval("PENDING")}, approved[4], approved[5])...).whole(),
			rows:   []string{"t\tp\tr3\trun-r3\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\t-\tyes\tunknown\tunknown\tevent r3-4 decides the approval as APPROVAL_STATE_PENDING"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 1; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
			code:   1, stderr: "not every request"},
		{name: "an end naming another execution", in: newExport("1.0").event(chain("r1", allowed[0], allowed[1], allowed[2], step{"ACTION_COMPLETED", execution("x9")})...).whole(),
			rows:   []string{"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\tevent r1-4 ends execution x9, not x1, which started"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 1; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
			code:   1, stderr: "not every request"},
		{name: "an event naming no request", in: newExport("1.0").event(strings.Replace(evt("r1", "r1-1", "", "ACTION_PROPOSED", proposed("read_order")), `"requestId":"r1",`, "", 1)).whole(),
			rows:   []string{"t\tp\t-\trun-r1\tread_order\t-\t-\t-\tno\t-\tunknown\tan event names no tenant, project or request"},
			totals: "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 1; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
			code:   1, stderr: "not every request"},
		{name: "a replacement character in a value is quoted", in: newExport("1.0").event(chain("r1", step{"ACTION_PROPOSED", proposed("read�order")}, allowed[1], allowed[2], allowed[3])...).whole(),
			rows:   []string{"t\tp\tr1\trun-r1\t\"read�order\"\tALLOW\tRULE_ALLOW\t-\tno\t-\tcompleted\t-"},
			totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 0" + endReached},
	}
}

func check(t *testing.T, tc reportCase) {
	t.Helper()
	got := report(t, tc.in)
	if got.code != tc.code {
		t.Errorf("exit status %d, want %d; stderr:\n%s", got.code, tc.code, got.stderr)
	}
	switch {
	case tc.stderr == "" && got.stderr != "":
		t.Errorf("stderr holds %q, want nothing", got.stderr)
	case !strings.Contains(got.stderr, tc.stderr):
		t.Errorf("stderr %q does not say %q", got.stderr, tc.stderr)
	}
	if tc.rows == nil && tc.totals == "" {
		if got.stdout != "" {
			t.Errorf("a refused export printed a report:\n%s", got.stdout)
		}
		return
	}
	rows, totals := table(t, got.stdout)
	if strings.Join(rows, "\n") != strings.Join(tc.rows, "\n") {
		t.Errorf("rows:\n%s\nwant:\n%s", strings.Join(rows, "\n"), strings.Join(tc.rows, "\n"))
	}
	if totals != tc.totals {
		t.Errorf("totals:\n%s\nwant:\n%s", totals, tc.totals)
	}
}

func TestUsage(t *testing.T) {
	got := report(t, newExport("1.0").event(chain("r1", allowed...)...).whole(), "trail.jsonl")
	if got.code != 2 || got.stdout != "" || !strings.Contains(got.stderr, "usage") {
		t.Fatalf("an argument: exit %d, stdout %q, stderr %q; want 2, nothing, a usage line", got.code, got.stdout, got.stderr)
	}
}

// TestRecordBound pins the longest record read: one byte over it is refused,
// and the trailer it held is not read. The bound holds the exporter's longest
// event record: a line of the plane's longest, as testdata/plane.json gives
// it, in the framing the exporter wrote around a demo event, its two offsets
// at the most digits an int64 has.
func TestRecordBound(t *testing.T) {
	var first struct {
		Offset int64           `json:"offset"`
		Cursor string          `json:"cursor"`
		Event  json.RawMessage `json:"event"`
	}
	record := strings.Split(demoExport(t), "\n")[1]
	if err := json.Unmarshal([]byte(record), &first); err != nil {
		t.Fatal(err)
	}
	cursor := strings.Split(first.Cursor, ":")
	if len(cursor) != 4 || len(first.Event) == 0 {
		t.Fatalf("the demo's first record is not an event with a v1 cursor: %s", record)
	}
	digits := len(strconv.FormatInt(math.MaxInt64, 10))
	framing := len(record) - len(first.Event) - len(strconv.FormatInt(first.Offset, 10)) - len(cursor[2])
	if longest := framing + 2*digits + readPlane(t).LineBoundBytes; maxRecordBytes < longest {
		t.Fatalf("the bound is %d bytes and the exporter's longest event record %d", maxRecordBytes, longest)
	}

	x := newExport("1.0").event(chain("r1", allowed...)...)
	trailer := x.trailerLine(true, 0)
	padded := func(n int) string {
		return x.cut() + strings.TrimSuffix(trailer, "}") + strings.Repeat(" ", n-len(trailer)) + "}\n"
	}
	if got := report(t, padded(maxRecordBytes)); got.code != 0 {
		t.Errorf("a trailer of exactly %d bytes: exit %d, want 0; stderr:\n%s", maxRecordBytes, got.code, got.stderr)
	}
	got := report(t, padded(maxRecordBytes+1))
	if got.code != 1 || !strings.Contains(got.stderr, "longer than") || !strings.Contains(got.stdout, "no trailer read") {
		t.Errorf("a trailer one byte over: exit %d, stderr %q; want 1, refused as too long, no trailer read", got.code, got.stderr)
	}
}
