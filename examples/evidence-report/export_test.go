package main

import (
	"strings"
	"testing"
)

// TestStrictRecords holds every record to the members the contract gives it,
// each spelled exactly and held once: a lenient decoder takes the last of two
// keys and a key in any case, which lets a record say two things at once.
func TestStrictRecords(t *testing.T) {
	r1 := chain("r1", allowed...)
	x := newExport("1.0").event(r1...)
	header := newExport("1.0").lines[0]
	trailer := x.trailerLine(true, 0)
	withHeader := func(h string) string { return h + "\n" + strings.Join(x.lines[1:], "\n") + "\n" + trailer + "\n" }
	withTrailer := func(tr string) string { return x.cut() + tr + "\n" }
	noTrailer := func(name, in, says string) reportCase {
		return reportCase{name: name, in: in, rows: []string{rowAllowed},
			totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1; no trailer read, the export is not whole",
			code:   1, stderr: says}
	}
	// refusedRecord follows the request with one record the trailer counts
	// by the type it names. A record that is not one object names no type.
	refusedRecord := func(name, record, says string) reportCase {
		y := newExport("1.0").event(r1...).raw(record)
		switch {
		case strings.HasPrefix(record, `{"type":"event"`):
			y.events++
		case strings.HasPrefix(record, `{"type":"gap"`):
			y.gaps++
		default:
			y.n++
		}
		return reportCase{name: name, in: y.whole(), rows: []string{rowAllowed},
			totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1" + endReached, code: 1, stderr: says}
	}
	firstEvent := x.lines[1]
	cases := []reportCase{
		{name: "a header key held twice", in: withHeader(strings.Replace(header, `"version":"1.0"`, `"version":"2.0","version":"1.0"`, 1)),
			code: 1, stderr: `member "version" appears twice`},
		{name: "a header in capitals", in: withHeader(strings.Replace(strings.Replace(header, `"type"`, `"Type"`, 1), `"format"`, `"FORMAT"`, 1)),
			code: 1, stderr: `differs from "type" only in case`},
		{name: "a header member the contract does not name", in: withHeader(strings.Replace(header, `"file"`, `"granted":true,"file"`, 1)),
			code: 1, stderr: "a member the contract does not name"},
		{name: "a query member the contract does not name", in: withHeader(strings.Replace(header, `"limit":1000`, `"limit":1000,"requests":["r1"]`, 1)),
			code: 1, stderr: "a member the contract does not name"},
		{name: "a query member in another case", in: withHeader(strings.Replace(header, `"limit":1000`, `"limit":1000,"Kind":["X"]`, 1)),
			code: 1, stderr: `differs from "kind" only in case`},
		{name: "a query that is not an object", in: withHeader(strings.Replace(header, `{"limit":1000}`, `[]`, 1)),
			code: 1, stderr: "query"},
		noTrailer("a trailer key held twice", withTrailer(strings.Replace(trailer, `"end_reached":true`, `"end_reached":false,"end_reached":true`, 1)),
			`member "end_reached" appears twice`),
		noTrailer("a trailer key in another case", withTrailer(strings.Replace(trailer, `"end_reached":true`, `"end_reached":false,"END_REACHED":true`, 1)),
			`differs from "end_reached" only in case`),
		noTrailer("a trailer type in capitals", withTrailer(strings.Replace(trailer, `"type"`, `"TYPE"`, 1)),
			`differs from "type" only in case`),
		noTrailer("a trailer member the contract does not name", withTrailer(strings.Replace(trailer, `"writer_held"`, `"complete":true,"writer_held"`, 1)),
			"a member the contract does not name"),
		noTrailer("a count the contract does not name", withTrailer(strings.Replace(trailer, `"duplicate":0}`, `"duplicate":0,"finding":0}`, 1)),
			"a member the contract does not name"),
		noTrailer("a count held twice", withTrailer(strings.Replace(trailer, `"counts":{"event":4`, `"counts":{"event":9,"event":4`, 1)),
			`member "event" appears twice`),
		noTrailer("a negative tail", withTrailer(strings.Replace(trailer, `"tail_bytes":0`, `"tail_bytes":-5`, 1)),
			"tail_bytes"),
		noTrailer("an end not reached with no next cursor", withTrailer(strings.Replace(x.trailerLine(false, 0), `"next_cursor":"`+someCursor+`",`, "", 1)),
			"next_cursor"),
		noTrailer("an end not reached with a next cursor that is not v1", withTrailer(strings.Replace(x.trailerLine(false, 0), someCursor, "c", 1)),
			"next_cursor"),
		noTrailer("a next cursor with a leading zero", withTrailer(strings.Replace(x.trailerLine(false, 0), ":2100:", ":02100:", 1)),
			"next_cursor"),
		noTrailer("a next cursor in capitals", withTrailer(strings.Replace(x.trailerLine(false, 0), "v1:aaaa", "v1:AAAA", 1)),
			"next_cursor"),
		noTrailer("a trailer followed by more on its line", withTrailer(trailer+` {}`), "more follows the object"),
		{name: "an event record key held twice", in: newExport("1.0").event(r1...).raw(strings.Replace(firstEvent, `"offset":0`, `"offset":400,"offset":500`, 1)).whole(),
			rows: []string{rowAllowed}, totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1" + endReached,
			code: 1, stderr: `member "offset" appears twice`},
		refusedRecord("an event record key in another case", strings.Replace(strings.Replace(firstEvent, `"offset":0`, `"offset":400`, 1), `"event":{`, `"Event":{`, 1),
			`differs from "event" only in case`),
		refusedRecord("an event record member the contract does not name", `{"type":"event","offset":400,"cursor":"c","event":{},"verified":true}`,
			"a member the contract does not name"),
		refusedRecord("a gap record member the contract does not name", `{"type":"gap","offset":400,"reason":"malformed","event_id":"r1-1"}`,
			`member "event_id"`),
		refusedRecord("a duplicate record key in another case", `{"type":"duplicate","offset":400,"event_id":"r1-2","First_Offset":100}`,
			`differs from "first_offset" only in case`),
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc) })
	}
}

// TestTrailerCursor accepts a next cursor spelled as the contract spells one,
// so the refusals above are of the spelling and not of every cursor.
func TestTrailerCursor(t *testing.T) {
	x := newExport("1.0").event(chain("r1", allowed...)...)
	check(t, reportCase{in: x.cut() + x.trailerLine(false, 0) + "\n", rows: []string{rowAllowed},
		totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 0; trailer end not reached",
		code:   1, stderr: "export again after its next_cursor"})
}

// TestNoRequest holds that an export accounting for no request is not a
// clean report: a filter naming a request that is not there reads the same.
func TestNoRequest(t *testing.T) {
	filtered := strings.Replace(newExport("1.0").whole(), `"limit":1000`, `"limit":1000,"request":["typo"]`, 1)
	for name, in := range map[string]string{"no event": newExport("1.0").whole(), "a filter that passed nothing": filtered} {
		t.Run(name, func(t *testing.T) {
			check(t, reportCase{in: in,
				totals: "totals: requests 0, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 0; gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
				code:   1, stderr: "accounts for no request"})
		})
	}
}

// TestConflictAcrossRequests holds that one event id with two contents makes
// both requests unknown when the two lines belong to different requests.
func TestConflictAcrossRequests(t *testing.T) {
	r1 := chain("r1", allowed...)
	r2 := chain("r2", denied...)
	r2[2] = evt("r2", "r1-4", "r2-2", "ACTION_BLOCKED", decided("DENY", "RULE_DENY"))
	check(t, reportCase{in: newExport("1.0").event(r1...).event(r2...).whole(),
		rows: []string{"t\tp\tr1\trun-r1\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\tevent r1-4 is held twice with different content",
			"t\tp\tr2\trun-r2\trefund\tDENY\tRULE_DENY\tDENY RULE_DENY\tno\t-\tunknown\tevent r1-4 is held twice with different content"},
		totals: "totals: requests 2, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 2; gaps 0, duplicates 0, conflicting 1, refused 0" + endReached,
		code:   1, stderr: "different content"})
}

// TestGapSaidOnce holds a gap to one line of diagnostics.
func TestGapSaidOnce(t *testing.T) {
	got := report(t, newExport("1.0").event(chain("r1", allowed...)...).gap("malformed").whole())
	if got.code != 1 || strings.Count(got.stderr, "gap") != 1 || !strings.Contains(got.stderr, "a gap at offset 400: malformed") {
		t.Fatalf("exit %d, stderr:\n%s\nwant 1 and the gap said once", got.code, got.stderr)
	}
}

// TestTrailerScan holds the trailer to scanned_bytes, a count no less than
// zero, and to dedup_scope "export", the scope of the duplicates it reports.
func TestTrailerScan(t *testing.T) {
	x := newExport("1.0").event(chain("r1", allowed...)...)
	trailer := x.trailerLine(true, 0)
	scanned := `,"scanned_bytes":400`
	if !strings.Contains(trailer, scanned) || !strings.Contains(trailer, `,"dedup_scope":"export"}`) {
		t.Fatalf("the trailer is not the one these cases edit: %s", trailer)
	}
	edited := func(from, to string) string { return x.cut() + strings.Replace(trailer, from, to, 1) + "\n" }
	refused := oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 1; no trailer read, the export is not whole"
	for _, tc := range []reportCase{
		{name: "no scanned_bytes", in: edited(scanned, ""), code: 1, stderr: "scanned_bytes"},
		{name: "a null scanned_bytes", in: edited(scanned, `,"scanned_bytes":null`), code: 1, stderr: "scanned_bytes"},
		{name: "a negative scanned_bytes", in: edited(scanned, `,"scanned_bytes":-1`), code: 1, stderr: "scanned_bytes is -1"},
		{name: "no dedup_scope", in: edited(`,"dedup_scope":"export"`, ""), code: 1, stderr: "dedup_scope"},
		{name: "a null dedup_scope", in: edited(`"dedup_scope":"export"`, `"dedup_scope":null`), code: 1, stderr: "dedup_scope"},
		{name: "another dedup_scope", in: edited(`"dedup_scope":"export"`, `"dedup_scope":"file"`), code: 1, stderr: "dedup_scope"},
		{name: "a dedup_scope in capitals", in: edited(`"dedup_scope":"export"`, `"dedup_scope":"Export"`), code: 1, stderr: "dedup_scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.rows, tc.totals = []string{rowAllowed}, refused
			check(t, tc)
		})
	}
	t.Run("a scanned_bytes of zero", func(t *testing.T) {
		check(t, reportCase{in: edited(scanned, `,"scanned_bytes":0`), rows: []string{rowAllowed},
			totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 0" + endReached})
	})
}

// TestHeaderSource holds the header's source to the SHA-256 of a first line,
// 64 lowercase hex digits, or to its absence while the file has no whole line.
func TestHeaderSource(t *testing.T) {
	sum := strings.Repeat("0123456789abcdef", 4)
	header := func(member string) string {
		return `{"type":"header","format":"` + exportFormat + `","version":"1.0","file":"a.trail",` + member + `"query":{"limit":1}}` + "\n"
	}
	for _, tc := range []struct {
		name, member string
		refused      bool
	}{
		{name: "a digest", member: `"source":"` + sum + `",`},
		{name: "no source", member: ``},
		{name: "a digest in capitals", member: `"source":"` + strings.ToUpper(sum) + `",`, refused: true},
		{name: "a digest one digit short", member: `"source":"` + sum[1:] + `",`, refused: true},
		{name: "a digest one digit long", member: `"source":"` + sum + `0",`, refused: true},
		{name: "an empty source", member: `"source":"",`, refused: true},
		{name: "a null source", member: `"source":null,`, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readExport(strings.NewReader(header(tc.member)))
			switch {
			case tc.refused && (err == nil || err.Error() != "the header's source is not the SHA-256 of a first line in 64 lowercase hex digits"):
				t.Fatalf("error %v, want the source refused", err)
			case !tc.refused && err != nil:
				t.Fatalf("error %v, want the header read", err)
			}
		})
	}
}

// TestRecordCursor holds an event's and a gap's cursor to its defined form:
// spelled v1, of the file the header names, and ending after the record's
// offset, where its line starts.
func TestRecordCursor(t *testing.T) {
	src := strings.Repeat("0123456789abcdef", 4)
	other := strings.Repeat("fedcba9876543210", 4)
	line := strings.Repeat("5", 64)
	header := `{"type":"header","format":"` + exportFormat + `","version":"1.0","file":"a.trail","source":"` + src + `","query":{"limit":9}}`
	noSource := `{"type":"header","format":"` + exportFormat + `","version":"1.0","file":"a.trail","query":{"limit":9}}`
	ev := chain("r1", allowed...)[0]
	records := map[string]func(cursor string) string{
		"event": func(c string) string { return `{"type":"event","offset":100,"cursor":"` + c + `","event":` + ev + `}` },
		"gap":   func(c string) string { return `{"type":"gap","offset":100,"cursor":"` + c + `","reason":"malformed"}` },
	}
	for _, tc := range []struct {
		name, header, cursor, says string
	}{
		{name: "one byte past its offset", header: header, cursor: "v1:" + src + ":101:" + line},
		{name: "not spelled v1", header: header, cursor: "c200", says: "whose cursor is not a v1 cursor"},
		{name: "empty", header: header, cursor: "", says: "whose cursor is not a v1 cursor"},
		{name: "of another file", header: header, cursor: "v1:" + other + ":200:" + line, says: "whose cursor is not of the file the header names"},
		{name: "of a header naming no source", header: noSource, cursor: "v1:" + src + ":200:" + line,
			says: "whose cursor is not of the file the header names"},
		{name: "at its offset", header: header, cursor: "v1:" + src + ":100:" + line, says: "whose cursor does not end after its offset, 100"},
		{name: "before its offset", header: header, cursor: "v1:" + src + ":99:" + line, says: "whose cursor does not end after its offset, 100"},
	} {
		for typ, record := range records {
			t.Run(typ+" "+tc.name, func(t *testing.T) {
				got, err := readExport(strings.NewReader(tc.header + "\n" + record(tc.cursor) + "\n"))
				if err != nil {
					t.Fatal(err)
				}
				switch want := "line 2: a" + map[string]string{"event": "n event", "gap": " gap"}[typ] + " record " + tc.says; {
				case tc.says == "" && got.refused != 0:
					t.Fatalf("refused %q, want the record read", got.firstRefusal)
				case tc.says != "" && (got.refused != 1 || got.firstRefusal != want):
					t.Fatalf("%d refused, the first %q; want %q", got.refused, got.firstRefusal, want)
				}
			})
		}
	}
}

// TestAFilteredExportIsNotWhole: a query naming a filter other than requests
// leaves out the events it does not name, such as a trailing event of another
// run, so a request it shows completed may not be. The report says so and
// exits 1, as for a cut export. A filter that names only requests selects
// whole requests, and exits 0 as the export without a filter does. A member
// other than requests that the query states counts, even empty or null.
func TestAFilteredExportIsNotWhole(t *testing.T) {
	whole := newExport("1.0").event(chain("r1", allowed...)...).whole()
	kinds := `"kind":["EVENT_KIND_ACTION_PROPOSED","EVENT_KIND_POLICY_DECIDED","EVENT_KIND_ACTION_STARTED","EVENT_KIND_ACTION_COMPLETED"]`
	for name, tc := range map[string]struct {
		filter string
		split  bool
	}{
		"no filter":            {"", false},
		"requests":             {`,"request":["r1"]`, false},
		"a cursor":             {`,"after":"` + someCursor + `"`, false},
		"a byte bound":         {`,"max_bytes":1000000`, false},
		"a run":                {`,"run":["run-r1"]`, true},
		"a kind":               {"," + kinds, true},
		"requests and a run":   {`,"request":["r1"],"run":["run-r1"]`, true},
		"requests and a kind":  {`,"request":["r1"],` + kinds, true},
		"a tenant":             {`,"tenant":["t"]`, true},
		"an empty run filter":  {`,"request":["r1"],"run":[]`, true},
		"a run filter of null": {`,"request":["r1"],"run":null`, true},
	} {
		t.Run(name, func(t *testing.T) {
			in := strings.Replace(whole, `"limit":1000`, `"limit":1000`+tc.filter, 1)
			if !tc.split {
				check(t, reportCase{in: in, rows: []string{rowAllowed},
					totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 0" + endReached})
				return
			}
			check(t, reportCase{in: in, rows: []string{rowAllowed},
				totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 0" + endReached,
				code:   1, stderr: "the export's query names a filter other than requests"})
		})
	}
}
