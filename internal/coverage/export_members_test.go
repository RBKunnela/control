package coverage_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/guardana/control/internal/coverage"
)

// noLine is the header and trailer members of an export of a file that holds
// no whole line: the contract leaves out its source and next cursor.
func noLine(b string) string {
	b = strings.Replace(b, `"source":"`+sourceDigest+`",`, "", 1)
	return strings.Replace(b, `"next_cursor":"c",`, "", 1)
}

func drop(record, member string) string {
	for _, m := range []string{member + `":0,`, member + `":"c",`, member + `":false,`, member + `":true,`} {
		record = strings.Replace(record, `"`+m, "", 1)
	}
	return record
}

func swap(record, from, to string) string { return strings.Replace(record, from, to, 1) }

// tail is the trailer of an export whose file ends in 7 bytes no newline ends.
func tail(gaps int, held bool) string {
	tr := swap(trailer(0, gaps, 0, true), `"tail_bytes":0`, `"tail_bytes":7`)
	if held {
		tr = swap(tr, `"writer_held":false`, `"writer_held":true`)
	}
	return tr
}

const partialTail = `{"type":"gap","offset":0,"reason":"partial_tail"}`

func TestReadExportRefusesAMissingOrMisspelledMember(t *testing.T) {
	ev := proposal{trace: traceA, span: spanA}.line()
	end := trailer(1, 0, 0, true)
	h := header(plainQuery)
	gap := `{"type":"gap","offset":0,"cursor":"c","reason":"malformed"}`
	dup := `{"type":"duplicate","offset":9,"event_id":"e1","first_offset":0}`
	cases := map[string][]byte{
		"a header without its source":              lines(noLine(h), ev, end),
		"a source that is not a digest":            lines(swap(h, sourceDigest, "57f7f9c1"), ev, end),
		"a source in upper case":                   lines(swap(h, sourceDigest, strings.ToUpper(sourceDigest)), ev, end),
		"a trailer without its next cursor":        lines(h, ev, noLine(end)),
		"an empty next cursor":                     lines(h, ev, swap(end, `"next_cursor":"c"`, `"next_cursor":""`)),
		"a line in a file with no whole line":      lines(noLine(h), ev, noLine(end)),
		"a cursor in a file with no whole line":    lines(noLine(header(`{"after":"v1:x","limit":1000}`)), noLine(trailer(0, 0, 0, true))),
		"a query without its limit":                lines(header(`{}`), ev, end),
		"a limit of 0":                             lines(header(`{"limit":0}`), ev, end),
		"a limit past 100000":                      lines(header(`{"limit":100001}`), ev, end),
		"a limit spelled as a string":              lines(header(`{"limit":"1000"}`), ev, end),
		"a byte bound of 0":                        lines(header(`{"limit":1000,"max_bytes":0}`), ev, end),
		"an empty cursor to start after":           lines(header(`{"after":"","limit":1000}`), ev, end),
		"an event without its offset":              lines(h, drop(ev, "offset"), end),
		"an event without its cursor":              lines(h, drop(ev, "cursor"), end),
		"an event with an empty cursor":            lines(h, swap(ev, `"cursor":"c"`, `"cursor":""`), end),
		"a negative offset":                        lines(h, swap(ev, `"offset":0`, `"offset":-1`), end),
		"a fractional offset":                      lines(h, swap(ev, `"offset":0`, `"offset":0.5`), end),
		"a gap without its offset":                 lines(h, drop(gap, "offset"), trailer(0, 1, 0, true)),
		"a gap within the file without its cursor": lines(h, drop(gap, "cursor"), trailer(0, 1, 0, true)),
		"a partial tail with a cursor":             lines(h, swap(gap, "malformed", "partial_tail"), tail(1, false)),
		"a record after the partial tail":          lines(h, partialTail, ev, swap(tail(1, false), `"event":0`, `"event":1`)),
		"a partial tail and no tail bytes":         lines(h, partialTail, trailer(0, 1, 0, true)),
		"a partial tail a writer holds":            lines(h, partialTail, tail(1, true)),
		"tail bytes no writer holds and no gap":    lines(h, ev, swap(end, `"tail_bytes":0`, `"tail_bytes":7`)),
		"a duplicate without its offset":           lines(h, ev, swap(dup, `"offset":9,`, ""), trailer(1, 0, 1, true)),
		"a duplicate without its event id":         lines(h, ev, swap(dup, `"event_id":"e1",`, ""), trailer(1, 0, 1, true)),
		"a duplicate without its first offset":     lines(h, ev, swap(dup, `,"first_offset":0`, ""), trailer(1, 0, 1, true)),
		"a trailer without tail_bytes":             lines(h, ev, drop(end, "tail_bytes")),
		"a trailer without writer_held":            lines(h, ev, drop(end, "writer_held")),
		"a trailer without scanned_bytes":          lines(h, ev, swap(end, `,"scanned_bytes":0`, "")),
		"a trailer without dedup_scope":            lines(h, ev, swap(end, `,"dedup_scope":"export"`, "")),
		"a trailer without counts":                 lines(h, ev, swap(end, `"counts":{"event":1,"gap":0,"duplicate":0},`, "")),
		"another dedup scope":                      lines(h, ev, swap(end, `"dedup_scope":"export"`, `"dedup_scope":"file"`)),
		"writer_held spelled as a string":          lines(h, ev, swap(end, `"writer_held":false`, `"writer_held":"false"`)),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			x, err := coverage.ReadExport(bytes.NewReader(b))
			if !errors.Is(err, coverage.ErrExport) || x != nil {
				t.Fatalf("ReadExport = %+v, %v; want ErrExport", x, err)
			}
		})
	}
}

// TestReadExportReadsWhatTheContractLeavesOut: the members the contract says
// are absent in a case read in that case, and every bound reads at its edge.
func TestReadExportReadsWhatTheContractLeavesOut(t *testing.T) {
	ev := proposal{trace: traceA, span: spanA}.line()
	cases := []struct {
		name   string
		b      []byte
		whole  bool
		events int
	}{
		{"a file of one partial line", lines(noLine(header(plainQuery)), partialTail, noLine(tail(1, false))), false, 0},
		{"a file of one line a writer is writing", lines(noLine(header(plainQuery)), noLine(tail(0, true))), true, 0},
		{"a partial tail after the whole lines", lines(header(plainQuery), ev, partialTail,
			swap(tail(1, false), `"event":0`, `"event":1`)), false, 1},
		{"a limit of 1", lines(header(`{"limit":1}`), ev, trailer(1, 0, 0, true)), true, 1},
		{"a limit of 100000", lines(header(`{"limit":100000}`), ev, trailer(1, 0, 0, true)), true, 1},
		{"a byte bound of 1", lines(header(`{"limit":1000,"max_bytes":1}`), ev, trailer(1, 0, 0, true)), true, 1},
		{"tail bytes past a limit that left no room for their gap", lines(header(`{"limit":1}`), ev,
			swap(trailer(1, 0, 0, false), `"tail_bytes":0`, `"tail_bytes":7`)), false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := mustExport(t, tc.b)
			if x.Whole != tc.whole || x.Events != tc.events {
				t.Fatalf("whole %v (%q), %d events; want whole %v, %d events", x.Whole, x.NotWhole, x.Events, tc.whole, tc.events)
			}
		})
	}
}
