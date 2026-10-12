package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// proposals is n requests q0, q1 and so on, each proposed and still open.
func proposals(n int) []string {
	out := make([]string, n)
	for i := range out {
		req := fmt.Sprintf("q%d", i)
		out[i] = evt(req, req+"-1", "", "ACTION_PROPOSED", proposed("read_order"))
	}
	return out
}

// TestOpenBound: 10 000 open requests are all followed; one more drops the
// oldest with an open_bound alert where it was raised, and its next event
// reads as broken while still raising what it calls for.
func TestOpenBound(t *testing.T) {
	decidedQ0 := evt("q0", "q0-2", "q0-1", "POLICY_DECIDED", decided("INDETERMINATE", "PDP_TIMEOUT"))
	undecided := `{"v":1,"alert":"indeterminate","tenant":"t","project":"p","request":"q0","run":"run-q0","event":"q0-2",` +
		`"offset":%d,"verdict":"INDETERMINATE","reasons":["PDP_TIMEOUT"]}` + "\n"
	for _, tc := range []struct {
		open                 int
		code                 int
		alerts, totals, next string
		nextAlerts           string
	}{
		{open: 10_000, totals: "totals: requests 10000, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 10000, unknown 0; " +
			"gaps 0, duplicates 0, conflicting 0, refused 0; trailer end reached",
			next: columns + "\n" + "totals: requests 10000, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 10000, unknown 0; " +
				"gaps 0, duplicates 0, conflicting 0, refused 0; trailer end reached\n",
			nextAlerts: undecided},
		{open: 10_001, code: 1, alerts: `{"v":1,"alert":"open_bound","tenant":"t","project":"p","request":"q0","run":"run-q0",` +
			`"offset":%d,"note":"more than 10000 requests are open: the oldest is no longer followed, and its later events read as broken"}` + "\n",
			totals: "totals: requests 10000, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 10000, unknown 0; " +
				"gaps 0, duplicates 0, conflicting 0, refused 0; trailer end reached",
			next: columns + "\n" +
				"t\tp\tq0\trun-q0\t-\tINDETERMINATE\tPDP_TIMEOUT\t-\tno\t-\tunknown\tevent q0-2 follows q0-1, of a request no longer followed\n" +
				"totals: requests 10001, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 10000, unknown 1; " +
				"gaps 0, duplicates 0, conflicting 0, refused 0; trailer end reached\n",
			nextAlerts: undecided + `{"v":1,"alert":"lifecycle_unknown","tenant":"t","project":"p","request":"q0","run":"run-q0","event":"q0-2",` +
				`"offset":%d,"note":"event q0-2 follows q0-1, of a request no longer followed"}` + "\n"},
	} {
		t.Run(fmt.Sprint(tc.open), func(t *testing.T) {
			lines := proposals(tc.open)
			dir := newState(t)
			got := consume(t, dir, framed("q.trail", lines, 0, len(lines), 100_000))
			_, totals := table(t, got.stdout)
			var last, end int
			for _, l := range lines {
				last, end = end, end+len(l)+1
			}
			want := strings.ReplaceAll(tc.alerts, "%d", fmt.Sprint(last))
			if got.code != tc.code || totals != tc.totals || withoutCursors(alertLines(got.stderr)) != want {
				t.Fatalf("%d proposals: exit %d, totals %q, alerts\n%s\nwant %d, %q,\n%s", tc.open, got.code, totals, alertLines(got.stderr), tc.code, tc.totals, want)
			}
			lines = append(lines, decidedQ0)
			got = consume(t, dir, framed("q.trail", lines, len(lines)-1, len(lines), 100_000))
			want = strings.ReplaceAll(tc.nextAlerts, "%d", fmt.Sprint(end))
			if got.code != 1 || got.stdout != tc.next || withoutCursors(alertLines(got.stderr)) != want {
				t.Errorf("q0 decided after: exit %d, stdout\n%s\nalerts\n%s\nwant 1,\n%s\n%s", got.code, got.stdout, alertLines(got.stderr), tc.next, want)
			}
		})
	}
}

// denials is n requests d0, d1 and so on, each denied and blocked, three
// events apiece.
func denials(n int) []string {
	out := make([]string, 0, 3*n)
	for i := range n {
		out = append(out, chain(fmt.Sprintf("d%d", i), denied...)...)
	}
	return out
}

// TestDedupWindowBound: the window keeps the last 20 000 events. A line
// repeated in the next export while its first is the 20 000th from the end is
// a duplicate; once it is the 20 001st it reads as a new event, which here
// starts a request that ended.
func TestDedupWindowBound(t *testing.T) {
	w := chain("w", denied...)
	for _, tc := range []struct {
		findings int
		code     int
		totals   string
	}{
		{findings: 2, totals: "totals: requests 0, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 0; " +
			"gaps 0, duplicates 1, conflicting 0, refused 0; trailer end reached"},
		{findings: 3, code: 1, totals: "totals: requests 0, completed 0, failed 0, uncertain 0, aborted 0, blocked 0, open 0, unknown 0; " +
			"gaps 0, duplicates 0, conflicting 0, refused 0; trailer end reached"},
	} {
		t.Run(fmt.Sprint(tc.findings), func(t *testing.T) {
			lines := append(append([]string(nil), w...), denials(6665)...)
			prev := "d6664-3"
			for i := range tc.findings {
				id := fmt.Sprintf("f%d", i)
				lines = append(lines, evt("d6664", id, prev, "FINDING_RAISED", ""))
				prev = id
			}
			if others := len(lines); others != 20_000+tc.findings-2 {
				t.Fatalf("%d events no request holds open, want %d", others, 20_000+tc.findings-2)
			}
			dir := newState(t)
			if got := consume(t, dir, framed("w.trail", lines, 0, len(lines), 100_000)); got.code != 0 {
				t.Fatalf("the first export: exit %d, stderr %s", got.code, got.stderr)
			}
			lines = append(lines, w[0])
			got := consume(t, dir, framed("w.trail", lines, len(lines)-1, len(lines), 100_000))
			_, totals := table(t, got.stdout)
			if got.code != tc.code || totals != tc.totals {
				t.Errorf("w-1 again: exit %d, totals %q; want %d, %q; stderr %s", got.code, totals, tc.code, tc.totals, got.stderr)
			}
			if tc.code == 1 && !strings.Contains(got.stderr, `"note":"event w-1 starts request w again after it ended"`) {
				t.Errorf("w-1 again past the window: stderr %s", got.stderr)
			}
		})
	}
}

// TestExportRecordBound: an export of 100 000 records and its trailer is read
// whole; one record more and the read stops at the trailer, which is refused
// with what follows it unread.
func TestExportRecordBound(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		records int
		whole   bool
	}{{records: 100_000, whole: true}, {records: 100_001}} {
		t.Run(fmt.Sprint(tc.records), func(t *testing.T) {
			t.Parallel()
			x := newExport("1.0")
			for range tc.records {
				x.gap("malformed")
			}
			got, err := readExport(strings.NewReader(x.whole() + x.lines[1] + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			if stopped(got) != !tc.whole || got.gaps != tc.records {
				t.Fatalf("%d records: %d refused, trailer read %t, %d lines and %d gaps read; want whole %t",
					tc.records, got.refused, got.trailer != nil, got.line, got.gaps, tc.whole)
			}
			if !tc.whole && !strings.Contains(got.firstRefusal, fmt.Sprintf("line %d: the export goes on past 100000 records and its trailer", tc.records+2)) {
				t.Errorf("the refusal says %q", got.firstRefusal)
			}
		})
	}
}

// stopped reports whether the read took no trailer, refused one record and
// read nothing past it.
func stopped(x *export) bool {
	if x.trailer != nil {
		return false
	}
	return x.refused == 1 && strings.Contains(x.firstRefusal, fmt.Sprintf("line %d: ", x.line))
}

// paddedGaps is an export whose records and trailer after the header are
// total bytes, newlines counted, each gap no longer than a record may be.
func paddedGaps(t *testing.T, total int) string {
	t.Helper()
	x := newExport("1.0")
	for range total/maxRecordBytes + 1 {
		x.gap("")
	}
	trailer := x.trailerLine(true, 0)
	short := total - len(trailer) - 1
	for _, l := range x.lines[1:] {
		short -= len(l) + 1
	}
	for i := 1; i < len(x.lines) && short > 0; i++ {
		pad := min(short, maxRecordBytes-len(x.lines[i]))
		x.lines[i] = strings.Replace(x.lines[i], `"reason":""`, `"reason":"`+strings.Repeat("m", pad)+`"`, 1)
		short -= pad
	}
	in := x.cut() + trailer + "\n"
	if short != 0 || len(in)-len(x.lines[0])-1 != total {
		t.Fatalf("the padded export is %d bytes after its header, want %d", len(in)-len(x.lines[0])-1, total)
	}
	return in
}

// TestExportByteBound: 64 MiB of records and trailer after the header are
// read whole; one byte more and the read stops at the trailer, which is
// refused.
func TestExportByteBound(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		bytes int
		whole bool
	}{{bytes: 64 << 20, whole: true}, {bytes: 64<<20 + 1}} {
		t.Run(fmt.Sprint(tc.bytes), func(t *testing.T) {
			t.Parallel()
			got, err := readExport(strings.NewReader(paddedGaps(t, tc.bytes) + `{"type":"gap","offset":0,"reason":"malformed"}` + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			if stopped(got) != !tc.whole {
				t.Fatalf("%d bytes: %d refused, trailer read %t, %d lines read; want whole %t", tc.bytes, got.refused, got.trailer != nil, got.line, tc.whole)
			}
			if !tc.whole && !strings.Contains(got.firstRefusal, "the export goes on past 67108864 bytes after its header") {
				t.Errorf("the refusal says %q", got.firstRefusal)
			}
		})
	}
}

// endless serves its prefix and then bytes that no newline ever ends. It
// fails a read only far past every bound, so a reader that ignores the
// bounds ends instead of spinning, and the test sees how much it took.
type endless struct {
	prefix string
	served int
}

const endlessBackstop = 4 * maxExportBytes

func (e *endless) Read(p []byte) (int, error) {
	if e.served >= len(e.prefix)+endlessBackstop {
		return 0, errors.New("the endless reader's backstop")
	}
	n := 0
	if e.served < len(e.prefix) {
		n = copy(p, e.prefix[e.served:])
	}
	for ; n < len(p); n++ {
		p[n] = 'x'
	}
	e.served += n
	return n, nil
}

// TestEndlessLine: a line no newline ends is read no further than its bound,
// the export's bytes after the header, or a record's bytes for the header
// itself, and refused there.
func TestEndlessLine(t *testing.T) {
	t.Parallel()
	const slack = 4096 // one fill of the reader's buffer past the bound
	t.Run("after the header", func(t *testing.T) {
		t.Parallel()
		header := newExport("1.0").lines[0] + "\n"
		in := &endless{prefix: header}
		got, err := readExport(in)
		if err != nil {
			t.Fatal(err)
		}
		if read := in.served - len(header); read > maxExportBytes+slack {
			t.Fatalf("read %d bytes after the header, past the bound %d; refusal %q", read, maxExportBytes, got.firstRefusal)
		}
		if !stopped(got) || !strings.Contains(got.firstRefusal, "line 2: the export goes on past 67108864 bytes after its header") {
			t.Fatalf("%d refused, the first %q; want the line refused at the byte bound", got.refused, got.firstRefusal)
		}
	})
	t.Run("the header", func(t *testing.T) {
		t.Parallel()
		in := &endless{prefix: `{"type":"header","file":"`}
		_, err := readExport(in)
		if in.served > maxRecordBytes+1+slack {
			t.Fatalf("read %d bytes of the header, past the bound %d; error %v", in.served, maxRecordBytes, err)
		}
		if err == nil || err.Error() != "the first record is not a whole header" {
			t.Fatalf("error %v, want the header refused as not whole", err)
		}
	})
}
