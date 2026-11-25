package findinglog

import (
	"bytes"
	"testing"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"google.golang.org/protobuf/proto"
)

// FuzzReadLog: whatever a file holds, the reader returns whole writes only,
// each ending with its report, after at most one header, and every record
// it returns the writer writes again into a log the reader reads back the
// same.
func FuzzReadLog(f *testing.F) {
	a := line(f, findingRecord(finding(idA, confirmed, "repeated_denial")))
	b := line(f, findingRecord(finding(idB, suspected, "a\u0085b\u202ec")))
	r := line(f, writtenReport(1))
	f.Add([]byte(header02 + a + r + b + r))
	f.Add([]byte(header02 + a))
	f.Add([]byte(finding02 + report02))
	f.Add([]byte(a + r + b + r))
	f.Add([]byte(a + r + b + r[:30]))
	f.Add([]byte(a + b))
	f.Add([]byte("{}\n\r\n\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		got, committed, err := readCommitted(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return
		}
		if committed < 0 || committed > int64(len(body)) {
			t.Fatalf("the committed writes end at %d of %d bytes", committed, len(body))
		}
		wholeWrites(t, got)
		var again []byte
		for _, rec := range got {
			l, err := marshalLine(rec)
			if err != nil {
				t.Fatalf("the writer refuses a record the reader returned: %v", err)
			}
			again = append(again, l...)
		}
		back, end, err := readCommitted(bytes.NewReader(again), int64(len(again)))
		if err != nil || len(back) != len(got) || end != int64(len(again)) {
			t.Fatalf("the rewritten log reads as %d records ending at %d, %v; want %d ending at %d", len(back), end, err, len(got), len(again))
		}
		for i := range got {
			if !proto.Equal(back[i], got[i]) {
				t.Fatalf("record %d reads back as %v, want %v", i, back[i], got[i])
			}
		}
	})
}

// wholeWrites fails t unless got is at most one header, then whole writes,
// the last of them ending with its report.
func wholeWrites(t *testing.T, got []*findingv1alpha1.Record) {
	t.Helper()
	writes := got
	if len(got) > 0 && got[0].GetLogHeader() != nil {
		writes = got[1:]
	}
	if len(writes) > 0 && writes[len(writes)-1].GetSuperviseReport() == nil {
		t.Fatalf("the last record returned is no report: %v", writes[len(writes)-1])
	}
	for _, rec := range writes {
		if rec.GetLogHeader() != nil {
			t.Fatalf("a header after the first record: %v", got)
		}
	}
}
