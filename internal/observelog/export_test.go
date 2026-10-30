package observelog

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/lineexport"
)

func source(t testing.TB, name string, body []byte) lineexport.Source {
	t.Helper()
	return lineexport.Source{Name: name, R: bytes.NewReader(body), Size: int64(len(body))}
}

func readGolden(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: the test's own fixture
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// goldenCases are the queries the goldens were written for. Between them
// they hold a record of both types, a duplicate of each, a gap of every
// reason but too_long, a cursor taken from an earlier export and a header
// naming every query member.
var goldenCases = map[string]Query{
	"log.export.jsonl": {Limit: DefaultExportLimit},
	"log.resumed.jsonl": {
		After: "v1:dcb1fd173fc72f876364fba297dd9dd32f122b78630eb034a235d3422538e80d:1330:" +
			"292dd320022b956798cdf2767c94c728e68dc0dee9e64c82c529b6abe5ef7d1f",
		Limit: 4, MaxBytes: 100_000,
	},
}

func TestTheExportMatchesItsGoldens(t *testing.T) {
	body := readGolden(t, "log.jsonl")
	for name, q := range goldenCases {
		var out bytes.Buffer
		if _, err := Export(source(t, "log.jsonl", body), q, &out); err != nil {
			t.Fatalf("%s: Export = %v", name, err)
		}
		if want := readGolden(t, name); !bytes.Equal(out.Bytes(), want) {
			t.Errorf("%s: the export does not match its golden\n--- got ---\n%s--- want ---\n%s", name, out.String(), want)
		}
	}
}

// TestAnExportResumesWhereTheLastOneStopped: two exports of three records
// and two, the second after the first's cursor, hold the records of one
// export of five. Duplicates are found within one export, so the split
// falls where no later line repeats an earlier one.
func TestAnExportResumesWhereTheLastOneStopped(t *testing.T) {
	body := readGolden(t, "log.jsonl")
	var whole, first, second bytes.Buffer
	if _, err := Export(source(t, "log.jsonl", body), Query{Limit: 5}, &whole); err != nil {
		t.Fatal(err)
	}
	tr, err := Export(source(t, "log.jsonl", body), Query{Limit: 3}, &first)
	if err != nil || tr.EndReached {
		t.Fatalf("the first export = %+v, %v; want one that stops short", tr, err)
	}
	if _, err := Export(source(t, "log.jsonl", body), Query{After: tr.NextCursor, Limit: 2}, &second); err != nil {
		t.Fatal(err)
	}
	inner := func(b []byte) []string {
		l := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		return l[1 : len(l)-1]
	}
	got, want := append(inner(first.Bytes()), inner(second.Bytes())...), inner(whole.Bytes())
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("two exports hold\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestAnExportRefusesACursorItCannotPlace(t *testing.T) {
	body := readGolden(t, "log.jsonl")
	var first bytes.Buffer
	tr, err := Export(source(t, "log.jsonl", body), Query{Limit: 2}, &first)
	if err != nil {
		t.Fatal(err)
	}
	other := append([]byte("{}\n"), body...)
	for name, c := range map[string]struct {
		body  []byte
		after string
		want  error
	}{
		"another file":   {other, tr.NextCursor, ErrCursorOtherFile},
		"malformed":      {body, "v1:" + strings.Repeat("a", 64), ErrCursorMalformed},
		"past the end":   {body[:600], tr.NextCursor, ErrCursorPastEnd},
		"off a line":     {body, strings.Replace(tr.NextCursor, ":1121:", ":1120:", 1), ErrCursorOffLine},
		"a changed line": {changed(body, 1000), tr.NextCursor, ErrCursorChanged},
	} {
		var out bytes.Buffer
		if _, err := Export(source(t, "log.jsonl", c.body), Query{After: c.after, Limit: 2}, &out); !errors.Is(err, c.want) {
			t.Errorf("%s: Export = %v, want %v", name, err, c.want)
		}
		if out.Len() != 0 {
			t.Errorf("%s: the refused export wrote %q", name, out.String())
		}
	}
}

func TestTheExportRefusesAQueryOutsideItsBounds(t *testing.T) {
	body := readGolden(t, "log.jsonl")
	for _, c := range []struct {
		q    Query
		want error
	}{
		{Query{Limit: 0}, ErrQuery},
		{Query{Limit: MaxExportLimit + 1}, ErrQuery},
		{Query{Limit: 1, MaxBytes: -1}, ErrQuery},
		{Query{Limit: MaxExportLimit}, nil},
		{Query{Limit: 1, MaxBytes: 10}, ErrByteBound},
	} {
		var out bytes.Buffer
		_, err := Export(source(t, "log.jsonl", body), c.q, &out)
		if !errors.Is(err, c.want) || (err == nil) != (c.want == nil) {
			t.Errorf("%+v: Export = %v, want %v", c.q, err, c.want)
		}
	}
	if MaxExportLimit != 100_000 || DefaultExportLimit != 1000 {
		t.Errorf("limits %d and %d, want the evidence export's 100000 and 1000", MaxExportLimit, DefaultExportLimit)
	}
}

// TestAnImportReportIsADuplicateOnlyWhenEveryByteRepeats: two reports of one
// import that differ in a count are two records.
func TestAnImportReportIsADuplicateOnlyWhenEveryByteRepeats(t *testing.T) {
	r := `{"importReport":{"schemaVersion":"0.1","tenantId":"t","projectId":"p","source":{"sourceId":"s"},"receivedTime":"2026-10-04T10:05:00Z","counts":{"read":"%s"}}}` + "\n"
	body := []byte(strings.Replace(r, "%s", "1", 1) + strings.Replace(r, "%s", "2", 1) + strings.Replace(r, "%s", "1", 1))
	tr, err := Export(source(t, "r.jsonl", body), Query{Limit: 10}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Counts["import_report"] != 2 || tr.Counts[lineexport.Duplicate] != 1 || tr.Counts[lineexport.Gap] != 0 {
		t.Errorf("counts = %v, want 2 import reports and 1 duplicate", tr.Counts)
	}
}

// changed is body with the byte at i replaced by another.
func changed(body []byte, i int) []byte {
	out := bytes.Clone(body)
	out[i] ^= 0x20
	return out
}

// gapReason exports one line and returns the reason of the gap it became,
// or "" when it became a record.
func gapReason(t *testing.T, line string) string {
	t.Helper()
	var out bytes.Buffer
	tr, err := Export(source(t, "l.jsonl", []byte(line)), Query{Limit: 10}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range bytes.Split(out.Bytes(), []byte("\n")) {
		var rec struct{ Type, Reason string }
		if json.Unmarshal(l, &rec) == nil && rec.Type == lineexport.Gap {
			return rec.Reason
		}
	}
	if tr.Counts[typeObservation]+tr.Counts[typeImportReport] != 1 {
		t.Fatalf("%.40q: no gap and no record, counts %v", line, tr.Counts)
	}
	return ""
}

// TestTheExportNamesWhyALineIsAGap: each line is the golden's first with
// one change, so the change alone decides the verdict.
func TestTheExportNamesWhyALineIsAGap(t *testing.T) {
	a := string(bytes.SplitAfter(readGolden(t, "log.jsonl"), []byte("\n"))[0])
	later := strings.Replace(a, `"0.1"`, `"0.4"`, 1)
	for name, c := range map[string]struct{ line, want string }{
		"the writer's line":          {a, ""},
		"a CRLF ending":              {strings.TrimSuffix(a, "\n") + "\r\n", gapCR},
		"a raw C1 control":           {strings.Replace(a, "read_file", "read\u009bfile", 1), gapMalformed},
		"a snake_case member":        {strings.Replace(a, `"tenantId"`, `"tenant_id"`, 1), gapMalformed},
		"a space between tokens":     {strings.Replace(a, `"tenantId":`, `"tenantId": `, 1), gapMalformed},
		"a later version":            {later, gapVersion},
		"a later version's member":   {strings.Replace(later, `"tenantId"`, `"futureMember":1,"tenantId"`, 1), gapVersion},
		"an unknown member at 0.1":   {strings.Replace(a, `"tenantId"`, `"futureMember":1,"tenantId"`, 1), gapMalformed},
		"an unknown kind at a later": {`{"futureRecord":{"schemaVersion":"0.4"}}` + "\n", gapMalformed},
	} {
		if got := gapReason(t, c.line); got != c.want {
			t.Errorf("%s: the line is %q, want %q", name, got, c.want)
		}
	}
}
