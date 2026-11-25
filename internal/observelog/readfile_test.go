package observelog

import (
	"bytes"
	"testing"

	"github.com/guardana/control/internal/observe"
)

// FuzzReadCommitted: whatever a file holds, the read either refuses it with
// an error that quotes none of it, or returns records the codec writes, no
// more than the file has newlines, the last of them an import report, and
// says a write is unclosed whenever the file does not end with one.
func FuzzReadCommitted(f *testing.F) {
	f.Add(readGolden(f, "log.jsonl"))
	f.Add(readGolden(f, "log.resumed.jsonl"))
	f.Add([]byte(`{"importReport":{"schemaVersion":"0.1"}}` + "\n" + `{"obs`))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		read, err := readCommitted(bytes.NewReader(body), int64(len(body)))
		got := read.Records
		if err != nil {
			if bytes.ContainsAny([]byte(err.Error()), `"{`) {
				t.Fatalf("the error quotes the file: %q", err)
			}
			return
		}
		if len(got) > bytes.Count(body, []byte("\n")) {
			t.Fatalf("%d records from %d newlines", len(got), bytes.Count(body, []byte("\n")))
		}
		if len(got) > 0 && got[len(got)-1].GetImportReport() == nil {
			t.Fatalf("the last record is no import report: %v", got[len(got)-1])
		}
		closedAtEnd := len(body) == 0 || body[len(body)-1] == '\n' && len(got) > 0
		if !read.Unclosed && !closedAtEnd {
			t.Fatalf("a body of %d bytes and %d records read as every write closed", len(body), len(got))
		}
		for i, r := range got {
			if _, err := observe.MarshalLine(r); err != nil {
				t.Fatalf("record %d does not encode: %v", i, err)
			}
		}
	})
}
