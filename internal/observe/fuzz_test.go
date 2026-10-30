package observe_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// FuzzReadNeutral: a descriptor that reads neutrally, written again by
// protojson, reads to the same descriptor and passes CheckNeutral, and a
// refusal is always ErrDescriptor.
func FuzzReadNeutral(f *testing.F) {
	for _, name := range []string{"descriptor.json", "descriptor-egress.json"} {
		f.Add(readTestdata(f, name))
	}
	f.Add([]byte(`{"schema_version":"0.2","kind":"egress-access-log","select":{}}`))
	f.Add([]byte(`{"schema_version":"0.1","kind":"otel-genai-traces","egress_access_log":{}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := observe.ReadNeutral(b)
		if err != nil {
			if !errors.Is(err, observe.ErrDescriptor) || d != nil {
				t.Fatalf("refusal %v with %v, want ErrDescriptor and nothing", err, d)
			}
			return
		}
		if err := observe.CheckNeutral(d); err != nil {
			t.Fatalf("a descriptor ReadNeutral took fails CheckNeutral: %v", err)
		}
		again, err := protojson.Marshal(d)
		if err != nil {
			t.Fatalf("an accepted descriptor does not encode: %v", err)
		}
		d2, err := observe.ReadNeutral(again)
		if err != nil || !proto.Equal(d, d2) {
			t.Fatalf("an accepted descriptor written again reads as %v, %v", d2, err)
		}
	})
}

// FuzzUnmarshalLine: a line that reads is a record the writer writes, whose
// line is in the writer's form and reads back to the same record; a refusal
// is always a codec error.
func FuzzUnmarshalLine(f *testing.F) {
	for _, name := range []string{"records.jsonl", "connection.jsonl"} {
		for _, line := range bytes.SplitAfter(readTestdata(f, name), []byte("\n")) {
			f.Add(line)
			f.Add(bytes.TrimSuffix(line, []byte("\n")))
		}
	}
	f.Add([]byte(`{"observation":null}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		r, err := observe.UnmarshalLine(line)
		if err != nil {
			if (!errors.Is(err, observe.ErrLine) && !errors.Is(err, observe.ErrLineTooLong)) || r != nil {
				t.Fatalf("refusal %v with %v, want a codec error and nothing", err, r)
			}
			return
		}
		out, err := observe.MarshalLine(r)
		if errors.Is(err, observe.ErrLineTooLong) {
			return
		}
		if err != nil {
			t.Fatalf("an accepted record does not write: %v", err)
		}
		if err := observe.CheckLineForm(out); err != nil {
			t.Fatalf("the writer's line is not in its form: %v", err)
		}
		back, err := observe.UnmarshalLine(out)
		if err != nil || !proto.Equal(back, r) {
			t.Fatalf("written again it reads as %v, %v", back, err)
		}
	})
}
