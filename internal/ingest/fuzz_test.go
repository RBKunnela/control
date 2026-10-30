package ingest_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/guardana/control/internal/ingest"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// FuzzReadDescriptor: a descriptor that reads, written again by protojson,
// reads to the same descriptor, and a refusal is always ErrDescriptor or
// ErrVersion.
func FuzzReadDescriptor(f *testing.F) {
	for _, name := range []string{otelFixture, envoyFixture, squidFixture} {
		fixture := readFixture(f, name)
		f.Add(fixture)
		f.Add(bytes.Replace(fixture, []byte(`"source_id"`), []byte(`"sourceId"`), 1))
	}
	otel := readFixture(f, otelFixture)
	f.Add(bytes.Replace(otel, []byte(`"TRUST_SELF_REPORTED"`), []byte(`3`), 1))
	f.Add(bytes.Replace(otel, []byte(`"1.41.0"`), []byte(`"1.40.0"`), 1))
	f.Add(bytes.Replace(readFixture(f, envoyFixture), []byte(`"json-lines"`), []byte(`"xml"`), 1))
	f.Add([]byte(`{"source_id":"a","sourceId":"b"}`))
	f.Add([]byte(`{"select":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ingest.ReadDescriptor(b)
		if err != nil {
			if (!errors.Is(err, observe.ErrDescriptor) && !errors.Is(err, observe.ErrVersion)) || d != nil {
				t.Fatalf("refusal %v with %v, want ErrDescriptor or ErrVersion and nothing", err, d)
			}
			return
		}
		again, err := protojson.Marshal(d)
		if err != nil {
			t.Fatalf("an accepted descriptor does not encode: %v", err)
		}
		d2, err := ingest.ReadDescriptor(again)
		if err != nil || !proto.Equal(d, d2) {
			t.Fatalf("an accepted descriptor written again reads as %v, %v", d2, err)
		}
	})
}
