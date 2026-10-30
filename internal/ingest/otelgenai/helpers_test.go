package otelgenai_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/ingest/otelgenai"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	descSHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	traceA  = "4bf92f3577b34da6a3ce929d0e0e4736"
	traceB  = "5bf92f3577b34da6a3ce929d0e0e4737"
	runA    = "run-0123456789abcdef0123456789abcdef"
)

var received = time.Date(2026, 10, 4, 10, 5, 0, 0, time.UTC)

func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS("testdata"), name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return b
}

func descriptor(t testing.TB) *observev1.SourceDescriptor {
	t.Helper()
	d, err := observe.ReadNeutral(readTestdata(t, "descriptor.json"))
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if err := otelgenai.Check(d); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	return d
}

func importBytes(t testing.TB, in []byte, desc *observev1.SourceDescriptor) otelgenai.Batch {
	t.Helper()
	b, err := otelgenai.Import(bytes.NewReader(in), desc, descSHA, received)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	checkBatch(t, b)
	return b
}

func importFile(t testing.TB, name string) otelgenai.Batch {
	t.Helper()
	return importBytes(t, readTestdata(t, name), descriptor(t))
}

// checkBatch writes every record as a log line and holds the report to
// account for each span read exactly once. It returns the lines.
func checkBatch(t testing.TB, b otelgenai.Batch) string {
	t.Helper()
	var out strings.Builder
	for _, o := range b.Observations {
		line, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_Observation{Observation: o}})
		if err != nil {
			t.Fatalf("observation %s does not pass MarshalLine: %v", o.GetObservationId(), err)
		}
		out.Write(line)
	}
	line, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: b.Report}})
	if err != nil {
		t.Fatalf("report does not pass MarshalLine: %v", err)
	}
	out.Write(line)
	c := b.Report.GetCounts()
	sum := c.GetObserved() + c.GetOtherResource() + c.GetRefused()
	for _, n := range c.GetSkipped() {
		sum += n
	}
	if sum != c.GetRead() || c.GetObserved() != uint64(len(b.Observations)) {
		t.Fatalf("counts do not add up: %v with %d observations", c, len(b.Observations))
	}
	return out.String()
}

func wantCounts(t testing.TB, b otelgenai.Batch, want *observev1.ImportCounts) {
	t.Helper()
	if want.Skipped == nil {
		want.Skipped = map[string]uint64{}
	}
	got := b.Report.GetCounts()
	if !proto.Equal(got, want) {
		t.Errorf("counts:\n got %s\nwant %s", protojson.Format(got), protojson.Format(want))
	}
}

func ts(t testing.TB, s string) *timestamppb.Timestamp {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("time %q: %v", s, err)
	}
	return timestamppb.New(v)
}

func spanID(n int) string { return fmt.Sprintf("00f067aa0ba9%04x", n) }

func source() *observev1.SourceRef {
	return &observev1.SourceRef{
		SourceId:         "agent-runtime",
		DescriptorSha256: descSHA,
		Trust:            observev1.Trust_TRUST_SELF_REPORTED,
		Convention:       &observev1.Convention{Name: "opentelemetry.gen_ai", Version: "1.41.0"},
	}
}

func obsID(trace string, span int) string {
	return observe.ObservationID("tenant-a", "project-a", "agent-runtime", trace, spanID(span))
}

func byID(t testing.TB, b otelgenai.Batch, span int) *observev1.Observation {
	t.Helper()
	for _, o := range b.Observations {
		if o.GetCorrelation().GetSpanId() == spanID(span) && o.GetCorrelation().GetTraceId() == traceA {
			return o
		}
	}
	t.Fatalf("no observation of span %d", span)
	return nil
}

func equal(t testing.TB, got, want proto.Message) {
	t.Helper()
	if !proto.Equal(got, want) {
		t.Errorf("\n got %s\nwant %s", protojson.Format(got), protojson.Format(want))
	}
}

// firstLineSHA256 digests the bytes before the first newline, independently
// of the importer's incremental hash.
func firstLineSHA256(in []byte) string {
	line, _, _ := bytes.Cut(in, []byte("\n"))
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}
