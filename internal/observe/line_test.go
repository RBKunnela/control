package observe_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestTheFixtureLinesRoundTrip(t *testing.T) {
	lines := fixtureLines(t)
	for i, want := range []*observev1.Record{obsRecord(fixtureObservation()), reportRecord(fixtureReport())} {
		got, err := observe.UnmarshalLine(lines[i])
		if err != nil {
			t.Fatalf("line %d: UnmarshalLine: %v", i+1, err)
		}
		if !proto.Equal(got, want) {
			t.Fatalf("line %d reads as %v\nwant %v", i+1, got, want)
		}
		line, err := observe.MarshalLine(want)
		if err != nil {
			t.Fatalf("line %d: MarshalLine: %v", i+1, err)
		}
		if !bytes.Equal(line, lines[i]) {
			t.Fatalf("line %d writes as\n%s\nwant\n%s", i+1, line, lines[i])
		}
		noNewline, err := observe.UnmarshalLine(bytes.TrimSuffix(lines[i], []byte("\n")))
		if err != nil || !proto.Equal(noNewline, want) {
			t.Fatalf("line %d without its newline: %v, %v", i+1, noNewline, err)
		}
	}
}

func TestMarshalLineEscapesWhatAReaderMightSplitOn(t *testing.T) {
	o := fixtureObservation()
	o.Subject.Name = "a\u2028b\u2029c\u0085d\u009be\u202ef\u007fg\"h\\i\nj"
	line, err := observe.MarshalLine(obsRecord(o))
	if err != nil {
		t.Fatal(err)
	}
	want := `"name":"a\u2028b\u2029c\u0085d\u009be\u202ef\u007fg\"h\\i\nj"`
	if !bytes.Contains(line, []byte(want)) {
		t.Fatalf("line %s does not hold %s", line, want)
	}
	for _, raw := range []string{"\u2028", "\u2029", "\u0085", "\u009b", "\u202e", "\u007f"} {
		if bytes.Contains(line, []byte(raw)) {
			t.Errorf("line holds %q raw", raw)
		}
	}
	if bytes.IndexByte(line, '\n') != len(line)-1 {
		t.Fatalf("line holds a newline before its end: %q", line)
	}
	back, err := observe.UnmarshalLine(line)
	if err != nil || !proto.Equal(back, obsRecord(o)) {
		t.Fatalf("escaped line reads back as %v, %v", back, err)
	}
}

type recordCase struct {
	name   string
	edit   func(o *observev1.Observation)
	member string // "" accepts
}

var observationCases = []recordCase{
	{"version absent", func(o *observev1.Observation) { o.SchemaVersion = "" }, "absent"},
	{"version next minor", func(o *observev1.Observation) { o.SchemaVersion = "0.3" }, "minor"},
	{"version major", func(o *observev1.Observation) { o.SchemaVersion = "1.0" }, "major"},
	{"id absent", func(o *observev1.Observation) { o.ObservationId = "" }, "observation_id"},
	{"id 31 digits", func(o *observev1.Observation) { o.ObservationId = fixtureObservationID[:35] }, "observation_id"},
	{"id 33 digits", func(o *observev1.Observation) { o.ObservationId = fixtureObservationID + "0" }, "observation_id"},
	{"id upper", func(o *observev1.Observation) { o.ObservationId = "obs-" + strings.Repeat("A", 32) }, "observation_id"},
	{"id prefix", func(o *observev1.Observation) { o.ObservationId = "obx-" + fixtureObservationID[4:] }, "observation_id"},
	{"id all zeros", func(o *observev1.Observation) { o.ObservationId = "obs-" + strings.Repeat("0", 32) }, "observation_id"},
	{"id of another key", func(o *observev1.Observation) {
		o.ObservationId = observe.ObservationID("someone", "else", "x", fixtureTraceID, fixtureSpanID)
	}, "observation_id"},
	{"no source", func(o *observev1.Observation) { o.Source = nil }, "source.source_id"},
	{"source id absent", func(o *observev1.Observation) { o.Source.SourceId = "" }, "source.source_id"},
	{"source id with a slash", func(o *observev1.Observation) { o.Source.SourceId = "agent/runtime" }, "source.source_id"},
	{"no received_time", func(o *observev1.Observation) { o.ReceivedTime = nil }, "received_time"},
	{"tenant absent", func(o *observev1.Observation) { o.TenantId = "" }, "tenant_id"},
	{"project absent", func(o *observev1.Observation) { o.ProjectId = "" }, "project_id"},
	{"correlation absent", func(o *observev1.Observation) { o.Correlation = nil }, "trace_id"},
	{"trace zero", func(o *observev1.Observation) { o.Correlation.TraceId = strings.Repeat("0", 32) }, "trace_id"},
	{"trace upper", func(o *observev1.Observation) { o.Correlation.TraceId = strings.ToUpper(fixtureTraceID) }, "trace_id"},
	{"span absent", func(o *observev1.Observation) { o.Correlation.SpanId = "" }, "span_id"},
	{"span zero", func(o *observev1.Observation) { o.Correlation.SpanId = strings.Repeat("0", 16) }, "span_id"},
	{"parent absent", func(o *observev1.Observation) { o.Correlation.ParentSpanId = "" }, ""},
	{"parent zero", func(o *observev1.Observation) { o.Correlation.ParentSpanId = strings.Repeat("0", 16) }, "parent_span_id"},
	{"parent a trace id", func(o *observev1.Observation) { o.Correlation.ParentSpanId = fixtureTraceID }, "parent_span_id"},
	{"claimed without a run", func(o *observev1.Observation) { o.Correlation.RunId = "" }, "run_id"},
	{"claimed with a malformed run", func(o *observev1.Observation) { o.Correlation.RunId = "run-1" }, "run_id"},
	{"none with a run", func(o *observev1.Observation) { o.Correlation.Basis = observev1.Basis_BASIS_NONE }, "run_id"},
	{"unspecified with a run", func(o *observev1.Observation) { o.Correlation.Basis = 0 }, "run_id"},
	{"undeclared basis with a run", func(o *observev1.Observation) { o.Correlation.Basis = 99 }, "run_id"},
	{"joined with a run", func(o *observev1.Observation) { o.Correlation.Basis = observev1.Basis_BASIS_JOINED }, ""},
	{"none without a run", func(o *observev1.Observation) {
		o.Correlation.Basis, o.Correlation.RunId = observev1.Basis_BASIS_NONE, ""
	}, ""},
	{"undeclared stage", func(o *observev1.Observation) { o.Stage = 42 }, ""},
}

var reportCases = []struct {
	name   string
	edit   func(r *observev1.ImportReport)
	member string
}{
	{"version absent", func(r *observev1.ImportReport) { r.SchemaVersion = "" }, "absent"},
	{"version next minor", func(r *observev1.ImportReport) { r.SchemaVersion = "0.3" }, "minor"},
	{"tenant absent", func(r *observev1.ImportReport) { r.TenantId = "" }, "tenant_id"},
	{"project absent", func(r *observev1.ImportReport) { r.ProjectId = "" }, "project_id"},
	{"no counts", func(r *observev1.ImportReport) { r.Counts = nil }, ""},
	{"no source", func(r *observev1.ImportReport) { r.Source = nil }, "source.source_id"},
	{"source id absent", func(r *observev1.ImportReport) { r.Source.SourceId = "" }, "source.source_id"},
	{"source id with a slash", func(r *observev1.ImportReport) { r.Source.SourceId = "agent/runtime" }, "source.source_id"},
	{"no received_time", func(r *observev1.ImportReport) { r.ReceivedTime = nil }, "received_time"},
}

// checkBothWays holds the writer and the reader to one rule: a record the
// writer refuses, written by plain protojson, is a line the reader refuses.
func checkBothWays(t *testing.T, name string, r *observev1.Record, member string) {
	t.Helper()
	_, werr := observe.MarshalLine(r)
	raw, err := protojson.Marshal(r)
	if err != nil {
		t.Fatalf("%s: protojson: %v", name, err)
	}
	_, rerr := observe.UnmarshalLine(raw)
	for dir, err := range map[string]error{"MarshalLine": werr, "UnmarshalLine": rerr} {
		switch {
		case member == "" && err != nil:
			t.Errorf("%s: %s refused: %v", name, dir, err)
		case member != "" && (!errors.Is(err, observe.ErrLine) || !strings.Contains(err.Error(), member)):
			t.Errorf("%s: %s = %v, want ErrLine naming %q", name, dir, err, member)
		}
	}
}

func TestTheCodecChecksAnObservation(t *testing.T) {
	for _, c := range observationCases {
		o := fixtureObservation()
		c.edit(o)
		checkBothWays(t, c.name, obsRecord(o), c.member)
	}
}

// Each field of the key changes the id: changed alone it leaves an id the
// codec refuses, changed with the id derived again it reads.
func TestTheObservationIDIsTheIDOfItsKey(t *testing.T) {
	keys := map[string]func(o *observev1.Observation){
		"tenant_id":  func(o *observev1.Observation) { o.TenantId = "tenant-b" },
		"project_id": func(o *observev1.Observation) { o.ProjectId = "project-b" },
		"source_id":  func(o *observev1.Observation) { o.Source.SourceId = "other-runtime" },
		"trace_id":   func(o *observev1.Observation) { o.Correlation.TraceId = "0af7651916cd43dd8448eb211c80319c" },
		"span_id":    func(o *observev1.Observation) { o.Correlation.SpanId = "b7ad6b7169203332" },
	}
	for name, edit := range keys {
		o := fixtureObservation()
		edit(o)
		checkBothWays(t, name+" changed, id kept", obsRecord(o), "observation_id")
		o.ObservationId = observe.ObservationID(o.TenantId, o.ProjectId, o.Source.SourceId,
			o.Correlation.TraceId, o.Correlation.SpanId)
		checkBothWays(t, name+" changed, id derived again", obsRecord(o), "")
	}
}

func TestTheCodecChecksAnImportReport(t *testing.T) {
	for _, c := range reportCases {
		r := fixtureReport()
		c.edit(r)
		checkBothWays(t, c.name, reportRecord(r), c.member)
	}
}

func TestMarshalLineRefuses(t *testing.T) {
	unknown := fixtureObservation()
	unknown.Subject.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	cases := map[string]struct {
		r    *observev1.Record
		want string
	}{
		"nil":                     {nil, "nil record"},
		"no member":               {&observev1.Record{}, "no member"},
		"a nil member":            {&observev1.Record{Record: &observev1.Record_Observation{}}, "no member"},
		"a nil report":            {&observev1.Record{Record: &observev1.Record_ImportReport{}}, "no member"},
		"an unknown nested field": {obsRecord(unknown), "cannot name"},
		"invalid UTF-8":           {obsRecord(withName("\xff")), "UTF-8"},
	}
	for name, c := range cases {
		line, err := observe.MarshalLine(c.r)
		if !errors.Is(err, observe.ErrLine) || !strings.Contains(err.Error(), c.want) || line != nil {
			t.Errorf("%s: MarshalLine = %q, %v, want ErrLine saying %q", name, line, err, c.want)
		}
	}
}

func withName(name string) *observev1.Observation {
	o := fixtureObservation()
	o.Subject.Name = name
	return o
}
