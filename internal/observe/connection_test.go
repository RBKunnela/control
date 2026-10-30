package observe_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	egressDescriptorSHA256 = "96ee7d9625bf44c0df043605e7dd0de0635d607590a6ad025a2d56120d848b1d"
	connectionID           = "obs-386c423085fb24ff6b2f087b626a9c03"
)

func egressSource() *observev1.SourceRef {
	return &observev1.SourceRef{
		SourceId:         "egress-proxy",
		DescriptorSha256: egressDescriptorSHA256,
		Trust:            observev1.Trust_TRUST_INDEPENDENT,
		Kind:             observe.KindEgressAccessLog,
	}
}

// fixtureConnection is the first line of connection.jsonl, written out by
// hand.
func fixtureConnection() *observev1.Observation {
	return &observev1.Observation{
		SchemaVersion: "0.3",
		ObservationId: connectionID,
		TenantId:      "tenant-a",
		ProjectId:     "project-a",
		Source:        egressSource(),
		EventTime:     ts("2026-10-04T10:00:00.250Z"),
		ReceivedTime:  ts("2026-10-04T10:05:00Z"),
		Stage:         observev1.Stage_STAGE_INDIRECT,
		Subject:       &observev1.Subject{Kind: observev1.SubjectKind_SUBJECT_KIND_CONNECTION, Name: "api.example.com"},
		Correlation:   &observev1.Correlation{Basis: observev1.Basis_BASIS_NONE},
		Connection: &observev1.Connection{
			Port:          443,
			Method:        "CONNECT",
			HttpStatus:    200,
			BytesSent:     1834,
			BytesReceived: 52011,
			Caller:        "10.0.0.7",
			CallerBasis:   observev1.CallerBasis_CALLER_BASIS_ADDRESS,
		},
	}
}

// fixtureRefusals is the second line of connection.jsonl, written out by hand.
func fixtureRefusals() *observev1.ImportReport {
	return &observev1.ImportReport{
		SchemaVersion:        "0.3",
		TenantId:             "tenant-a",
		ProjectId:            "project-a",
		Source:               egressSource(),
		ReceivedTime:         ts("2026-10-04T10:05:00Z"),
		InputFirstLineSha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		InputBytes:           2048,
		Counts: &observev1.ImportCounts{
			Read:      4,
			Observed:  1,
			Duplicate: 1,
			Refused:   2,
			RefusedBy: map[string]uint64{"destination": 1, "time": 1},
		},
		EarliestEventTime: ts("2026-10-04T10:00:00.250Z"),
		LatestEventTime:   ts("2026-10-04T10:00:00.250Z"),
		EveryRunDoubted:   true,
	}
}

func connectionLines(t *testing.T) [][]byte {
	t.Helper()
	lines := bytes.SplitAfter(readTestdata(t, "connection.jsonl"), []byte("\n"))
	if len(lines) != 3 || len(lines[2]) != 0 {
		t.Fatalf("connection.jsonl holds %d parts, want two lines", len(lines))
	}
	return lines[:2]
}

func TestTheConnectionLinesRoundTrip(t *testing.T) {
	lines := connectionLines(t)
	for i, want := range []*observev1.Record{obsRecord(fixtureConnection()), reportRecord(fixtureRefusals())} {
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
		if err := observe.CheckLineForm(line); err != nil {
			t.Fatalf("line %d is not in the writer's form: %v", i+1, err)
		}
	}
}

// The goldens of the earlier schemas are not touched by the later ones.
func TestTheEarlierGoldensAreUnchanged(t *testing.T) {
	for name, want := range map[string]string{
		"descriptor.json": fixtureDescriptorSHA256,
		"records.jsonl":   "8ce2d72b55bf63a56c97e262d7d480a8f3c04781de32318b824ba7e1823a4a46",
	} {
		sum := sha256.Sum256(readTestdata(t, name))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("SHA-256 of %s = %s, want %s", name, got, want)
		}
	}
	if got := observe.DescriptorSHA256(readTestdata(t, "descriptor-egress.json")); got != egressDescriptorSHA256 {
		t.Errorf("SHA-256 of descriptor-egress.json = %s, want %s", got, egressDescriptorSHA256)
	}
}

type connectionKey struct {
	tenant, project, source string
	seconds                 int64
	nanos                   int32
	host                    string
	port                    uint32
	method                  string
	status                  uint32
	sent, received          uint64
	caller                  string
}

func (k connectionKey) observation() *observev1.Observation {
	return &observev1.Observation{
		TenantId:  k.tenant,
		ProjectId: k.project,
		Source:    &observev1.SourceRef{SourceId: k.source},
		EventTime: &timestamppb.Timestamp{Seconds: k.seconds, Nanos: k.nanos},
		Subject:   &observev1.Subject{Name: k.host},
		Connection: &observev1.Connection{
			Port: k.port, Method: k.method, HttpStatus: k.status,
			BytesSent: k.sent, BytesReceived: k.received, Caller: k.caller,
		},
	}
}

// The expected ids were computed outside Go: SHA-256 over the domain
// "observation-id:connection:1" and the twelve fields, numbers in decimal,
// each preceded by its length as eight big-endian bytes, cut to 16 bytes.
func TestConnectionIDIsPinned(t *testing.T) {
	cases := []struct {
		key  connectionKey
		want string
	}{
		{connectionKey{"tenant-a", "project-a", "egress-proxy", 1791108000, 250000000, "api.example.com", 443, "CONNECT", 200, 1834, 52011, "10.0.0.7"}, connectionID},
		{connectionKey{}, "obs-b9973de2a56e936b8d4562b2e69462cd"},
		{connectionKey{"t", "p", "s", -1, 999999999, "h", 65535, "GET", 599, math.MaxUint64, 0, "c"}, "obs-d8441a7cfedbd1f4c5a7ff06e7042255"},
		{connectionKey{tenant: "ab", project: "c", source: "s", host: "h"}, "obs-30dfd7c3809d52828449371cf63f8d2c"},
		{connectionKey{tenant: "a", project: "bc", source: "s", host: "h"}, "obs-a9e34a201ca94135fcf6db0d2f63672f"},
		{connectionKey{tenant: "t", project: "p", source: "s", seconds: 12, nanos: 3, host: "h"}, "obs-35ba47fe059c6ba4af5ffb159799ca51"},
		{connectionKey{tenant: "t", project: "p", source: "s", seconds: 1, nanos: 23, host: "h"}, "obs-803da644924ee691494055f8574df92a"},
	}
	for _, c := range cases {
		if got := observe.ConnectionID(c.key.observation()); got != c.want {
			t.Errorf("ConnectionID(%+v) = %s, want %s", c.key, got, c.want)
		}
	}
	if got := observe.ConnectionID(fixtureConnection()); got != connectionID {
		t.Errorf("ConnectionID(fixture) = %s, want %s", got, connectionID)
	}
}

// Every field of the key moves the id, and so does nothing else the codec
// lets vary.
func TestConnectionIDSeesEveryKeyField(t *testing.T) {
	edits := map[string]func(o *observev1.Observation){
		"tenant_id":                 func(o *observev1.Observation) { o.TenantId = "tenant-b" },
		"project_id":                func(o *observev1.Observation) { o.ProjectId = "project-b" },
		"source.source_id":          func(o *observev1.Observation) { o.Source.SourceId = "other-proxy" },
		"event_time.seconds":        func(o *observev1.Observation) { o.EventTime.Seconds++ },
		"event_time.nanos":          func(o *observev1.Observation) { o.EventTime.Nanos++ },
		"subject.name":              func(o *observev1.Observation) { o.Subject.Name = "api.example.org" },
		"connection.port":           func(o *observev1.Observation) { o.Connection.Port = 80 },
		"connection.method":         func(o *observev1.Observation) { o.Connection.Method = "GET" },
		"connection.http_status":    func(o *observev1.Observation) { o.Connection.HttpStatus = 403 },
		"connection.bytes_sent":     func(o *observev1.Observation) { o.Connection.BytesSent++ },
		"connection.bytes_received": func(o *observev1.Observation) { o.Connection.BytesReceived++ },
		"connection.caller":         func(o *observev1.Observation) { o.Connection.Caller = "10.0.0.8" },
	}
	for name, edit := range edits {
		o := fixtureConnection()
		edit(o)
		if observe.ConnectionID(o) == connectionID {
			t.Errorf("changing %s leaves the id unchanged", name)
		}
		checkBothWays(t, name+" changed, id kept", obsRecord(o), "observation_id")
		o.ObservationId = observe.ConnectionID(o)
		checkBothWays(t, name+" changed, id derived again", obsRecord(o), "")
	}
	received := fixtureConnection()
	received.ReceivedTime = ts("2027-01-01T00:00:00Z")
	received.Source.DescriptorSha256 = strings.Repeat("f", 64)
	if observe.ConnectionID(received) != connectionID {
		t.Error("the receipt or the descriptor digest moves a connection's id")
	}
}

func TestTheCodecChecksAConnection(t *testing.T) {
	for _, c := range []recordCase{
		{"the fixture", func(*observev1.Observation) {}, ""},
		{"a trace id", func(o *observev1.Observation) { o.Correlation.TraceId = fixtureTraceID }, "correlation: a connection names no trace"},
		{"a span id", func(o *observev1.Observation) { o.Correlation.SpanId = fixtureSpanID }, "correlation: a connection names no trace"},
		{"a parent span id", func(o *observev1.Observation) { o.Correlation.ParentSpanId = fixtureParentSpanID }, "correlation: a connection names no trace"},
		{"a run id", func(o *observev1.Observation) { o.Correlation.RunId = fixtureRunID }, "correlation: a connection names no trace"},
		{"a run claimed", func(o *observev1.Observation) {
			o.Correlation.Basis, o.Correlation.RunId = observev1.Basis_BASIS_CLAIMED, fixtureRunID
		}, "correlation: a connection names no trace"},
		{"basis claimed", func(o *observev1.Observation) { o.Correlation.Basis = observev1.Basis_BASIS_CLAIMED }, "correlation.basis"},
		{"basis joined", func(o *observev1.Observation) { o.Correlation.Basis = observev1.Basis_BASIS_JOINED }, "correlation.basis"},
		{"basis unspecified", func(o *observev1.Observation) { o.Correlation.Basis = 0 }, "correlation.basis"},
		{"no correlation", func(o *observev1.Observation) { o.Correlation = nil }, "correlation.basis"},
		{"stage completed", func(o *observev1.Observation) { o.Stage = observev1.Stage_STAGE_COMPLETED }, "stage"},
		{"stage unspecified", func(o *observev1.Observation) { o.Stage = 0 }, "stage"},
		{"no event time", func(o *observev1.Observation) { o.EventTime = nil }, "event_time"},
		{"no connection", func(o *observev1.Observation) { o.Connection = nil }, "connection: required"},
		{"no connection at 0.1", func(o *observev1.Observation) {
			o.SchemaVersion, o.Connection = "0.1", nil
		}, `source.kind: not a member of schema "0.1"`},
		{"no source kind", func(o *observev1.Observation) { o.Source.Kind = "" }, `source.kind: a subject of kind SUBJECT_KIND_CONNECTION from a source of kind "otel-genai-traces"`},
		{"the OpenTelemetry kind spelled", func(o *observev1.Observation) { o.Source.Kind = observe.KindOTelGenAI }, `source.kind: "otel-genai-traces" is spelled empty`},
		{"a kind this build does not read", func(o *observev1.Observation) { o.Source.Kind = "process-events" }, "source.kind: \"process-events\" is not a kind"},
		{"the id of a span", func(o *observev1.Observation) {
			o.ObservationId = observe.ObservationID("tenant-a", "project-a", "egress-proxy", "", "")
		}, "observation_id"},
		{"an operation", func(o *observev1.Observation) { o.Subject.Operation = "execute_tool" }, "subject.operation: set on a connection"},
		{"a provider", func(o *observev1.Observation) { o.Subject.Provider = "p" }, "subject.provider: set on a connection"},
		{"a server address", func(o *observev1.Observation) { o.Subject.ServerAddress = "x.example" }, "subject.server_address: set on a connection"},
		{"an outcome", func(o *observev1.Observation) { o.Outcome = &observev1.Outcome{} }, "outcome: set on a connection"},
		{"a convention", func(o *observev1.Observation) { o.Source.Convention = &observev1.Convention{} }, "source.convention: set on a connection"},
		{"content dropped", func(o *observev1.Observation) { o.ContentAttributesDropped = 1 }, "content_attributes_dropped: set on a connection"},
		{"no caller, basis address", func(o *observev1.Observation) { o.Connection.Caller = "" }, "connection.caller_basis"},
		{"no caller, basis authenticated", func(o *observev1.Observation) {
			o.Connection.Caller, o.Connection.CallerBasis = "", observev1.CallerBasis_CALLER_BASIS_AUTHENTICATED
		}, "connection.caller_basis"},
		{"no caller, basis none", func(o *observev1.Observation) {
			o.Connection.Caller, o.Connection.CallerBasis = "", observev1.CallerBasis_CALLER_BASIS_NONE
		}, ""},
		{"no caller, basis unspecified", func(o *observev1.Observation) {
			o.Connection.Caller, o.Connection.CallerBasis = "", 0
		}, ""},
		{"nothing but the host", func(o *observev1.Observation) { o.Connection = &observev1.Connection{} }, ""},
		{"a method no connection keeps", func(o *observev1.Observation) { o.Connection.Method = "EVIL" }, `connection.method: "EVIL"`},
		{"a method in lower case", func(o *observev1.Observation) { o.Connection.Method = "get" }, "connection.method"},
		{"the last method of the list", func(o *observev1.Observation) { o.Connection.Method = "TRACE" }, ""},
		{"status 99", func(o *observev1.Observation) { o.Connection.HttpStatus = 99 }, "connection.http_status: 99"},
		{"status 100", func(o *observev1.Observation) { o.Connection.HttpStatus = 100 }, ""},
		{"status 599", func(o *observev1.Observation) { o.Connection.HttpStatus = 599 }, ""},
		{"status 600", func(o *observev1.Observation) { o.Connection.HttpStatus = 600 }, "connection.http_status: 600"},
		{"status 999", func(o *observev1.Observation) { o.Connection.HttpStatus = 999 }, "connection.http_status: 999"},
		{"a caller with a bidi override", func(o *observev1.Observation) {
			o.Connection.Caller, o.Connection.CallerBasis = "alice\u202e", observev1.CallerBasis_CALLER_BASIS_AUTHENTICATED
		}, "connection.caller: not text"},
		{"a caller of whitespace", func(o *observev1.Observation) {
			o.Connection.Caller, o.Connection.CallerBasis = " ", observev1.CallerBasis_CALLER_BASIS_NONE
		}, "connection.caller: not text"},
		{"a caller at the text bound", func(o *observev1.Observation) {
			o.Connection.Caller, o.Connection.CallerBasis = strings.Repeat("a", observe.MaxTextBytes), observev1.CallerBasis_CALLER_BASIS_AUTHENTICATED
		}, ""},
		{"a caller past the text bound", func(o *observev1.Observation) {
			o.Connection.Caller, o.Connection.CallerBasis = strings.Repeat("a", observe.MaxTextBytes+1), observev1.CallerBasis_CALLER_BASIS_AUTHENTICATED
		}, "connection.caller: not text"},
		{"a path as an address", func(o *observev1.Observation) { o.Connection.Caller = "path?token=x" }, `connection.caller: "path?token=x" is not an address`},
		{"a name as an address", func(o *observev1.Observation) { o.Connection.Caller = "workload.example" }, "connection.caller"},
		{"an address with a port", func(o *observev1.Observation) { o.Connection.Caller = "[2001:db8::7]:50123" }, ""},
		{"a path from an authenticated caller", func(o *observev1.Observation) {
			o.Connection.Caller, o.Connection.CallerBasis = "path?token=x", observev1.CallerBasis_CALLER_BASIS_AUTHENTICATED
		}, ""},
	} {
		o := fixtureConnection()
		c.edit(o)
		if c.member == "" || !strings.Contains(c.member, "observation_id") {
			o.ObservationId = observe.ConnectionID(o)
		}
		checkBothWays(t, c.name, obsRecord(o), c.member)
	}
}

func TestTheCodecChecksAConnectionsHost(t *testing.T) {
	for host, member := range map[string]string{
		"api.example.com":              "",
		"xn--bcher-kva.example":        "",
		"192.0.2.10":                   "",
		"2001:db8::1":                  "",
		strings.Repeat("a", 253):       "",
		strings.Repeat("a", 254):       "subject.name: 254 bytes, limit 253",
		"":                             "subject.name: required",
		"api.example.com/v1":           "subject.name",
		"https://api.example.com":      "subject.name",
		"api.example.com:443":          "subject.name",
		"user@api.example.com":         "subject.name",
		"Api.Example.com":              "subject.name",
		"api.example.com.":             "subject.name",
		"api..example.com":             "subject.name",
		"api.example.com?q=1":          "subject.name",
		"api example.com":              "subject.name",
		"bücher.example":               "subject.name",
		"[2001:db8::1]":                "subject.name",
		"api.example.com#x":            "subject.name",
		"api.example.com\n":            "subject.name",
		strings.Repeat("a", 252) + "/": "subject.name",
	} {
		o := fixtureConnection()
		o.Subject.Name = host
		o.ObservationId = observe.ConnectionID(o)
		checkBothWays(t, "host "+host, obsRecord(o), member)
	}
}

// A connection member is the connection subject's alone.
func TestAConnectionOnlyOnAConnection(t *testing.T) {
	for _, kind := range []observev1.SubjectKind{
		observev1.SubjectKind_SUBJECT_KIND_TOOL, observev1.SubjectKind_SUBJECT_KIND_MODEL,
		observev1.SubjectKind_SUBJECT_KIND_AGENT, 0, 99,
	} {
		o := fixtureObservation()
		o.SchemaVersion = "0.3"
		o.Subject.Kind = kind
		o.Connection = &observev1.Connection{Port: 443}
		checkBothWays(t, "a connection on "+kind.String(), obsRecord(o), "connection: set on a subject of kind")
	}
	tool := fixtureConnection()
	tool.Subject.Kind = observev1.SubjectKind_SUBJECT_KIND_TOOL
	checkBothWays(t, "a connection's line as a tool", obsRecord(tool), `source.kind: a subject of kind SUBJECT_KIND_TOOL from a source of kind "egress-access-log"`)
}

// TestARecordIsSchema03ExactlyWhenItCarriesAMemberOf03, in both directions
// and for both records.
func TestARecordIsSchema03ExactlyWhenItCarriesAMemberOf03(t *testing.T) {
	conn := func(version string) *observev1.Record {
		o := fixtureConnection()
		o.SchemaVersion = version
		return obsRecord(o)
	}
	tool := func(version string) *observev1.Record {
		o := fixtureObservation()
		o.SchemaVersion = version
		return obsRecord(o)
	}
	// A report with no source kind, so that refused_by alone decides.
	report := func(version string, every bool, by map[string]uint64) *observev1.Record {
		r := fixtureRefusals()
		r.SchemaVersion, r.EveryRunDoubted, r.Counts.RefusedBy, r.Source.Kind = version, every, by, ""
		return reportRecord(r)
	}
	kind := func(version string) *observev1.Record {
		r := fixtureRefusals()
		r.SchemaVersion, r.Counts.Refused, r.Counts.RefusedBy = version, 0, nil
		return reportRecord(r)
	}
	callers := func(version string) *observev1.Record {
		r := fixtureRefusals()
		r.SchemaVersion, r.Source.Kind, r.Counts.CallersDropped = version, "", 1
		r.Counts.Refused, r.Counts.RefusedBy = 0, nil
		return reportRecord(r)
	}
	by := map[string]uint64{"destination": 1, "time": 1}
	for name, c := range map[string]struct {
		r      *observev1.Record
		member string
	}{
		"a connection at 0.3":               {conn("0.3"), ""},
		"a connection at 0.2":               {conn("0.2"), `connection: not a member of schema "0.2"`},
		"a connection at 0.1":               {conn("0.1"), `connection: not a member of schema "0.1"`},
		"a connection at 0.4":               {conn("0.4"), "minor"},
		"a tool at 0.3":                     {tool("0.3"), `schema_version: "0.3" on a record with no member of "0.3"`},
		"refusals by reason at 0.3":         {report("0.3", true, by), ""},
		"refusals by reason, no doubt, 0.3": {report("0.3", false, by), ""},
		"refusals by reason at 0.2":         {report("0.2", true, by), `counts.refused_by: not a member of schema "0.2"`},
		"refusals by reason at 0.1":         {report("0.1", false, by), `counts.refused_by: not a member of schema "0.1"`},
		"a doubt and no reasons at 0.3":     {report("0.3", true, nil), `schema_version: "0.3" on a record with no member of "0.3"`},
		"a doubt and no reasons at 0.2":     {report("0.2", true, nil), ""},
		"neither at 0.3":                    {report("0.3", false, nil), `schema_version: "0.3" on a record with no member of "0.3"`},
		"an empty map of reasons at 0.3":    {report("0.3", false, map[string]uint64{}), `schema_version: "0.3" on a record with no member of "0.3"`},
		"a source kind alone at 0.3":        {kind("0.3"), ""},
		"a source kind alone at 0.2":        {kind("0.2"), `source.kind: not a member of schema "0.2"`},
		"a source kind alone at 0.1":        {kind("0.1"), `source.kind: not a member of schema "0.1"`},
		"callers dropped at 0.3":            {callers("0.3"), ""},
		"callers dropped at 0.2":            {callers("0.2"), `counts.callers_dropped: not a member of schema "0.2"`},
	} {
		checkBothWays(t, name, c.r, c.member)
	}
}

func TestRefusalsByReasonSumToTheRefused(t *testing.T) {
	for name, c := range map[string]struct {
		refused uint64
		by      map[string]uint64
		member  string
	}{
		"the sum":        {2, map[string]uint64{"destination": 1, "time": 1}, ""},
		"one reason":     {5, map[string]uint64{"line_too_long": 5}, ""},
		"short of it":    {3, map[string]uint64{"destination": 1, "time": 1}, "counts.refused_by: the reasons do not sum"},
		"past it":        {1, map[string]uint64{"destination": 1, "time": 1}, "counts.refused_by: the reasons do not sum"},
		"a reason of 0":  {1, map[string]uint64{"destination": 1, "time": 0}, "counts no line"},
		"an overflow":    {1, map[string]uint64{"a": math.MaxUint64, "b": 2}, "counts.refused_by: the reasons overflow"},
		"at the maximum": {math.MaxUint64, map[string]uint64{"a": math.MaxUint64 - 1, "b": 1}, ""},
	} {
		r := fixtureRefusals()
		r.Counts.Refused, r.Counts.RefusedBy = c.refused, c.by
		checkBothWays(t, name, reportRecord(r), c.member)
	}
}

func TestFillWritesTheSchemaOfRefusalsByReason(t *testing.T) {
	for _, c := range []struct {
		every bool
		by    map[string]uint64
		want  string
	}{
		{false, map[string]uint64{"time": 1}, "0.3"},
		{true, map[string]uint64{"time": 1}, "0.3"},
		{true, nil, "0.2"},
		{false, nil, "0.1"},
	} {
		var d observe.Doubt
		if c.every {
			d.Claim("")
		}
		r := &observev1.ImportReport{SchemaVersion: "9.9", Counts: &observev1.ImportCounts{Refused: 1, RefusedBy: c.by}}
		d.Fill(r)
		if r.GetSchemaVersion() != c.want {
			t.Errorf("every %v, reasons %v: Fill wrote %q, want %q", c.every, c.by, r.GetSchemaVersion(), c.want)
		}
	}
}

func TestCallerBasisOf(t *testing.T) {
	cases := map[observev1.CallerBasis]observev1.CallerBasis{
		0:  observev1.CallerBasis_CALLER_BASIS_NONE,
		1:  observev1.CallerBasis_CALLER_BASIS_NONE,
		2:  observev1.CallerBasis_CALLER_BASIS_ADDRESS,
		3:  observev1.CallerBasis_CALLER_BASIS_AUTHENTICATED,
		4:  observev1.CallerBasis_CALLER_BASIS_NONE,
		-1: observev1.CallerBasis_CALLER_BASIS_NONE,
	}
	for in, want := range cases {
		if got := observe.CallerBasisOf(in); got != want {
			t.Errorf("CallerBasisOf(%d) = %v, want %v", in, got, want)
		}
	}
}
