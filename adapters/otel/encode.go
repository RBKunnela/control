package otel

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/evidence"
)

// The request is ExportLogsServiceRequest in the protobuf JSON mapping, spelled
// out here field by field so the exporter needs no OTLP module. The golden in
// testdata/otlp, produced from the protocol's own types, pins the spelling:
// lowerCamel member names, an enum by its name, a 64-bit integer as a string,
// and an absent field left out rather than written as its zero.
type exportLogsServiceRequest struct {
	ResourceLogs []resourceLogs `json:"resourceLogs"`
}

type resourceLogs struct {
	Resource  resource    `json:"resource"`
	ScopeLogs []scopeLogs `json:"scopeLogs"`
}

type resource struct {
	Attributes []keyValue `json:"attributes"`
}

type scopeLogs struct {
	Scope      instrumentationScope `json:"scope"`
	LogRecords []logRecord          `json:"logRecords"`
}

type instrumentationScope struct {
	Name string `json:"name"`
}

type logRecord struct {
	TimeUnixNano   string     `json:"timeUnixNano,omitempty"`
	SeverityNumber string     `json:"severityNumber"`
	SeverityText   string     `json:"severityText"`
	Body           anyValue   `json:"body"`
	Attributes     []keyValue `json:"attributes,omitempty"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

// anyValue is the one member of AnyValue this exporter uses. It is a oneof
// member, which protojson writes even when empty.
type anyValue struct {
	StringValue string `json:"stringValue"`
}

const (
	severityInfo     = "SEVERITY_NUMBER_INFO"
	severityInfoText = "INFO"
)

// encode builds one request over events: one log record per event, its JSONL
// line as the body and its identifiers as attributes under the product's
// namespace, an empty identifier left out.
func encode(events []*controlv1.Event) ([]byte, error) {
	records := make([]logRecord, 0, len(events))
	var line bytes.Buffer
	for _, ev := range events {
		line.Reset()
		if err := evidence.EncodeJSONL(&line, []*controlv1.Event{ev}); err != nil {
			return nil, err
		}
		rec := logRecord{
			SeverityNumber: severityInfo,
			SeverityText:   severityInfoText,
			Body:           anyValue{StringValue: strings.TrimSuffix(line.String(), "\n")},
			Attributes:     attributes(ev),
		}
		if n, ok := unixNano(ev.GetOccurredAt()); ok {
			rec.TimeUnixNano = strconv.FormatUint(n, 10)
		}
		records = append(records, rec)
	}
	req := exportLogsServiceRequest{ResourceLogs: []resourceLogs{{
		Resource: resource{Attributes: []keyValue{attribute("service.name", brand.Slug)}},
		ScopeLogs: []scopeLogs{{
			Scope:      instrumentationScope{Name: brand.OTelNamespace},
			LogRecords: records,
		}},
	}}}
	return json.Marshal(req)
}

// The largest count of nanoseconds since the epoch in 64 unsigned bits, as
// seconds and the nanos past them.
const (
	maxUnixSeconds = int64(math.MaxUint64 / uint64(time.Second))
	maxUnixNanos   = int32(math.MaxUint64 % uint64(time.Second))
)

// unixNano is ts as OTLP's unsigned count of nanoseconds since the epoch. A
// time before the epoch, or past what 64 unsigned bits count, has none, and
// its record then carries no time, as one with no occurred_at does. The count
// is taken from the seconds and nanos, since time.Time's signed count wraps
// outside 1678 to 2262.
func unixNano(ts *timestamppb.Timestamp) (uint64, bool) {
	if ts == nil || ts.CheckValid() != nil {
		return 0, false
	}
	secs, nanos := ts.GetSeconds(), ts.GetNanos()
	if secs < 0 || secs > maxUnixSeconds || secs == maxUnixSeconds && nanos > maxUnixNanos {
		return 0, false
	}
	return uint64(secs)*uint64(time.Second) + uint64(nanos), true //nolint:gosec // G115: CheckValid holds nanos to 0 through 999999999
}

func attributes(ev *controlv1.Event) []keyValue {
	var attrs []keyValue
	add := func(name, value string) {
		if value != "" {
			attrs = append(attrs, attribute(brand.OTelNamespace+"."+name, value))
		}
	}
	add("event_id", ev.GetEventId())
	add("request_id", ev.GetRequestId())
	add("run_id", ev.GetRunId())
	add("project_id", ev.GetProjectId())
	add("tenant_id", ev.GetTenantId())
	add("kind", ev.GetKind().String())
	add("enforcement_mode", ev.GetEnforcementMode().String())
	return attrs
}

func attribute(key, value string) keyValue {
	return keyValue{Key: key, Value: anyValue{StringValue: value}}
}
