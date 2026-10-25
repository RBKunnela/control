package otel

import (
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// TestARecordsTimeIsItsEventsOwn: a record carries its event's time as OTLP's
// unsigned nanosecond count, past the signed range too, and no time for one
// before the epoch or past what that count holds.
func TestARecordsTimeIsItsEventsOwn(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		at   *timestamppb.Timestamp
		want string
	}{
		{"none", nil, ""},
		{"1600-01-01", timestamppb.New(time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)), ""},
		{"a nanosecond before the epoch", &timestamppb.Timestamp{Seconds: -1, Nanos: 999999999}, ""},
		{"the epoch", &timestamppb.Timestamp{}, "0"},
		{"2026-10-25", timestamppb.New(time.Date(2026, 10, 25, 12, 0, 0, 5, time.UTC)), "1792929600000000005"},
		{"the last signed nanosecond", &timestamppb.Timestamp{Seconds: 9223372036, Nanos: 854775807}, "9223372036854775807"},
		{"the first past it", &timestamppb.Timestamp{Seconds: 9223372036, Nanos: 854775808}, "9223372036854775808"},
		{"2300-01-01", timestamppb.New(time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC)), "10413792000000000000"},
		{"the last unsigned nanosecond", &timestamppb.Timestamp{Seconds: 18446744073, Nanos: 709551615}, "18446744073709551615"},
		{"the first past it", &timestamppb.Timestamp{Seconds: 18446744073, Nanos: 709551616}, ""},
		{"9999-12-31", timestamppb.New(time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)), ""},
	} {
		ev := sample(1)
		ev.OccurredAt = c.at
		raw, err := encode([]*controlv1.Event{ev})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var req struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []map[string]any `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatal(err)
		}
		rec := req.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
		got, present := rec["timeUnixNano"]
		if c.want == "" && present || c.want != "" && got != c.want {
			t.Errorf("%s: timeUnixNano %v (present %v), want %q", c.name, got, present, c.want)
		}
	}
}

// TestAnInvalidTimestampHasNoCount: a timestamp protobuf calls invalid counts
// no nanoseconds, though its seconds and nanos would add up to some.
func TestAnInvalidTimestampHasNoCount(t *testing.T) {
	t.Parallel()
	for _, ts := range []*timestamppb.Timestamp{{Seconds: 1, Nanos: 1000000000}, {Seconds: 1, Nanos: -1}, {Seconds: 253402300800}} {
		if n, ok := unixNano(ts); ok {
			t.Errorf("%v: counts %d", ts, n)
		}
	}
	if n, ok := unixNano(&timestamppb.Timestamp{Seconds: 1, Nanos: 999999999}); !ok || n != 1999999999 {
		t.Errorf("the last valid nanos of second 1: %d, %v", n, ok)
	}
}
