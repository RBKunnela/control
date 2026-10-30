package egresslog

import (
	"strconv"
	"strings"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// eventTime reads a line's time under the descriptor's format. A time that is
// unset, unparseable or outside what a record can carry is no time; a time
// after the receive time is kept as read. Neither format reads the dash
// or the empty text of an unset value.
func eventTime(v value, format observev1.TimeFormat) (*timestamppb.Timestamp, bool) {
	var ts *timestamppb.Timestamp
	switch format {
	case observev1.TimeFormat_TIME_FORMAT_RFC3339:
		t, err := time.Parse(time.RFC3339Nano, v.text)
		if err != nil {
			return nil, false
		}
		ts = timestamppb.New(t)
	case observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS:
		ts = epoch(v, 9)
	case observev1.TimeFormat_TIME_FORMAT_UNIX_MILLISECONDS:
		ts = epoch(v, 0)
	}
	if ts == nil || ts.CheckValid() != nil {
		return nil, false
	}
	return ts, true
}

// epoch reads seconds with at most fraction fractional digits, or
// milliseconds when fraction is 0, written as a JSON number or a decimal
// string with no sign or exponent.
func epoch(v value, fraction int) *timestamppb.Timestamp {
	whole, frac, dotted := strings.Cut(v.text, ".")
	if !digits(whole) || (dotted && (!digits(frac) || len(frac) > fraction)) {
		return nil
	}
	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return nil
	}
	if fraction == 0 {
		return &timestamppb.Timestamp{Seconds: n / 1000, Nanos: int32(n%1000) * 1e6}
	}
	nanos, err := strconv.ParseInt(frac+strings.Repeat("0", 9-len(frac)), 10, 32)
	if err != nil {
		return nil
	}
	return &timestamppb.Timestamp{Seconds: n, Nanos: int32(nanos)}
}
