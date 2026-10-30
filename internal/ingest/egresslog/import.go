package egresslog

import (
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Batch is what one import yields: the observations in input order and the
// report that accounts for every line read.
type Batch struct {
	Observations []*observev1.Observation
	Report       *observev1.ImportReport
}

// Import reads r's complete lines as JSON objects and maps each to one
// connection observation under the descriptor's mapping. It returns an error
// only when r fails or the descriptor or receive time cannot be served; bad
// input is counted in the report, never an error. Every complete line is read
// and lands in exactly one of observed and refused, and each refusal is
// counted under its reason.
func Import(r io.Reader, desc *observev1.SourceDescriptor, descriptorSHA256 string, received time.Time) (Batch, error) {
	if r == nil {
		return Batch{}, errors.New("egresslog: no input")
	}
	if err := checkDescriptor(desc, descriptorSHA256); err != nil {
		return Batch{}, err
	}
	rt := timestamppb.New(received)
	if received.IsZero() || rt.CheckValid() != nil {
		return Batch{}, fmt.Errorf("%w: %v", ErrReceived, received)
	}
	mapped, err := mapping(desc.GetEgressAccessLog().GetFields())
	if err != nil {
		return Batch{}, err
	}
	im := &importer{desc: desc, sha: descriptorSHA256, received: rt, mapped: mapped, counts: &observev1.ImportCounts{}}
	in := newLines(r)
	for {
		line, tooLong, ok, err := in.next()
		if err != nil {
			return Batch{}, fmt.Errorf("egresslog: reading input: %w", err)
		}
		if !ok {
			break
		}
		im.counts.Read++
		if tooLong {
			im.refuse(reasonTooLong)
			continue
		}
		im.line(line)
	}
	return Batch{Observations: im.observations, Report: im.report(in)}, nil
}

// importer accumulates one import. earliest and latest span the event times
// of the connections observed. doubt is every run once a line is refused,
// since a refused line names no run.
type importer struct {
	desc             *observev1.SourceDescriptor
	sha              string
	received         *timestamppb.Timestamp
	mapped           map[string]field
	counts           *observev1.ImportCounts
	observations     []*observev1.Observation
	earliest, latest *timestamppb.Timestamp
	doubt            observe.Doubt
}

func (im *importer) refuse(reason string) {
	if im.counts.RefusedBy == nil {
		im.counts.RefusedBy = map[string]uint64{}
	}
	im.counts.RefusedBy[reason]++
	im.counts.Refused++
	im.doubt.Claim("")
}

func (im *importer) line(line []byte) {
	vals, reason := decodeLine(line, im.mapped)
	if reason != "" {
		im.refuse(reason)
		return
	}
	at, ok := eventTime(vals[fieldTime], im.desc.GetEgressAccessLog().GetFields().GetTimeFormat())
	if !ok {
		im.refuse(reasonTime)
		return
	}
	fields := im.desc.GetEgressAccessLog().GetFields()
	host, authorityPort, ok := destination(vals[fieldDestination], fields.GetDestinationForm())
	if !ok {
		im.refuse(reasonDestination)
		return
	}
	port, ok := connectionPort(vals[fieldPort], authorityPort)
	if !ok {
		im.refuse(reasonPort)
		return
	}
	c := im.connection(vals)
	c.Port = port
	o := &observev1.Observation{
		SchemaVersion: observe.SchemaVersion03,
		TenantId:      im.desc.GetTenantId(),
		ProjectId:     im.desc.GetProjectId(),
		Source:        im.source(),
		EventTime:     at,
		ReceivedTime:  copyTime(im.received),
		Stage:         observev1.Stage_STAGE_INDIRECT,
		Subject:       &observev1.Subject{Kind: observev1.SubjectKind_SUBJECT_KIND_CONNECTION, Name: host},
		Correlation:   &observev1.Correlation{Basis: observev1.Basis_BASIS_NONE},
		Connection:    c,
	}
	o.ObservationId = observe.ConnectionID(o)
	im.observations = append(im.observations, o)
	im.counts.Observed++
	im.heard(at)
}

// connection reads the optional values. A malformed one is dropped and
// counted, and the line kept; an unset one is nothing to drop.
func (im *importer) connection(vals values) *observev1.Connection {
	c := &observev1.Connection{CallerBasis: observev1.CallerBasis_CALLER_BASIS_NONE}
	drop := func(v value, keep func(value) bool) {
		if !v.unset() && !keep(v) {
			im.counts.StringsDropped++
		}
	}
	drop(vals[fieldMethod], func(v value) bool {
		if v.kind == kindString && observe.ConnectionMethod(v.text) {
			c.Method = v.text
			return true
		}
		return false
	})
	drop(vals[fieldStatus], func(v value) bool {
		n, ok := httpStatus(v)
		c.HttpStatus = n
		return ok
	})
	drop(vals[fieldBytesSent], func(v value) bool {
		n, ok := v.unsigned()
		if ok {
			c.BytesSent = n
		}
		return ok
	})
	drop(vals[fieldBytesReceived], func(v value) bool {
		n, ok := v.unsigned()
		if ok {
			c.BytesReceived = n
		}
		return ok
	})
	basis := im.desc.GetEgressAccessLog().GetCallerBasis()
	if v := vals[fieldCaller]; !v.unset() {
		switch who, ok := caller(v, basis); {
		case ok:
			c.Caller, c.CallerBasis = who, basis
		case basis == observev1.CallerBasis_CALLER_BASIS_ADDRESS:
			im.counts.CallersDropped++
		default:
			im.counts.StringsDropped++
		}
	}
	return c
}

// httpStatus reads a status the connection codec takes, or reports none.
func httpStatus(v value) (uint32, bool) {
	n, ok := v.unsigned()
	if !ok || n > math.MaxUint32 || !observe.ConnectionStatus(n) {
		return 0, false
	}
	return uint32(n), true
}

func (im *importer) source() *observev1.SourceRef {
	return &observev1.SourceRef{
		SourceId:         im.desc.GetSourceId(),
		DescriptorSha256: im.sha,
		Trust:            im.desc.GetTrust(),
		Kind:             observe.KindEgressAccessLog,
	}
}

func (im *importer) heard(at *timestamppb.Timestamp) {
	if im.earliest == nil || before(at, im.earliest) {
		im.earliest = at
	}
	if im.latest == nil || before(im.latest, at) {
		im.latest = at
	}
}

func before(a, b *timestamppb.Timestamp) bool {
	return a.GetSeconds() < b.GetSeconds() || (a.GetSeconds() == b.GetSeconds() && a.GetNanos() < b.GetNanos())
}

// copyTime gives each record its own copy, so a caller that changes one
// record's time changes no other.
func copyTime(t *timestamppb.Timestamp) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return &timestamppb.Timestamp{Seconds: t.GetSeconds(), Nanos: t.GetNanos()}
}

func (im *importer) report(in *lines) *observev1.ImportReport {
	r := &observev1.ImportReport{
		TenantId:             im.desc.GetTenantId(),
		ProjectId:            im.desc.GetProjectId(),
		Source:               im.source(),
		ReceivedTime:         copyTime(im.received),
		InputFirstLineSha256: in.firstLineSHA256(),
		InputBytes:           in.consumed,
		Counts:               im.counts,
		EarliestEventTime:    copyTime(im.earliest),
		LatestEventTime:      copyTime(im.latest),
	}
	im.doubt.Fill(r)
	return r
}
