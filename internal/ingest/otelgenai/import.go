package otelgenai

import (
	"errors"
	"fmt"
	"io"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// ErrDescriptor reports a descriptor this importer cannot serve: one
	// observe.ReadDescriptor would refuse, which covers the kind and every
	// pinned version, or a digest that is not lowercase hex SHA-256.
	ErrDescriptor = errors.New("otelgenai: descriptor not served")
	// ErrReceived reports a receive time no record can carry.
	ErrReceived = errors.New("otelgenai: received time refused")
)

// Batch is what one import yields: the observations in input order and the
// report that accounts for every span read.
type Batch struct {
	Observations []*observev1.Observation
	Report       *observev1.ImportReport
}

// Import reads r's complete lines as OTLP/JSON TracesData and maps the spans
// of the descriptor's service to observations. It returns an error only when
// r fails or the descriptor or receive time cannot be served; bad input is
// counted in the report, never an error. Every span read lands in exactly
// one of observed, skipped, other_resource and refused, and a refused line in
// which no span can be counted counts once as read and refused.
func Import(r io.Reader, desc *observev1.SourceDescriptor, descriptorSHA256 string, received time.Time) (Batch, error) {
	if r == nil {
		return Batch{}, errors.New("otelgenai: no input")
	}
	if err := checkDescriptor(desc, descriptorSHA256); err != nil {
		return Batch{}, err
	}
	rt := timestamppb.New(received)
	if received.IsZero() || rt.CheckValid() != nil {
		return Batch{}, fmt.Errorf("%w: %v", ErrReceived, received)
	}
	im := &importer{desc: desc, sha: descriptorSHA256, received: rt, counts: &observev1.ImportCounts{Skipped: map[string]uint64{}}}
	in := newLines(r)
	for {
		line, tooLong, ok, err := in.next()
		if err != nil {
			return Batch{}, fmt.Errorf("otelgenai: reading input: %w", err)
		}
		if !ok {
			break
		}
		if tooLong {
			im.counts.Read++
			im.counts.Refused++
			im.doubt.Claim("")
			continue
		}
		im.line(line)
	}
	return Batch{Observations: im.observations, Report: im.report(in)}, nil
}

func checkDescriptor(desc *observev1.SourceDescriptor, sha string) error {
	if desc == nil {
		return fmt.Errorf("%w: none", ErrDescriptor)
	}
	b, err := protojson.Marshal(desc)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDescriptor, err)
	}
	if _, err := observe.ReadDescriptor(b); err != nil {
		return fmt.Errorf("%w: %w", ErrDescriptor, err)
	}
	if len(sha) != 64 || !lowerHex(sha) {
		return fmt.Errorf("%w: descriptor digest is not 64 lowercase hex digits", ErrDescriptor)
	}
	return nil
}

func lowerHex(s string) bool {
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// importer accumulates one import. earliest and latest span the end times
// of every span of the selected resource that was read and not refused,
// skipped ones included, so a source that sends only operations the importer
// skips is still heard. doubt holds the runs the refused spans claim.
type importer struct {
	desc             *observev1.SourceDescriptor
	sha              string
	received         *timestamppb.Timestamp
	counts           *observev1.ImportCounts
	observations     []*observev1.Observation
	earliest, latest uint64
	doubt            observe.Doubt
}

func (im *importer) source() *observev1.SourceRef {
	return &observev1.SourceRef{
		SourceId:         im.desc.GetSourceId(),
		DescriptorSha256: im.sha,
		Trust:            im.desc.GetTrust(),
		Convention: &observev1.Convention{
			Name:    im.desc.GetConvention().GetName(),
			Version: im.desc.GetConvention().GetVersion(),
		},
	}
}

// receivedTime gives each record its own copy, so a caller that changes one
// record's time changes no other.
func (im *importer) receivedTime() *timestamppb.Timestamp {
	return &timestamppb.Timestamp{Seconds: im.received.GetSeconds(), Nanos: im.received.GetNanos()}
}

func (im *importer) line(line []byte) {
	resources, err := decodeLine(line, im.desc.GetRunAttribute())
	if err != nil {
		n := countSpans(line)
		im.counts.Read += n
		im.counts.Refused += n
		im.doubt.Claim("")
		return
	}
	for _, rs := range resources {
		n := uint64(len(rs.spans))
		im.counts.Read += n
		if !im.selected(rs) {
			im.counts.OtherResource += n
			continue
		}
		var c spanCounts
		c.drop(&rs.attrs, keepNone)
		c.add(rs.scopes)
		im.add(c)
		for _, s := range rs.spans {
			im.span(s)
		}
	}
}

// selected reports a resource whose service.name is exactly the descriptor's.
func (im *importer) selected(rs *resourceSpans) bool {
	v, ok := index(rs.attrs.kept)[attrService]
	return ok && v.kind == kindString && v.str == im.desc.GetSelect().GetServiceName()
}

// span maps one span of the selected resource. The content of its links,
// and of a skipped span, is counted in the report alone; an observation
// counts its own span's attributes and events.
func (im *importer) span(s *span) {
	if !keyable(s) {
		im.counts.Refused++
		im.doubt.Claim(claimedRun(s, im.desc.GetRunAttribute()))
		return
	}
	im.heard(s.end)
	var c spanCounts
	r, operation, skip := rule(index(s.attrs.kept))
	if skip != "" {
		im.counts.Skipped[skip]++
		c.drop(&s.attrs, func(key string) bool { return key == attrOperation })
		c.add(s.events)
	} else {
		var o *observev1.Observation
		o, c = im.observation(s, r, operation)
		im.observations = append(im.observations, o)
		im.counts.Observed++
	}
	c.add(s.links)
	im.add(c)
}

func (im *importer) heard(end uint64) {
	if end == 0 {
		return
	}
	if im.earliest == 0 || end < im.earliest {
		im.earliest = end
	}
	im.latest = max(im.latest, end)
}

func (im *importer) add(c spanCounts) {
	im.counts.ContentAttributesDropped += uint64(c.contentDropped)
	im.counts.ReasoningPartsDropped += c.reasoning
	im.counts.ContentUnparsed += c.unparsed
	im.counts.RunIdsDropped += c.runIDsDropped
	im.counts.StringsDropped += c.stringsDropped
}

func (im *importer) report(in *lines) *observev1.ImportReport {
	r := &observev1.ImportReport{
		SchemaVersion:        observe.SchemaVersion,
		TenantId:             im.desc.GetTenantId(),
		ProjectId:            im.desc.GetProjectId(),
		Source:               im.source(),
		ReceivedTime:         im.receivedTime(),
		InputFirstLineSha256: in.firstLineSHA256(),
		InputBytes:           in.consumed,
		Counts:               im.counts,
		EarliestEventTime:    eventTime(im.earliest),
		LatestEventTime:      eventTime(im.latest),
	}
	im.doubt.Fill(r)
	return r
}
