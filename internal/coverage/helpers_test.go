package coverage_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/coverage"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	traceA = "0af7651916cd43dd8448eb211c80319c"
	traceB = "4bf92f3577b34da6a3ce929d0e0e4736"
	spanA  = "b7ad6b7169203331"
	spanB  = "00f067aa0ba902b7"
	spanC  = "53995c3f42cd8ad8"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func at(offset time.Duration) *timestamppb.Timestamp { return timestamppb.New(now.Add(offset)) }

func rfc(offset time.Duration) string { return now.Add(offset).Format(time.RFC3339Nano) }

func descriptor(id string, trust observev1.Trust) *observev1.SourceDescriptor {
	return &observev1.SourceDescriptor{SchemaVersion: "0.1", SourceId: id, Trust: trust, HeartbeatSeconds: 300,
		TenantId: "t1", ProjectId: "p1"}
}

// report is an import report of source received at received, whose newest
// event was at latest.
func report(source string, received, latest *timestamppb.Timestamp) *observev1.Record {
	return &observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: &observev1.ImportReport{
		SchemaVersion: "0.1", TenantId: "t1", ProjectId: "p1", Source: &observev1.SourceRef{SourceId: source},
		ReceivedTime: received, LatestEventTime: latest,
	}}}
}

// obs is a tool observation of source s1 in tenant t1 and project p1, with
// trust self-reported, seen a minute before now.
type obs struct {
	id, source, name, server string
	kind                     observev1.SubjectKind
	trust                    observev1.Trust
	tenant, project          string
	trace, span, parent      string
	noTime                   bool
}

func (o obs) record() *observev1.Record {
	pick := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}
	kind := o.kind
	if kind == observev1.SubjectKind_SUBJECT_KIND_UNSPECIFIED {
		kind = observev1.SubjectKind_SUBJECT_KIND_TOOL
	}
	trust := o.trust
	if trust == observev1.Trust_TRUST_UNSPECIFIED {
		trust = observev1.Trust_TRUST_SELF_REPORTED
	}
	ob := &observev1.Observation{
		SchemaVersion: "0.1", ObservationId: pick(o.id, "obs-1"),
		TenantId: pick(o.tenant, "t1"), ProjectId: pick(o.project, "p1"),
		Source:       &observev1.SourceRef{SourceId: pick(o.source, "s1"), Trust: trust},
		ReceivedTime: at(-30 * time.Second),
		Subject:      &observev1.Subject{Kind: kind, Name: pick(o.name, "create_issue"), ServerAddress: o.server},
		Correlation:  &observev1.Correlation{TraceId: o.trace, SpanId: o.span, ParentSpanId: o.parent},
	}
	if !o.noTime {
		ob.EventTime = at(-time.Minute)
	}
	return &observev1.Record{Record: &observev1.Record_Observation{Observation: ob}}
}

// liveSource is source s1 at trust, heard ten seconds ago, holding records.
func liveSource(trust observev1.Trust, records ...*observev1.Record) coverage.Source {
	return coverage.Source{
		Descriptor: descriptor("s1", trust),
		Records:    append([]*observev1.Record{report("s1", at(-10*time.Second), at(-10*time.Second))}, records...),
	}
}

// toolInventory declares one mcp_tool path, github/create_issue, seen by
// source s1 as create_issue.
func toolInventory(t testing.TB) *coverage.Inventory {
	t.Helper()
	return mustInventory(t, `{"schema_version":"0.1","paths":[{"id":"gh-create","kind":"mcp_tool",`+
		`"upstream":"github","tool":"create_issue","sources":[{"source_id":"s1","name":"create_issue"}]}]}`)
}

func mustInventory(t testing.TB, doc string) *coverage.Inventory {
	t.Helper()
	inv, err := coverage.ReadInventory([]byte(doc))
	if err != nil {
		t.Fatalf("ReadInventory: %v", err)
	}
	return inv
}

func override(effect controlv1.EffectClass) coverage.Override {
	return coverage.Override{Upstream: "github", Tool: "create_issue", Fingerprint: "fp1", Effect: effect}
}

func plane(name string, mode controlv1.EnforcementMode, failOpenRead bool, o ...coverage.Override) coverage.Plane {
	return coverage.Plane{Name: name, Mode: mode, FailOpenRead: failOpenRead, Overrides: o, Strength: channel.StrengthInline}
}

// listing is p configured with the given upstreams.
func listing(p coverage.Plane, upstreams ...string) coverage.Plane {
	p.Upstreams = upstreams
	return p
}

const (
	modeObserve  = controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	modeShadow   = controlv1.EnforcementMode_ENFORCEMENT_MODE_SHADOW
	modeWarn     = controlv1.EnforcementMode_ENFORCEMENT_MODE_WARN
	modeApprove  = controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE
	modeEnforce  = controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE
	modeLockdown = controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN
	effectRead   = controlv1.EffectClass_EFFECT_CLASS_READ
	effectWrite  = controlv1.EffectClass_EFFECT_CLASS_WRITE
)

// header is the header of an export of a file holding a whole line.
func header(query string) string {
	return fmt.Sprintf(`{"type":"header","format":%q,"version":"1.0","file":"t.trail","source":%q,"query":%s}`,
		brand.OTelNamespace+".evidence-export", sourceDigest, query)
}

const sourceDigest = "57f7f9c13a3299681c3a7122a448585ec8e5984f4c854f0c3dd54b08c997e2a3"

const plainQuery = `{"limit":1000}`

// proposal is one ACTION_PROPOSED event record of a tool call unless kind
// names another action kind, its envelope one the contract accepts. tenant
// and project set both the event's and its envelope's; the event and
// envelope fields set one side. unclassified leaves the effect class out, as
// a plane records a call nothing classifies.
type proposal struct {
	mode, trace, span, tenant, project, tool, upstream, kind string
	protocol                                                 string
	eventTenant, eventProject                                string
	envelopeTenant, envelopeProject                          string
	occurred                                                 time.Duration
	unclassified                                             bool
}

func (p proposal) line() string {
	pick := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}
	tenant, project := pick(p.tenant, "t1"), pick(p.project, "p1")
	effect := `,"effect":"EFFECT_CLASS_READ"`
	if p.unclassified {
		effect = ""
	}
	if p.protocol != "" {
		effect += fmt.Sprintf(`,"protocol":%q`, p.protocol)
	}
	return fmt.Sprintf(`{"type":"event","offset":0,"cursor":"c","event":{"eventId":"e1",`+
		`"kind":"EVENT_KIND_ACTION_PROPOSED","projectId":%q,"tenantId":%q,"occurredAt":%q,"schemaVersion":"1.0",`+
		`"enforcementMode":%q,"proposed":{"schemaVersion":"1.0","requestId":"r1","occurredAt":%q,`+
		`"traceId":%q,"spanId":%q,"projectId":%q,"tenantId":%q,"principal":{"id":"agent-1"},`+
		`"action":{"kind":%q,"name":%q,"provider":%q%s},"resource":{"type":"tool"}}}}`,
		pick(p.eventProject, project), pick(p.eventTenant, tenant), rfc(p.occurred), "ENFORCEMENT_MODE_"+pick(p.mode, "ENFORCE"),
		rfc(p.occurred), p.trace, p.span, pick(p.envelopeProject, project), pick(p.envelopeTenant, tenant),
		pick(p.kind, "tool"), pick(p.tool, "create_issue"), pick(p.upstream, "github"), effect)
}

// windowEvent is a POLICY_DECIDED event at occurred, which widens the
// export's window and joins nothing.
func windowEvent(occurred time.Duration) string {
	return fmt.Sprintf(`{"type":"event","offset":0,"cursor":"c","event":{"eventId":"w","kind":"EVENT_KIND_POLICY_DECIDED",`+
		`"occurredAt":%q,"schemaVersion":"1.0"}}`, rfc(occurred))
}

func trailer(events, gaps, duplicates int, end bool) string {
	return fmt.Sprintf(`{"type":"trailer","next_cursor":"c","end_reached":%t,"tail_bytes":0,"writer_held":false,`+
		`"counts":{"event":%d,"gap":%d,"duplicate":%d},"scanned_bytes":0,"dedup_scope":"export"}`, end, events, gaps, duplicates)
}

func lines(l ...string) []byte { return []byte(strings.Join(l, "\n") + "\n") }

func mustExport(t *testing.T, b []byte) *coverage.Export {
	t.Helper()
	x, err := coverage.ReadExport(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("ReadExport: %v", err)
	}
	return x
}

// wholeExport holds the given event lines, a window from an hour before now
// to now, and its trailer.
func wholeExport(t *testing.T, events ...string) *coverage.Export {
	t.Helper()
	l := append([]string{header(plainQuery), windowEvent(-time.Hour), windowEvent(0)}, events...)
	return mustExport(t, lines(append(l, trailer(len(events)+2, 0, 0, true))...))
}

func mustMap(t *testing.T, in coverage.Input) *coverage.Report {
	t.Helper()
	if in.Now.IsZero() {
		in.Now = now
	}
	r, err := coverage.Map(in)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if len(r.Paths) == 0 {
		t.Fatal("Map returned no paths")
	}
	return r
}
