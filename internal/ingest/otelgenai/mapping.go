package otelgenai

import (
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	attrOperation = "gen_ai.operation.name"
	attrProvider  = "gen_ai.provider.name"
	attrServer    = "server.address"
	attrErrorType = "error.type"
	attrService   = "service.name"
)

// Skip reasons. A convention operation the importer does not map is named;
// any other value shares one reason, so the input cannot grow the map.
const (
	skipNoOperation       = "no_operation"
	skipUnmappedOperation = "unmapped_operation"
	skipOperationPrefix   = "operation:"
)

type subjectRule struct {
	kind    observev1.SubjectKind
	nameKey string
}

var operations = map[string]subjectRule{
	"execute_tool":     {observev1.SubjectKind_SUBJECT_KIND_TOOL, "gen_ai.tool.name"},
	"invoke_agent":     {observev1.SubjectKind_SUBJECT_KIND_AGENT, "gen_ai.agent.name"},
	"create_agent":     {observev1.SubjectKind_SUBJECT_KIND_AGENT, "gen_ai.agent.name"},
	"chat":             {observev1.SubjectKind_SUBJECT_KIND_MODEL, "gen_ai.request.model"},
	"generate_content": {observev1.SubjectKind_SUBJECT_KIND_MODEL, "gen_ai.request.model"},
	"text_completion":  {observev1.SubjectKind_SUBJECT_KIND_MODEL, "gen_ai.request.model"},
	"embeddings":       {observev1.SubjectKind_SUBJECT_KIND_MODEL, "gen_ai.request.model"},
}

// unmappedConventionOperations are the other values gen_ai.operation.name
// takes in the pinned convention version.
var unmappedConventionOperations = map[string]bool{"retrieval": true, "invoke_workflow": true}

// copiedKeys are the keys whose values the mapping reads; attributes()
// keeps these and the descriptor's run attribute, and no other value.
var copiedKeys = func() map[string]bool {
	keys := map[string]bool{attrOperation: true, attrProvider: true, attrServer: true, attrErrorType: true, attrService: true}
	for _, r := range operations {
		keys[r.nameKey] = true
	}
	return keys
}()

func copied(key, runKey string) bool { return copiedKeys[key] || (runKey != "" && key == runKey) }

type attributes map[string]*anyValue

func index(kvs []keyValue) attributes {
	a := make(attributes, len(kvs))
	for i := range kvs {
		a[kvs[i].key] = &kvs[i].value
	}
	return a
}

// rule maps a span's operation to its subject, or names why it is skipped.
func rule(a attributes) (subjectRule, string, string) {
	v, ok := a[attrOperation]
	if !ok {
		return subjectRule{}, "", skipNoOperation
	}
	if v.kind == kindString {
		if r, ok := operations[v.str]; ok {
			return r, v.str, ""
		}
		if unmappedConventionOperations[v.str] {
			return subjectRule{}, "", skipOperationPrefix + v.str
		}
	}
	return subjectRule{}, "", skipUnmappedOperation
}

// keyable reports a span the importer can key and whose status it can read.
func keyable(s *span) bool {
	return observe.ValidTraceID(s.traceID) && observe.ValidSpanID(s.spanID) &&
		(s.parentSpanID == "" || observe.ValidSpanID(s.parentSpanID)) &&
		s.statusCode >= 0 && s.statusCode <= 2
}

// claimedRun is the run attribute's string on a span, "" when it holds none.
func claimedRun(s *span, runKey string) string {
	v, ok := index(s.attrs.kept)[runKey]
	if runKey == "" || !ok || v.kind != kindString {
		return ""
	}
	return v.str
}

func (im *importer) observation(s *span, rule subjectRule, operation string) (*observev1.Observation, spanCounts) {
	var c spanCounts
	a := index(s.attrs.kept)
	runKey := im.desc.GetRunAttribute()
	kept := func(key string) bool {
		return key == attrOperation || key == attrProvider || key == rule.nameKey || (runKey != "" && key == runKey)
	}
	c.drop(&s.attrs, kept)
	c.add(s.events)
	o := &observev1.Observation{
		SchemaVersion: observe.SchemaVersion,
		ObservationId: observe.ObservationID(im.desc.GetTenantId(), im.desc.GetProjectId(), im.desc.GetSourceId(), s.traceID, s.spanID),
		TenantId:      im.desc.GetTenantId(),
		ProjectId:     im.desc.GetProjectId(),
		Source:        im.source(),
		EventTime:     eventTime(s.end),
		ReceivedTime:  im.receivedTime(),
		Stage:         stage(s, a),
		Subject: &observev1.Subject{
			Kind:          rule.kind,
			Name:          c.text(a, rule.nameKey),
			Operation:     operation,
			Provider:      c.text(a, attrProvider),
			ServerAddress: c.text(a, attrServer),
		},
		Outcome:     &observev1.Outcome{Status: status(s.statusCode), ErrorType: c.text(a, attrErrorType)},
		Correlation: c.correlation(s, a, runKey),
	}
	o.ContentAttributesDropped = c.contentDropped
	return o, c
}

// text copies an allowlisted string, or drops and counts one that is not a
// string, is too long, is only whitespace or holds a rune printable() refuses.
// An absent or empty value is nothing to drop.
func (c *spanCounts) text(a attributes, key string) string {
	v, ok := a[key]
	if !ok || (v.kind == kindString && v.str == "") {
		return ""
	}
	if v.kind != kindString || !copyable(v.str) {
		c.stringsDropped++
		return ""
	}
	return v.str
}

func copyable(s string) bool {
	if len(s) > observe.MaxTextBytes || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if !printable(r) {
			return false
		}
	}
	return true
}

// printable refuses what can hide or reshape text where a record is shown:
// control and format characters, line and paragraph separators, private use,
// noncharacters, and U+FFFD, which a lone surrogate escape decodes to.
func printable(r rune) bool {
	switch {
	case unicode.IsControl(r), unicode.In(r, unicode.Cf, unicode.Co, unicode.Zl, unicode.Zp):
		return false
	case r == utf8.RuneError, r >= 0xFDD0 && r <= 0xFDEF, r&0xFFFE == 0xFFFE:
		return false
	}
	return true
}

// correlation claims a run only for a value in the one form a run id has;
// any other value of the run attribute is dropped and counted.
func (c *spanCounts) correlation(s *span, a attributes, runKey string) *observev1.Correlation {
	corr := &observev1.Correlation{
		Basis:        observev1.Basis_BASIS_NONE,
		TraceId:      s.traceID,
		SpanId:       s.spanID,
		ParentSpanId: s.parentSpanID,
	}
	if runKey == "" {
		return corr
	}
	v, ok := a[runKey]
	if !ok {
		return corr
	}
	if v.kind == kindString && observe.ValidRunID(v.str) {
		corr.Basis, corr.RunId = observev1.Basis_BASIS_CLAIMED, v.str
		return corr
	}
	c.runIDsDropped++
	return corr
}

// stage reads error.type's presence, whatever its value, as a failure.
func stage(s *span, a attributes) observev1.Stage {
	_, errorType := a[attrErrorType]
	switch {
	case s.statusCode == 2 || errorType:
		return observev1.Stage_STAGE_FAILED
	case s.end != 0:
		return observev1.Stage_STAGE_COMPLETED
	}
	return observev1.Stage_STAGE_UNSPECIFIED
}

func status(code int64) observev1.Status {
	switch code {
	case 1:
		return observev1.Status_STATUS_OK
	case 2:
		return observev1.Status_STATUS_ERROR
	}
	return observev1.Status_STATUS_UNSET
}

// eventTime is the span's end, or nil when it has none: never another time.
func eventTime(end uint64) *timestamppb.Timestamp {
	if end == 0 {
		return nil
	}
	sec, nsec := end/uint64(time.Second), end%uint64(time.Second)
	if sec > math.MaxInt64 || nsec > math.MaxInt32 {
		return nil
	}
	return &timestamppb.Timestamp{Seconds: int64(sec), Nanos: int32(nsec)}
}
