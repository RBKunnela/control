package observe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MaxLineBytes bounds one log line, its newline excluded, in both directions.
const MaxLineBytes = 64 << 10

var (
	// ErrLine reports a record or a line the codec refuses.
	ErrLine = errors.New("observe: line refused")
	// ErrLineTooLong reports a line over MaxLineBytes, in either direction.
	ErrLineTooLong = errors.New("observe: line too long")
)

// MarshalLine writes one record as one log line: compact JSON, escaped as
// evidence lines are, and a newline. It refuses a record UnmarshalLine would
// refuse, and one carrying a field this build cannot name, which protojson
// would drop without a word.
func MarshalLine(r *observev1.Record) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil record", ErrLine)
	}
	if err := checkRecord(r); err != nil {
		return nil, err
	}
	if v := innerVersion(r); v != SchemaVersion && v != SchemaVersion02 && v != SchemaVersion03 {
		return nil, fmt.Errorf("%w: schema_version %s, this writer writes %q, %q and %q", ErrLine,
			quoted(v, maxVersionBytes), SchemaVersion, SchemaVersion02, SchemaVersion03)
	}
	if hasUnknownFields(r.ProtoReflect()) {
		return nil, fmt.Errorf("%w: a field this build cannot name would be dropped", ErrLine)
	}
	raw, err := protojson.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrLine, cause(err))
	}
	var compact, line bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrLine, cause(err))
	}
	escapeLine(&line, compact.Bytes())
	if line.Len() > MaxLineBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrLineTooLong, line.Len(), MaxLineBytes)
	}
	line.WriteByte('\n')
	return line.Bytes(), nil
}

// UnmarshalLine reads one log line, with or without its newline. It refuses
// an unknown, duplicate or null member, a line holding no record or two, a
// version outside the table, and any record MarshalLine would refuse.
func UnmarshalLine(line []byte) (*observev1.Record, error) {
	if n := len(bytes.TrimSuffix(line, []byte("\n"))); n > MaxLineBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrLineTooLong, n, MaxLineBytes)
	}
	if len(bytes.TrimSpace(line)) == 0 {
		return nil, fmt.Errorf("%w: blank", ErrLine)
	}
	r := &observev1.Record{}
	if err := unmarshalStrict(line, r); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLine, err)
	}
	if err := checkRecord(r); err != nil {
		return nil, err
	}
	return r, nil
}

func innerVersion(r *observev1.Record) string {
	if o := r.GetObservation(); o != nil {
		return o.GetSchemaVersion()
	}
	return r.GetImportReport().GetSchemaVersion()
}

func checkRecord(r *observev1.Record) error {
	o, ir := r.GetObservation(), r.GetImportReport()
	if o == nil && ir == nil {
		return fmt.Errorf("%w: no member set", ErrLine)
	}
	if err := CheckVersion(innerVersion(r)); err != nil {
		return fmt.Errorf("%w: %w", ErrLine, err)
	}
	if err := checkSchema(innerVersion(r), r); err != nil {
		return err
	}
	if o != nil {
		return checkObservation(o)
	}
	if err := checkOrigin(ir.GetTenantId(), ir.GetProjectId(), ir.GetSource(), ir.GetReceivedTime()); err != nil {
		return err
	}
	if err := checkRefusedBy(ir.GetCounts()); err != nil {
		return err
	}
	return checkDoubt(ir)
}

// schemaRank orders the record schemas this package reads.
var schemaRank = map[string]int{SchemaVersion: 1, SchemaVersion02: 2, SchemaVersion03: 3}

// checkSchema holds a record of a version this package writes to the schema
// its members call for. A minor only a test adds to the table has no members
// here to judge.
func checkSchema(version string, r *observev1.Record) error {
	want, member := schemaOf(r)
	rank, writes := schemaRank[version]
	switch {
	case !writes, version == want:
		return nil
	case rank < schemaRank[want]:
		return fmt.Errorf("%w: %s: not a member of schema %q", ErrLine, member, version)
	}
	return fmt.Errorf("%w: schema_version: %q on a record with no member of %q", ErrLine, version, version)
}

// schemaOf names the schema r's members call for, the latest whose member it
// carries, and the first such member, or "" for SchemaVersion.
func schemaOf(r *observev1.Record) (version, member string) {
	if m := added03(r); m != "" {
		return SchemaVersion03, m
	}
	if m := added02(r.GetImportReport()); m != "" {
		return SchemaVersion02, m
	}
	return SchemaVersion, ""
}

// added03 names the first member of r that SchemaVersion02 does not have, or
// "".
func added03(r *observev1.Record) string {
	switch {
	case r.GetObservation().GetConnection() != nil:
		return "connection"
	case len(r.GetImportReport().GetCounts().GetRefusedBy()) > 0:
		return "counts.refused_by"
	case r.GetImportReport().GetCounts().GetCallersDropped() > 0:
		return "counts.callers_dropped"
	case r.GetObservation().GetSource().GetKind() != "" || r.GetImportReport().GetSource().GetKind() != "":
		return "source.kind"
	}
	return ""
}

// added02 names the first member of r that SchemaVersion does not have, or
// "" for none or no report.
func added02(r *observev1.ImportReport) string {
	switch {
	case len(r.GetDoubtedRunIds()) > 0:
		return "doubted_run_ids"
	case r.GetEveryRunDoubted():
		return "every_run_doubted"
	}
	return ""
}

// checkOrigin holds what every record carries: whose it is, which source it
// came from and when it was received.
func checkOrigin(tenant, project string, src *observev1.SourceRef, received *timestamppb.Timestamp) error {
	switch {
	case tenant == "":
		return fmt.Errorf("%w: tenant_id: required", ErrLine)
	case project == "":
		return fmt.Errorf("%w: project_id: required", ErrLine)
	case received == nil:
		return fmt.Errorf("%w: received_time: required", ErrLine)
	}
	if err := identifier(src.GetSourceId()); err != nil {
		return fmt.Errorf("%w: source.source_id: %w", ErrLine, err)
	}
	switch kind := src.GetKind(); {
	case kind == KindOTelGenAI:
		return fmt.Errorf("%w: source.kind: %q is spelled empty", ErrLine, kind)
	case kind != "" && LookupKind(kind).Name == "":
		return fmt.Errorf("%w: source.kind: %s is not a kind this build reads", ErrLine, quoted(kind, maxIdentifierBytes))
	}
	return nil
}

// RecordKind is the kind of the source a record came from: its source's kind,
// or KindOTelGenAI when it names none, as every record before SchemaVersion03
// does.
func RecordKind(src *observev1.SourceRef) string {
	if src.GetKind() == "" {
		return KindOTelGenAI
	}
	return src.GetKind()
}

func checkObservation(o *observev1.Observation) error {
	if !validObservationID(o.GetObservationId()) {
		return fmt.Errorf("%w: observation_id: %s is not \"obs-\" and 32 lowercase hex digits",
			ErrLine, quoted(o.GetObservationId(), maxIdentifierBytes))
	}
	if err := checkOrigin(o.GetTenantId(), o.GetProjectId(), o.GetSource(), o.GetReceivedTime()); err != nil {
		return err
	}
	connection := o.GetSubject().GetKind() == observev1.SubjectKind_SUBJECT_KIND_CONNECTION
	if egress := RecordKind(o.GetSource()) == KindEgressAccessLog; connection != egress {
		return fmt.Errorf("%w: source.kind: a subject of kind %s from a source of kind %q: a connection comes from an %q source, and only a connection does",
			ErrLine, o.GetSubject().GetKind(), RecordKind(o.GetSource()), KindEgressAccessLog)
	}
	switch kind := o.GetSubject().GetKind(); {
	case connection:
		return checkConnection(o)
	case o.GetConnection() != nil:
		return fmt.Errorf("%w: connection: set on a subject of kind %s", ErrLine, kind)
	}
	c := o.GetCorrelation()
	switch {
	case !ValidTraceID(c.GetTraceId()):
		return fmt.Errorf("%w: correlation.trace_id: %s is not 32 lowercase hex digits, not all zeros",
			ErrLine, quoted(c.GetTraceId(), maxIdentifierBytes))
	case !ValidSpanID(c.GetSpanId()):
		return fmt.Errorf("%w: correlation.span_id: %s is not 16 lowercase hex digits, not all zeros",
			ErrLine, quoted(c.GetSpanId(), maxIdentifierBytes))
	case c.GetParentSpanId() != "" && !ValidSpanID(c.GetParentSpanId()):
		return fmt.Errorf("%w: correlation.parent_span_id: %s is neither empty nor a span id",
			ErrLine, quoted(c.GetParentSpanId(), maxIdentifierBytes))
	}
	// An id that is not its key's would let one observation stand in for another's.
	key := ObservationID(o.GetTenantId(), o.GetProjectId(), o.GetSource().GetSourceId(), c.GetTraceId(), c.GetSpanId())
	if o.GetObservationId() != key {
		return fmt.Errorf("%w: observation_id: %s is not the id of its tenant, project, source, trace and span",
			ErrLine, quoted(o.GetObservationId(), maxIdentifierBytes))
	}
	return checkRun(c)
}

// checkRun holds the run id to the basis: a claimed basis names a run in its
// one form, and a basis read as none names no run, so a reader cannot take an
// unclaimed run id for a claim.
func checkRun(c *observev1.Correlation) error {
	run, basis := c.GetRunId(), BasisOf(c.GetBasis())
	switch {
	case run != "" && !ValidRunID(run):
		return fmt.Errorf("%w: correlation.run_id: %s is not \"run-\" and 32 lowercase hex digits",
			ErrLine, quoted(run, maxIdentifierBytes))
	case run == "" && basis == observev1.Basis_BASIS_CLAIMED:
		return fmt.Errorf("%w: correlation.run_id: required when the basis is %s", ErrLine, basis)
	case run != "" && basis == observev1.Basis_BASIS_NONE:
		return fmt.Errorf("%w: correlation.run_id: set while the basis reads as %s", ErrLine, basis)
	}
	return nil
}
