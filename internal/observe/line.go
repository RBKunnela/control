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
	if v := innerVersion(r); v != SchemaVersion && v != SchemaVersion02 {
		return nil, fmt.Errorf("%w: schema_version %s, this writer writes %q and %q", ErrLine,
			quoted(v, maxVersionBytes), SchemaVersion, SchemaVersion02)
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
	if err := checkSchema(innerVersion(r), added02(ir)); err != nil {
		return err
	}
	if o != nil {
		return checkObservation(o)
	}
	if err := checkOrigin(ir.GetTenantId(), ir.GetProjectId(), ir.GetSource(), ir.GetReceivedTime()); err != nil {
		return err
	}
	return checkDoubt(ir)
}

// checkSchema holds a record to the schema its members call for, given
// added, the first member it carries that SchemaVersion does not have, or "".
func checkSchema(version, added string) error {
	switch {
	case version == SchemaVersion && added != "":
		return fmt.Errorf("%w: %s: not a member of schema %q", ErrLine, added, SchemaVersion)
	case version == SchemaVersion02 && added == "":
		return fmt.Errorf("%w: schema_version: %q on a record with no member of %q", ErrLine, SchemaVersion02, SchemaVersion02)
	}
	return nil
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
	return nil
}

func checkObservation(o *observev1.Observation) error {
	if !validObservationID(o.GetObservationId()) {
		return fmt.Errorf("%w: observation_id: %s is not \"obs-\" and 32 lowercase hex digits",
			ErrLine, quoted(o.GetObservationId(), maxIdentifierBytes))
	}
	if err := checkOrigin(o.GetTenantId(), o.GetProjectId(), o.GetSource(), o.GetReceivedTime()); err != nil {
		return err
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
