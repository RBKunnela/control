package approvals

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/policy/strictjson"
)

// SchemaVersion is the version this build writes. A record whose major
// differs is refused: a reader that skipped what it could not name would
// answer about an approval it did not understand.
const SchemaVersion = "1.0"

// Resolution is what the store can say about a record. The zero value means
// it cannot say, so a caller that forgets to look holds the request anew
// rather than treating it as spent; a bool would put that case on the unsafe
// side by accident.
type Resolution uint8

const (
	// ResolutionUnspecified is the store having no answer.
	ResolutionUnspecified Resolution = iota
	// ResolutionPending is a record no execution has consumed, answered or
	// not.
	ResolutionPending
	// ResolutionConsumed is a record whose approval a resume spent. It
	// does not say the action ran: the resume can still block after it.
	ResolutionConsumed
	// ResolutionNotResumed is a record the plane closed without resuming the
	// call it was held for.
	ResolutionNotResumed
)

// String names the resolution as a record spells it.
func (r Resolution) String() string {
	switch r {
	case ResolutionUnspecified:
		return "unspecified"
	case ResolutionPending:
		return "pending"
	case ResolutionConsumed:
		return "consumed"
	case ResolutionNotResumed:
		return "not_resumed"
	}
	return "resolution(" + strconv.Itoa(int(r)) + ")"
}

// parseResolution reads what a record spells. "unspecified" is refused on the
// way in: a record that says the store cannot say is a record that says
// nothing.
func parseResolution(s string) (Resolution, error) {
	for _, r := range []Resolution{ResolutionPending, ResolutionConsumed, ResolutionNotResumed} {
		if r.String() == s {
			return r, nil
		}
	}
	return ResolutionUnspecified, fmt.Errorf("%w: resolution %q", ErrMalformed, cause(s))
}

// Record is the durable record, and the whole of what the plane reads back. It
// carries no envelope, no decision and no position in a trail, so a writer of
// the directory cannot choose what the plane records or where.
type Record struct {
	// SchemaVersion is the record format's version, not the wire contract's.
	SchemaVersion string
	// ApprovalID is the record's name on disk and the id inside it; the two
	// are compared on every read.
	ApprovalID string
	// RequestID is the held request. It is also inside Approval, and the two
	// are compared on every read.
	RequestID string
	// Binding is what the approval is stored and compared against. It is the
	// binding Approval's two digests make, and that is checked on every read.
	Binding approval.Binding
	// Resolution is what the store can say about this record.
	Resolution Resolution
	// Approval is the approval as it stands.
	Approval *controlv1.Approval
}

// A record on disk is a header and one JSON object:
//
//	magic    8 bytes, "APPRVREC"
//	length   uint32, big-endian, the byte count of the body
//	checksum uint32, big-endian, CRC32C (Castagnoli) over the body
//	body     length bytes
//
// The file holds exactly one record: a file shorter than the header and the
// body it claims is truncated, one longer has bytes past the body's end, and
// either way it is refused rather than read as far as it goes.
const (
	magic       = "APPRVREC"
	headerBytes = len(magic) + 8
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// checksum is the body's CRC32C.
func checksum(body []byte) uint32 { return crc32.Checksum(body, castagnoli) }

// wireRecord is the body's shape. Every key is known to this build; one that
// is not refuses the record.
type wireRecord struct {
	SchemaVersion string          `json:"schema_version"`
	ApprovalID    string          `json:"approval_id"`
	RequestID     string          `json:"request_id"`
	Binding       string          `json:"binding"`
	Resolution    string          `json:"resolution"`
	Approval      json.RawMessage `json:"approval"`
}

var wireKeys = []string{"schema_version", "approval_id", "request_id", "binding", "resolution", "approval"}

// check holds a record to what it claims about itself, in either direction. A
// record that disagrees with itself is refused rather than read as if one half
// of it were right.
//
// The same bounds apply in both directions. A record written straight into the
// directory travels into an evidence event as it stands, and nothing
// downstream reads payloads, so what an answer is held to on the way in is
// what a record is held to on the way back.
func (r Record) check(maxWindow time.Duration) error {
	if err := r.checkStanding(maxWindow); err != nil {
		return err
	}
	return r.checkApprover()
}

// checkStanding is every check but the approver id's: what a record has to
// pass before what it says about its own approval can be trusted.
func (r Record) checkStanding(maxWindow time.Duration) error {
	if err := r.checkIdentity(); err != nil {
		return err
	}
	if err := checkReason(r.Approval.GetReason()); err != nil {
		return err
	}
	return r.checkTimes(maxWindow)
}

// refusedApprover is a record that passes every check but its approver id's,
// which the claim rule refuses. An earlier release wrote such ids legally, so
// the record refuses its own approval and no other: it still says which
// approval it is, under which binding, and when it expires.
type refusedApprover struct {
	rec Record
	err error
}

func (e *refusedApprover) Error() string { return e.err.Error() }
func (e *refusedApprover) Unwrap() error { return e.err }

// refusedOnlyItself returns the record behind err when err refuses that
// record's own approval and nothing else.
func refusedOnlyItself(err error) (Record, bool) {
	var r *refusedApprover
	if errors.As(err, &r) {
		return r.rec, true
	}
	return Record{}, false
}

// checkIdentity holds the record's names and digests to each other.
func (r Record) checkIdentity() error {
	switch {
	case r.Approval == nil:
		return fmt.Errorf("%w: no approval", ErrInvalidHold)
	case r.RequestID == "":
		return fmt.Errorf("%w: no request id", ErrInvalidHold)
	case r.Binding == "":
		return fmt.Errorf("%w: no binding", ErrInvalidHold)
	case r.Resolution == ResolutionUnspecified:
		return fmt.Errorf("%w: no resolution", ErrInvalidHold)
	}
	if err := checkApprovalID(r.ApprovalID); err != nil {
		return err
	}
	if err := checkSchemaVersion(r.SchemaVersion); err != nil {
		return err
	}
	if err := checkSchemaVersion(r.Approval.GetSchemaVersion()); err != nil {
		return fmt.Errorf("the approval: %w", err)
	}
	if got := r.Approval.GetApprovalId(); got != r.ApprovalID {
		return fmt.Errorf("%w: the approval names %q, the record %q", ErrRecordMismatch, cause(got), cause(r.ApprovalID))
	}
	if got := r.Approval.GetRequestId(); got != r.RequestID {
		return fmt.Errorf("%w: the approval names request %q, the record %q", ErrRecordMismatch, cause(got), cause(r.RequestID))
	}
	binding, err := canon.ApprovalBinding(r.Approval.GetActionDigest(), r.Approval.GetPolicyBundleDigest())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRecordMismatch, err)
	}
	if approval.Binding(binding) != r.Binding {
		return fmt.Errorf("%w: the record is filed under a binding its digests do not make", ErrRecordMismatch)
	}
	return nil
}

// checkSchemaVersion refuses a version this build does not read. The major is
// what decides: a later minor may add a field, and the unknown-field rule
// refuses that record too, so nothing is dropped in silence.
func checkSchemaVersion(v string) error {
	if !strictjson.IsVersion(v, "1") {
		return fmt.Errorf("%w: %q", ErrSchemaVersion, cause(v))
	}
	return nil
}

// encodeRecord frames r. It refuses a record that does not check and a body
// over maxBody, so nothing is written that decodeRecord would refuse to read.
func encodeRecord(r Record, maxBody int, maxWindow time.Duration) ([]byte, error) {
	if err := r.check(maxWindow); err != nil {
		return nil, err
	}
	raw, err := protojson.Marshal(r.Approval)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	// protojson may vary insignificant whitespace between runs; compacting
	// makes two encodings of one record the same bytes.
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	body, err := json.Marshal(wireRecord{
		SchemaVersion: r.SchemaVersion,
		ApprovalID:    r.ApprovalID,
		RequestID:     r.RequestID,
		Binding:       string(r.Binding),
		Resolution:    r.Resolution.String(),
		Approval:      compact.Bytes(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrRecordTooLarge, len(body), maxBody)
	}
	out := make([]byte, headerBytes+len(body))
	copy(out, magic)
	binary.BigEndian.PutUint32(out[len(magic):], uint32(len(body))) //nolint:gosec // G115: the bound above is far below the field
	binary.BigEndian.PutUint32(out[len(magic)+4:], checksum(body))
	copy(out[headerBytes:], body)
	return out, nil
}

// decodeRecord reads one framed record. Every way it can fail is its own
// refusal, because an operator acts differently on a truncated file, a
// checksum that does not match and a field this build cannot name.
func decodeRecord(data []byte, maxBody int, maxWindow time.Duration) (Record, error) {
	body, err := unframe(data, maxBody)
	if err != nil {
		return Record{}, err
	}
	if err := checkMembers(body, wireKeys...); err != nil {
		return Record{}, err
	}
	var w wireRecord
	if err := json.Unmarshal(body, &w); err != nil {
		var typed *json.UnmarshalTypeError
		if errors.As(err, &typed) {
			return Record{}, fmt.Errorf("%w: %q holds a %s", ErrFieldType, cause(typed.Field), typed.Value)
		}
		return Record{}, fmt.Errorf("%w: %s", ErrMalformed, cause(err.Error()))
	}
	// Checked before the rest, so a record from a version this build cannot
	// read is reported as that and not as a field it happens to disagree on.
	if err := checkSchemaVersion(w.SchemaVersion); err != nil {
		return Record{}, err
	}
	resolution, err := parseResolution(w.Resolution)
	if err != nil {
		return Record{}, err
	}
	a := &controlv1.Approval{}
	// DiscardUnknown stays false: a field this build cannot name is refused
	// here too, rather than dropped on the way in.
	if err := (protojson.UnmarshalOptions{}).Unmarshal(w.Approval, a); err != nil {
		return Record{}, fmt.Errorf("%w: the approval: %s", ErrMalformed, cause(err.Error()))
	}
	r := Record{
		SchemaVersion: w.SchemaVersion,
		ApprovalID:    w.ApprovalID,
		RequestID:     w.RequestID,
		Binding:       approval.Binding(w.Binding),
		Resolution:    resolution,
		Approval:      a,
	}
	if err := r.checkStanding(maxWindow); err != nil {
		return Record{}, err
	}
	if err := r.checkApprover(); err != nil {
		if errors.Is(err, approval.ErrReservedApproverID) {
			return Record{}, &refusedApprover{rec: r, err: err}
		}
		return Record{}, err
	}
	return r, nil
}

// checkMembers refuses a body that is not one JSON object, and one naming a
// member outside known, spelled in another case, or named twice:
// encoding/json folds case and keeps the last of two, so a reader that did
// neither would read another record from the same bytes.
func checkMembers(body []byte, known ...string) error {
	members, err := strictjson.ReadObject(body)
	switch {
	case errors.Is(err, strictjson.ErrRepeated):
		return fmt.Errorf("%w: a member appears twice", ErrMalformed)
	case err != nil:
		return fmt.Errorf("%w: the body is not one JSON object", ErrMalformed)
	}
	if err := members.Only(known...); err != nil {
		return fmt.Errorf("%w: a member this build cannot name", ErrUnknownField)
	}
	return nil
}

// unframe returns the body of one framed record.
func unframe(data []byte, maxBody int) ([]byte, error) {
	if len(data) < headerBytes {
		return nil, fmt.Errorf("%w: %d bytes, header %d", ErrTruncated, len(data), headerBytes)
	}
	if string(data[:len(magic)]) != magic {
		return nil, fmt.Errorf("%w: the file does not begin as a record does", ErrCorrupt)
	}
	length := int64(binary.BigEndian.Uint32(data[len(magic):]))
	if length == 0 {
		return nil, fmt.Errorf("%w: the record claims an empty body", ErrMalformed)
	}
	if length > int64(maxBody) {
		return nil, fmt.Errorf("%w: the record claims %d bytes, limit %d", ErrRecordTooLarge, length, maxBody)
	}
	switch end := int64(headerBytes) + length; {
	case end > int64(len(data)):
		return nil, fmt.Errorf("%w: the record claims %d bytes and the file holds %d", ErrTruncated, length, len(data)-headerBytes)
	case end < int64(len(data)):
		return nil, fmt.Errorf("%w: %d bytes past the record's end", ErrCorrupt, int64(len(data))-end)
	}
	body := data[headerBytes:]
	if checksum(body) != binary.BigEndian.Uint32(data[len(magic)+4:]) {
		return nil, fmt.Errorf("%w: the checksum does not match the body", ErrCorrupt)
	}
	return body, nil
}

// clone deep-copies the approval, so neither the caller's later writes nor the
// store's reach the other side.
func (r Record) clone() Record {
	r.Approval = proto.CloneOf(r.Approval)
	return r
}

// maxCauseBytes bounds how much of another writer's bytes travel with a
// refusal that may end up in an operator's log.
const maxCauseBytes = 120

// cause bounds and neutralises text a refusal quotes: it comes from a file
// this process did not write, and a refusal is read on a terminal.
func cause(s string) string {
	if len(s) > maxCauseBytes {
		s = s[:maxCauseBytes] + "..."
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
