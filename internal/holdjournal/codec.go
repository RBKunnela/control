package holdjournal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/policy/strictjson"
)

// An entry on disk is a header and one JSON object:
//
//	magic    8 bytes, "HOLDJRNL"
//	length   uint32, big-endian, the byte count of the body
//	checksum uint32, big-endian, CRC32C (Castagnoli) over the body
//	body     length bytes
//
// The file holds exactly one entry: a file shorter than the header and the
// body it claims is truncated, one longer has bytes past the body's end, and
// either way it is refused rather than read as far as it goes.
const (
	magic       = "HOLDJRNL"
	headerBytes = len(magic) + 8
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// checksum is the body's CRC32C.
func checksum(body []byte) uint32 { return crc32.Checksum(body, castagnoli) }

// wireEntry is the body's shape. Every key is known to this build; one that is
// not refuses the entry.
type wireEntry struct {
	SchemaVersion string          `json:"schema_version"`
	State         string          `json:"state"`
	RequestID     string          `json:"request_id"`
	RunID         string          `json:"run_id"`
	ProjectID     string          `json:"project_id"`
	TenantID      string          `json:"tenant_id"`
	LastEventID   string          `json:"last_event_id"`
	Binding       string          `json:"binding"`
	Approval      json.RawMessage `json:"approval"`
	Expires       string          `json:"expires"`
}

var wireKeys = []string{
	"schema_version", "state", "request_id", "run_id", "project_id", "tenant_id",
	"last_event_id", "binding", "approval", "expires",
}

// parseState reads what an entry spells. "unknown" is refused on the way in:
// an entry that says the plane cannot say is an entry that says nothing.
func parseState(s string) (State, error) {
	for _, st := range []State{StateHeld, StateResuming, StateClosing} {
		if st.String() == s {
			return st, nil
		}
	}
	return StateUnknown, fmt.Errorf("%w: state %q", ErrMalformed, cause(s))
}

// checkSchemaVersion refuses a version this build does not read. The major is
// what decides: a later minor may add a field, and the unknown-field rule
// refuses that entry too, so nothing is dropped in silence.
func checkSchemaVersion(v string) error {
	if !strictjson.IsVersion(v, "1") {
		return fmt.Errorf("%w: %q", ErrSchemaVersion, cause(v))
	}
	return nil
}

// check holds an entry to what it claims about itself, in either direction. An
// entry that disagrees with itself is refused rather than read as if one half
// of it were right, because the other half is what a close would be written
// from.
func (e Entry) check() error {
	if err := checkSchemaVersion(e.SchemaVersion); err != nil {
		return err
	}
	if _, err := encodeName(e.IDs.RequestID); err != nil {
		return err
	}
	switch {
	case e.State == StateUnknown:
		return fmt.Errorf("%w: no state", ErrEntry)
	case e.LastEventID == "":
		return fmt.Errorf("%w: no position on the trail", ErrEntry)
	case e.Binding == "":
		return fmt.Errorf("%w: no binding", ErrEntry)
	case e.Approval.GetApprovalId() == "":
		return fmt.Errorf("%w: no approval", ErrEntry)
	case e.Expires.IsZero():
		return fmt.Errorf("%w: no expiry", ErrEntry)
	}
	if err := checkSchemaVersion(e.Approval.GetSchemaVersion()); err != nil {
		return fmt.Errorf("the approval: %w", err)
	}
	if got := e.Approval.GetRequestId(); got != e.IDs.RequestID {
		return fmt.Errorf("%w: the approval names request %q, the entry %q",
			ErrEntry, cause(got), cause(e.IDs.RequestID))
	}
	return nil
}

// encodeEntry frames e. It refuses an entry that does not check and a body
// over maxBody, so nothing is written that decodeEntry would refuse to read.
func encodeEntry(e Entry, maxBody int) ([]byte, error) {
	if err := e.check(); err != nil {
		return nil, err
	}
	raw, err := protojson.Marshal(e.Approval)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	// protojson may vary insignificant whitespace between runs; compacting
	// makes two encodings of one entry the same bytes.
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	body, err := json.Marshal(wireEntry{
		SchemaVersion: e.SchemaVersion,
		State:         e.State.String(),
		RequestID:     e.IDs.RequestID,
		RunID:         e.IDs.RunID,
		ProjectID:     e.IDs.ProjectID,
		TenantID:      e.IDs.TenantID,
		LastEventID:   e.LastEventID,
		Binding:       string(e.Binding),
		Approval:      compact.Bytes(),
		Expires:       e.Expires.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrEntryTooLarge, len(body), maxBody)
	}
	out := make([]byte, headerBytes+len(body))
	copy(out, magic)
	binary.BigEndian.PutUint32(out[len(magic):], uint32(len(body))) //nolint:gosec // G115: the bound above is far below the field
	binary.BigEndian.PutUint32(out[len(magic)+4:], checksum(body))
	copy(out[headerBytes:], body)
	return out, nil
}

// decodeEntry reads one framed entry. Every way it can fail is its own
// refusal, because an operator acts differently on a truncated file, a
// checksum that does not match and a field this build cannot name.
func decodeEntry(data []byte, maxBody int) (Entry, error) {
	body, err := unframe(data, maxBody)
	if err != nil {
		return Entry{}, err
	}
	w, err := readWire(body)
	if err != nil {
		return Entry{}, err
	}
	// Checked before the rest, so an entry from a version this build cannot
	// read is reported as that and not as a field it happens to disagree on.
	if err := checkSchemaVersion(w.SchemaVersion); err != nil {
		return Entry{}, err
	}
	state, err := parseState(w.State)
	if err != nil {
		return Entry{}, err
	}
	expires, err := time.Parse(time.RFC3339Nano, w.Expires)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: the expiry: %s", ErrMalformed, cause(err.Error()))
	}
	// The expiry is read in one spelling, the encoder's.
	if expires.UTC().Format(time.RFC3339Nano) != w.Expires {
		return Entry{}, fmt.Errorf("%w: the expiry %q is not spelled as this build writes it", ErrMalformed, cause(w.Expires))
	}
	a := &controlv1.Approval{}
	// DiscardUnknown stays false: a field this build cannot name is refused
	// here too, rather than dropped on the way in.
	if err := (protojson.UnmarshalOptions{}).Unmarshal(w.Approval, a); err != nil {
		return Entry{}, fmt.Errorf("%w: the approval: %s", ErrMalformed, cause(err.Error()))
	}
	// protojson reads an enum number this build does not name as that number.
	if _, named := controlv1.ApprovalState_name[int32(a.GetState())]; !named {
		return Entry{}, fmt.Errorf("%w: the approval's state %d is not one this build names", ErrMalformed, a.GetState())
	}
	e := Entry{
		SchemaVersion: w.SchemaVersion,
		State:         state,
		IDs: evidence.IDs{
			RequestID: w.RequestID, RunID: w.RunID,
			ProjectID: w.ProjectID, TenantID: w.TenantID,
		},
		LastEventID: w.LastEventID,
		Binding:     approval.Binding(w.Binding),
		Approval:    a,
		Expires:     expires,
	}
	if err := e.check(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// readWire reads the body's one object and refuses a key this build cannot
// name, or one named twice, before it reads any value.
func readWire(body []byte) (wireEntry, error) {
	if err := checkMembers(body, wireKeys...); err != nil {
		return wireEntry{}, err
	}
	var w wireEntry
	if err := json.Unmarshal(body, &w); err != nil {
		var typed *json.UnmarshalTypeError
		if errors.As(err, &typed) {
			return wireEntry{}, fmt.Errorf("%w: %q holds a %s", ErrFieldType, cause(typed.Field), typed.Value)
		}
		return wireEntry{}, fmt.Errorf("%w: %s", ErrMalformed, cause(err.Error()))
	}
	return w, nil
}

// checkMembers refuses a body that is not one JSON object, and one naming a
// member outside known, spelled in another case, or named twice:
// encoding/json folds case and keeps the last of two, so a reader that did
// neither would read another entry from the same bytes.
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

// unframe returns the body of one framed entry.
func unframe(data []byte, maxBody int) ([]byte, error) {
	if len(data) < headerBytes {
		return nil, fmt.Errorf("%w: %d bytes, header %d", ErrTruncated, len(data), headerBytes)
	}
	if string(data[:len(magic)]) != magic {
		return nil, fmt.Errorf("%w: the file does not begin as an entry does", ErrCorrupt)
	}
	length := int64(binary.BigEndian.Uint32(data[len(magic):]))
	if length == 0 {
		return nil, fmt.Errorf("%w: the entry claims an empty body", ErrMalformed)
	}
	if length > int64(maxBody) {
		return nil, fmt.Errorf("%w: the entry claims %d bytes, limit %d", ErrEntryTooLarge, length, maxBody)
	}
	switch end := int64(headerBytes) + length; {
	case end > int64(len(data)):
		return nil, fmt.Errorf("%w: the entry claims %d bytes and the file holds %d", ErrTruncated, length, len(data)-headerBytes)
	case end < int64(len(data)):
		return nil, fmt.Errorf("%w: %d bytes past the entry's end", ErrCorrupt, int64(len(data))-end)
	}
	body := data[headerBytes:]
	if checksum(body) != binary.BigEndian.Uint32(data[len(magic)+4:]) {
		return nil, fmt.Errorf("%w: the checksum does not match the body", ErrCorrupt)
	}
	return body, nil
}
