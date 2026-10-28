// The decoder's tests are internal, because what has to hold is the decoder
// itself: every byte an entry is read from comes off a disk this process may
// not have written whole.
package holdjournal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
)

// seedEntry is one entry as this build writes it.
func seedEntry() Entry {
	minted := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	return Entry{
		SchemaVersion: SchemaVersion,
		State:         StateHeld,
		IDs: evidence.IDs{
			RequestID: "req-1", RunID: "run-1", ProjectID: "proj-1", TenantID: "tenant-1",
		},
		LastEventID: "evt-1",
		Binding:     approval.Binding("sha256:aaaa|sha256:bbbb"),
		Approval: &controlv1.Approval{
			SchemaVersion: "1.0",
			ApprovalId:    "appr-1",
			RequestId:     "req-1",
			State:         controlv1.ApprovalState_APPROVAL_STATE_PENDING,
			RequestedAt:   timestamppb.New(minted),
			ExpiresAt:     timestamppb.New(minted.Add(15 * time.Minute)),
		},
		Expires: minted.Add(15 * time.Minute),
	}
}

// seedBytes is that entry framed.
func seedBytes(t testing.TB) []byte {
	t.Helper()
	raw, err := encodeEntry(seedEntry(), DefaultMaxEntryBytes)
	if err != nil {
		t.Fatalf("encoding the seed: %v", err)
	}
	return raw
}

// withBody frames body the way a writer of the directory would, so an input
// that changes the body still has a header that checks.
func withBody(body []byte) []byte {
	out := make([]byte, headerBytes+len(body))
	copy(out, magic)
	binary.BigEndian.PutUint32(out[len(magic):], uint32(len(body))) //nolint:gosec // G115: a test body is small
	binary.BigEndian.PutUint32(out[len(magic)+4:], checksum(body))
	copy(out[headerBytes:], body)
	return out
}

// everyRefusal is this package's whole vocabulary. A refusal is held against
// all of it, so a decoder that answers with two sentinels at once is caught
// even when the second one belongs to the directory rather than to the entry.
var everyRefusal = map[string]Error{
	"ErrEntry":          ErrEntry,
	"ErrRecorded":       ErrRecorded,
	"ErrNoEntry":        ErrNoEntry,
	"ErrFlip":           ErrFlip,
	"ErrMaybeRecorded":  ErrMaybeRecorded,
	"ErrClosed":         ErrClosed,
	"ErrReadOnly":       ErrReadOnly,
	"ErrLocked":         ErrLocked,
	"ErrNoLock":         ErrNoLock,
	"ErrPermissions":    ErrPermissions,
	"ErrNotAJournal":    ErrNotAJournal,
	"ErrForeignFile":    ErrForeignFile,
	"ErrTooManyEntries": ErrTooManyEntries,
	"ErrInvalidOption":  ErrInvalidOption,
	"ErrEntryTooLarge":  ErrEntryTooLarge,
	"ErrTruncated":      ErrTruncated,
	"ErrCorrupt":        ErrCorrupt,
	"ErrUnknownField":   ErrUnknownField,
	"ErrFieldType":      ErrFieldType,
	"ErrSchemaVersion":  ErrSchemaVersion,
	"ErrMalformed":      ErrMalformed,
	"ErrNameMismatch":   ErrNameMismatch,
	"ErrRequestName":    ErrRequestName,
}

// assertOnly holds a refusal to exactly one sentinel: the one the case names,
// and none of the others. A refusal that matched two of them would leave an
// operator unable to say what has to be repaired.
func assertOnly(t *testing.T, err error, want Error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("refusal %v, want %v", err, want)
	}
	for name, other := range everyRefusal {
		if other != want && errors.Is(err, other) {
			t.Errorf("the refusal also reads as %s: %v", name, err)
		}
	}
}

// TestTheDecoderTellsItsRefusalsApart: an operator repairs a truncated file, a
// corrupted one and one from a build they do not have differently, so none of
// them may arrive as the same refusal, and none of them as an empty entry.
func TestTheDecoderTellsItsRefusalsApart(t *testing.T) {
	valid := seedBytes(t)
	body := valid[headerBytes:]
	trailing := append(bytes.Clone(valid), 0)
	badChecksum := bytes.Clone(valid)
	badChecksum[len(badChecksum)-1] ^= 0x20
	overlong := bytes.Clone(valid)
	binary.BigEndian.PutUint32(overlong[len(magic):], uint32(len(body)+1)) //nolint:gosec // G115: a seed is a few hundred bytes
	claimsTooMuch := bytes.Clone(valid)
	binary.BigEndian.PutUint32(claimsTooMuch[len(magic):], uint32(DefaultMaxEntryBytes+1))

	cases := map[string]struct {
		data []byte
		want Error
	}{
		"nothing at all":                 {nil, ErrTruncated},
		"a header and no body":           {[]byte(magic + strings.Repeat("\x00", 8)), ErrMalformed},
		"one byte short":                 {valid[:len(valid)-1], ErrTruncated},
		"a length past the file's end":   {overlong, ErrTruncated},
		"a length past the bound":        {claimsTooMuch, ErrEntryTooLarge},
		"bytes past the entry's end":     {trailing, ErrCorrupt},
		"a body that does not check":     {badChecksum, ErrCorrupt},
		"a file that is not an entry":    {bytes.Repeat([]byte("."), headerBytes+16), ErrCorrupt},
		"a body that is not an object":   {withBody([]byte(`["an entry"]`)), ErrMalformed},
		"a major nobody reads":           {withBody(bytes.Replace(body, []byte(`"schema_version":"1.0"`), []byte(`"schema_version":"2.0"`), 1)), ErrSchemaVersion},
		"no schema version":              {withBody(bytes.Replace(body, []byte(`"schema_version":"1.0"`), []byte(`"schema_version":""`), 1)), ErrSchemaVersion},
		"a field this build cannot name": {withBody(bytes.Replace(body, []byte(`"binding"`), []byte(`"bindinx"`), 1)), ErrUnknownField},
		"a field of another type":        {withBody(bytes.Replace(body, []byte(`"last_event_id":"evt-1"`), []byte(`"last_event_id":7`), 1)), ErrFieldType},
		"a state nobody knows":           {withBody(bytes.Replace(body, []byte(`"state":"held"`), []byte(`"state":"unknown"`), 1)), ErrMalformed},
		"an expiry that is not a time":   {withBody(bytes.Replace(body, []byte(`"expires":"2026-03-01T12:15:00Z"`), []byte(`"expires":"soon"`), 1)), ErrMalformed},
		// encoding/json keeps the last of two members of one name, so a
		// reader keeping the first would read another entry from the bytes.
		"a state given twice": {
			withBody(bytes.Replace(body, []byte(`{"schema_version"`), []byte(`{"state":"resuming","schema_version"`), 1)), ErrMalformed,
		},
		"a member given twice with one value": {
			withBody(bytes.Replace(body, []byte(`{"schema_version"`), []byte(`{"request_id":"req-1","schema_version"`), 1)), ErrMalformed,
		},
		"a member in capitals": {
			withBody(bytes.Replace(body, []byte(`"state":"held"`), []byte(`"STATE":"held"`), 1)), ErrUnknownField,
		},
		// The expiry is read in one spelling, the one the encoder writes.
		"an expiry with a numeric zone": {
			withBody(bytes.Replace(body, []byte(`"expires":"2026-03-01T12:15:00Z"`), []byte(`"expires":"2026-03-01T12:15:00+00:00"`), 1)), ErrMalformed,
		},
		"an expiry in another zone": {
			withBody(bytes.Replace(body, []byte(`"expires":"2026-03-01T12:15:00Z"`), []byte(`"expires":"2026-03-01T13:15:00+01:00"`), 1)), ErrMalformed,
		},
		"an expiry with trailing zeros": {
			withBody(bytes.Replace(body, []byte(`"expires":"2026-03-01T12:15:00Z"`), []byte(`"expires":"2026-03-01T12:15:00.000Z"`), 1)), ErrMalformed,
		},
		"an approval this build cannot read": {
			withBody(bytes.Replace(body, []byte(`"approvalId"`), []byte(`"approvalIx"`), 1)), ErrMalformed,
		},
		"an approval of a major nobody reads": {
			withBody(bytes.Replace(body, []byte(`"schemaVersion":"1.0"`), []byte(`"schemaVersion":"2.0"`), 1)), ErrSchemaVersion,
		},
		"an approval with no schema version": {
			withBody(bytes.Replace(body, []byte(`"schemaVersion":"1.0",`), nil, 1)), ErrSchemaVersion,
		},
		"an approval naming another request": {
			withBody(bytes.Replace(body, []byte(`"requestId":"req-1"`), []byte(`"requestId":"req-2"`), 1)), ErrEntry,
		},
		"an approval in a state nobody knows": {
			withBody(bytes.Replace(body, []byte(`"state":"APPROVAL_STATE_PENDING"`), []byte(`"state":99`), 1)), ErrMalformed,
		},
		"a request id that cannot name a file": {
			withBody(bytes.Replace(body, []byte(`"request_id":"req-1"`), []byte(`"request_id":""`), 1)), ErrRequestName,
		},
		"no position on the trail": {
			withBody(bytes.Replace(body, []byte(`"last_event_id":"evt-1"`), []byte(`"last_event_id":""`), 1)), ErrEntry,
		},
	}
	for _, v := range []string{"1.", "1.x", "1.0.0", "1.-3", "1.+3", "01.0", " 1.0"} {
		cases["the version "+v] = struct {
			data []byte
			want Error
		}{withBody(bytes.Replace(body, []byte(`"schema_version":"1.0"`), []byte(`"schema_version":"`+v+`"`), 1)), ErrSchemaVersion}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			entry, err := decodeEntry(tc.data, DefaultMaxEntryBytes)
			assertOnly(t, err, tc.want)
			if entry.State != StateUnknown || entry.Approval != nil || entry.IDs.RequestID != "" {
				t.Fatalf("a refused entry handed back %+v", entry)
			}
		})
	}
	// The same bytes, undamaged, decode: no case above passed because the
	// seed itself was unreadable.
	if _, err := decodeEntry(valid, DefaultMaxEntryBytes); err != nil {
		t.Fatalf("the undamaged seed was refused: %v", err)
	}
}

// TestAnEntryRoundTripsThroughItsEncoding: every field this build writes comes
// back, in every state an entry can stand in.
func TestAnEntryRoundTripsThroughItsEncoding(t *testing.T) {
	for _, state := range []State{StateHeld, StateResuming, StateClosing} {
		entry := seedEntry()
		entry.State = state
		raw, err := encodeEntry(entry, DefaultMaxEntryBytes)
		if err != nil {
			t.Fatalf("encoding an entry in %v: %v", state, err)
		}
		back, err := decodeEntry(raw, DefaultMaxEntryBytes)
		if err != nil {
			t.Fatalf("decoding an entry in %v: %v", state, err)
		}
		switch {
		case back.State != state:
			t.Fatalf("the state came back as %v, want %v", back.State, state)
		case back.IDs != entry.IDs:
			t.Fatalf("the ids came back as %+v", back.IDs)
		case back.LastEventID != "evt-1" || back.Binding != approval.Binding("sha256:aaaa|sha256:bbbb"):
			t.Fatalf("the position came back as %q under %q", back.LastEventID, back.Binding)
		case !back.Expires.Equal(entry.Expires):
			t.Fatalf("the expiry came back as %v", back.Expires)
		case !proto.Equal(back.Approval, entry.Approval):
			t.Fatalf("the approval came back as %v", back.Approval)
		}
	}
}

// TestTheEncoderWritesNothingItsDecoderWouldRefuse: an entry that does not
// check never reaches a file.
func TestTheEncoderWritesNothingItsDecoderWouldRefuse(t *testing.T) {
	damaged := seedEntry()
	damaged.LastEventID = ""
	if _, err := encodeEntry(damaged, DefaultMaxEntryBytes); !errors.Is(err, ErrEntry) {
		t.Fatalf("encoding an entry with no position: %v, want ErrEntry", err)
	}
	for _, v := range []string{"2.0", ""} {
		other := seedEntry()
		other.Approval.SchemaVersion = v
		if _, err := encodeEntry(other, DefaultMaxEntryBytes); !errors.Is(err, ErrSchemaVersion) {
			t.Fatalf("encoding an entry whose approval is %q: %v, want ErrSchemaVersion", v, err)
		}
	}
	if _, err := encodeEntry(seedEntry(), 32); !errors.Is(err, ErrEntryTooLarge) {
		t.Fatalf("encoding an entry over the bound: %v, want ErrEntryTooLarge", err)
	}
}
