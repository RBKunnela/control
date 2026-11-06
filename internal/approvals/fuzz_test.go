// The decoder's fuzz target. It is an internal test because the decoder is
// what has to hold, not the directory around it: every byte a record is read
// from comes from a file anyone with write access to the directory can write.
package approvals

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core/approval"
)

const (
	fuzzActionDigest = "sha256:" + "abababababababababababababababababababababababababababababababab"
	fuzzBundleDigest = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
)

// seedRecord is one record as this build writes it.
func seedRecord(t testing.TB) []byte {
	t.Helper()
	binding, err := canon.ApprovalBinding(fuzzActionDigest, fuzzBundleDigest)
	if err != nil {
		t.Fatalf("binding the seed: %v", err)
	}
	minted := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	raw, err := encodeRecord(Record{
		SchemaVersion: SchemaVersion,
		ApprovalID:    "APPROVAL1",
		RequestID:     "req-1",
		Binding:       approval.Binding(binding),
		Authority:     HeldUnderSigned,
		Tenant:        "tenant-1",
		Project:       "proj-1",
		Approval: &controlv1.Approval{
			SchemaVersion:      "1.0",
			ApprovalId:         "APPROVAL1",
			RequestId:          "req-1",
			ActionDigest:       fuzzActionDigest,
			PolicyBundleDigest: fuzzBundleDigest,
			State:              controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
			ApproverId:         "approver-1",
			Reason:             "signed off",
			RequestedAt:        timestamppb.New(minted),
			DecidedAt:          timestamppb.New(minted.Add(time.Minute)),
			ExpiresAt:          timestamppb.New(minted.Add(15 * time.Minute)),
		},
	}, DefaultMaxRecordBytes, DefaultMaxApprovalWindow)
	if err != nil {
		t.Fatalf("encoding the seed: %v", err)
	}
	return raw
}

// withBody frames body the way a writer of the directory would: the length and
// the checksum are taken over the bytes handed in, so whatever body arrives
// reaches the decoder rather than dying at the frame.
func withBody(body []byte) []byte {
	out := make([]byte, headerBytes+len(body))
	copy(out, magic)
	binary.BigEndian.PutUint32(out[len(magic):], uint32(len(body))) //nolint:gosec // G115: a fuzz input is far below the field
	binary.BigEndian.PutUint32(out[len(magic)+4:], checksum(body))
	copy(out[headerBytes:], body)
	return out
}

// recordSeeds are inputs shaped like records rather than like noise. A mutant
// a scan stops on is reached only from an input whose length field is
// plausible and whose body is nearly right, and random bytes do not reach one.
func recordSeeds(t testing.TB) [][]byte {
	t.Helper()
	valid := seedRecord(t)
	return append(bodySeeds(valid[headerBytes:]), frameSeeds(valid)...)
}

// bodySeeds are record bodies. The target frames them for itself, so each one
// arrives at the body's own decoder, and each is a near miss of what this
// build writes: one decoder refusal apiece, and one body that is accepted so
// that a mutation of it starts from a record that decodes.
func bodySeeds(body []byte) [][]byte {
	swap := func(old, with string) []byte { return bytes.Replace(body, []byte(old), []byte(with), 1) }
	return [][]byte{
		body,
		swap(`"request_id":"req-1",`, ``),
		swap(`"request_id":"req-1"`, `"request_id":""`),
		swap(`"request_id":"req-1"`, `"request_id":"req-2"`),
		swap(`"binding"`, `"bindinx"`),
		swap(`"binding":"sha256:7e`, `"binding":"sha256:0e`),
		swap(`"binding":"sha256:7e5557df4a97ec3c5df3a67c879ffe3799c820636914f7b010bf6eac312a7aaa"`, `"binding":""`),
		swap(`"schema_version":"2.1"`, `"schema_version":"1.0"`),
		swap(`"schema_version":"2.1"`, `"schema_version":"3.0"`),
		swap(`"schema_version":"2.1"`, `"schema_version":2`),
		swap(`"schema_version":"2.1"`, `"schema_version":"2.0"`),
		swap(`"authority":"signed"`, `"authority":"anyone"`),
		swap(`,"authority":"signed"`, ``),
		swap(`"tenant":"tenant-1"`, `"tenant":""`),
		swap(`"binding":`, `"resolution":"consumed","binding":`),
		swap(`"approval_id":"APPROVAL1"`, `"approval_id":"../elsewhere"`),
		swap(`"approvalId":"APPROVAL1"`, `"approvalId":"APPROVAL2"`),
		swap(`"approvalId"`, `"approvalIdx"`),
		swap(`"actionDigest":"sha256:`, `"actionDigest":"md5:`),
		swap(`"approverId":"approver-1"`, `"approverId":"approver 1"`),
		swap(`"reason":"signed off"`, `"reason":"signed\noff"`),
		swap(`"expiresAt":"2026-03-01T12:15:00Z"`, `"expiresAt":"2036-03-01T12:15:00Z"`),
		swap(`"decidedAt":"2026-03-01T12:01:00Z"`, `"decidedAt":"2025-03-01T12:01:00Z"`),
		[]byte(`{"schema_version":"3.0"}`),
		[]byte("a body that is not a JSON object at all"),
		nil,
	}
}

// frameSeeds are whole files, which the target also puts through as they
// stand: a frame that does not check is refused, and that refusal is a
// property in its own right.
func frameSeeds(valid []byte) [][]byte {
	body := valid[headerBytes:]
	trailing := append(bytes.Clone(valid), 0)
	// A plausible length, and a body one byte apart from its checksum: the
	// offset a scan would stop at is exactly the end of this record.
	flipped := bytes.Clone(valid)
	flipped[len(flipped)-2] ^= 0x20
	// A length field that claims one byte more than the body carries.
	overlong := bytes.Clone(valid)
	binary.BigEndian.PutUint32(overlong[len(magic):], uint32(len(body)+1)) //nolint:gosec // G115: a seed is a few hundred bytes
	// A length field past the bound, which is refused before the file's own
	// size is ever looked at.
	overBound := bytes.Clone(valid)
	binary.BigEndian.PutUint32(overBound[len(magic):], uint32(DefaultMaxRecordBytes+1))

	return [][]byte{
		valid,
		bytes.Clone(valid)[:len(valid)-1],
		trailing,
		flipped,
		overlong,
		overBound,
		[]byte(magic),
		[]byte(strings.Repeat("A", headerBytes)),
		nil,
	}
}

// FuzzRecord holds the decoder to three things over any bytes at all: it does
// not crash, it hands back nothing at all when it refuses, and what it accepts
// survives a round trip through the encoder.
//
// Every input is put through twice. The frame carries a CRC32C the body has to
// match, which no mutation of a whole file arrives at, so a target that only
// fed raw bytes would leave everything past the frame unreached; framing the
// fuzzer's bytes as a body is what puts the record's own decoder under it. The
// raw pass stays because refusing a frame that does not check is a property
// worth holding too.
func FuzzRecord(f *testing.F) {
	for _, seed := range recordSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		holdsDecoder(t, withBody(data))
		holdsDecoder(t, data)
	})
}

// holdsDecoder puts one whole file through the decoder and holds what comes
// back to what the package promises about it.
func holdsDecoder(t *testing.T, file []byte) {
	t.Helper()
	rec, err := decodeRecord(file, DefaultMaxRecordBytes, DefaultMaxApprovalWindow)
	if err != nil {
		if rec.ApprovalID != "" || rec.Approval != nil || rec.Binding != "" {
			t.Fatalf("a refused record handed back %+v", rec)
		}
		return
	}
	// Whatever was accepted names a file this package may write, so no input
	// can put a record outside the directory.
	if err := checkApprovalID(rec.ApprovalID); err != nil {
		t.Fatalf("an accepted record names %q: %v", rec.ApprovalID, err)
	}
	if rec.SchemaVersion != SchemaVersion {
		t.Fatalf("an accepted record is of version %q", rec.SchemaVersion)
	}
	roundTrip(t, rec)
}

// roundTrip holds an accepted record to encoding and decoding back to itself.
func roundTrip(t *testing.T, rec Record) {
	t.Helper()
	again, err := encodeRecord(rec, DefaultMaxRecordBytes, DefaultMaxApprovalWindow)
	if err != nil {
		t.Fatalf("a record that decoded will not encode: %v", err)
	}
	back, err := decodeRecord(again, DefaultMaxRecordBytes, DefaultMaxApprovalWindow)
	if err != nil {
		t.Fatalf("a record this build wrote will not decode: %v", err)
	}
	if back.ApprovalID != rec.ApprovalID || back.RequestID != rec.RequestID ||
		back.Binding != rec.Binding ||
		!proto.Equal(back.Approval, rec.Approval) {
		t.Fatalf("the round trip changed the record: %+v then %+v", rec, back)
	}
}
