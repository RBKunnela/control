package approvals_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
)

// The framing, restated here from the package documentation rather than taken
// from the code under test: eight bytes of magic, a big-endian length, a
// big-endian CRC32C of the body, and the body.
const (
	frameMagic       = "APPRVREC"
	frameHeaderBytes = len(frameMagic) + 8
)

var frameTable = crc32.MakeTable(crc32.Castagnoli)

// reframe wraps body in a header this test builds itself, so a mutated record
// is one a second implementation of the format would write.
func reframe(t testing.TB, body []byte) []byte {
	t.Helper()
	out := make([]byte, frameHeaderBytes+len(body))
	copy(out, frameMagic)
	binary.BigEndian.PutUint32(out[len(frameMagic):], uint32(len(body))) //nolint:gosec // G115: a test frame is a few hundred bytes
	binary.BigEndian.PutUint32(out[len(frameMagic)+4:], crc32.Checksum(body, frameTable))
	copy(out[frameHeaderBytes:], body)
	return out
}

// bodyOf returns the body of a framed record, after checking the frame, so
// every mutation below starts from bytes this test knows are whole.
func bodyOf(t testing.TB, framed []byte) []byte {
	t.Helper()
	if len(framed) <= frameHeaderBytes || string(framed[:len(frameMagic)]) != frameMagic {
		t.Fatalf("the record on disk is not framed as the format says: %d bytes", len(framed))
	}
	length := binary.BigEndian.Uint32(framed[len(frameMagic):])
	if int(length) != len(framed)-frameHeaderBytes {
		t.Fatalf("the record claims %d bytes of body and carries %d", length, len(framed)-frameHeaderBytes)
	}
	if got := crc32.Checksum(framed[frameHeaderBytes:], frameTable); got != binary.BigEndian.Uint32(framed[len(frameMagic)+4:]) {
		t.Fatalf("the record on disk does not check")
	}
	return framed[frameHeaderBytes:]
}

// replaceInBody replaces one string inside a framed record's body and returns
// the body, unframed.
func replaceInBody(t testing.TB, framed []byte, old, replacement string) []byte {
	t.Helper()
	body := bodyOf(t, framed)
	if !bytes.Contains(body, []byte(old)) {
		t.Fatalf("the record holds no %q to replace", old)
	}
	return bytes.Replace(body, []byte(old), []byte(replacement), 1)
}

// withField sets one member of the record object, as any writer of the
// directory could.
func withField(t testing.TB, framed []byte, key string, raw string) []byte {
	t.Helper()
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(bodyOf(t, framed), &fields); err != nil {
		t.Fatalf("the record body is not one JSON object: %v", err)
	}
	if raw == "" {
		delete(fields, key)
	} else {
		fields[key] = json.RawMessage(raw)
	}
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshalling the mutated body: %v", err)
	}
	return reframe(t, out)
}

// withApprovalField sets one member of the approval inside the record.
func withApprovalField(t testing.TB, framed []byte, key, raw string) []byte {
	t.Helper()
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(bodyOf(t, framed), &fields); err != nil {
		t.Fatalf("the record body is not one JSON object: %v", err)
	}
	inner := map[string]json.RawMessage{}
	if err := json.Unmarshal(fields["approval"], &inner); err != nil {
		t.Fatalf("the approval is not one JSON object: %v", err)
	}
	inner[key] = json.RawMessage(raw)
	encoded, err := json.Marshal(inner)
	if err != nil {
		t.Fatalf("marshalling the mutated approval: %v", err)
	}
	fields["approval"] = encoded
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshalling the mutated body: %v", err)
	}
	return reframe(t, out)
}

// everyRefusal is the vocabulary a record on disk can be refused with. Each
// case below names one of them and is held to refusing that one and none of
// the others: an operator acts differently on a truncated file, a checksum
// that does not match and a field this build cannot name.
var everyRefusal = map[string]approvals.Error{
	"ErrTruncated":      approvals.ErrTruncated,
	"ErrCorrupt":        approvals.ErrCorrupt,
	"ErrUnknownField":   approvals.ErrUnknownField,
	"ErrFieldType":      approvals.ErrFieldType,
	"ErrSchemaVersion":  approvals.ErrSchemaVersion,
	"ErrMalformed":      approvals.ErrMalformed,
	"ErrNameMismatch":   approvals.ErrNameMismatch,
	"ErrRecordMismatch": approvals.ErrRecordMismatch,
	"ErrRecordTooLarge": approvals.ErrRecordTooLarge,
	"ErrApproverID":     approvals.ErrApproverID,
	"ErrReason":         approvals.ErrReason,
	"ErrDecidedAt":      approvals.ErrDecidedAt,
	"ErrExpiryWindow":   approvals.ErrExpiryWindow,
}

func TestEveryWayARecordCanLieIsItsOwnRefusal(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t testing.TB, framed []byte) []byte
		want   approvals.Error
	}{
		{"a record one byte short", func(_ testing.TB, f []byte) []byte { return f[:len(f)-1] }, approvals.ErrTruncated},
		{"a header cut in half", func(_ testing.TB, f []byte) []byte { return f[:frameHeaderBytes/2] }, approvals.ErrTruncated},
		{"a byte past the record's end", func(_ testing.TB, f []byte) []byte { return append(f, 0) }, approvals.ErrCorrupt},
		{"a body one byte apart from its checksum", func(_ testing.TB, f []byte) []byte {
			out := bytes.Clone(f)
			out[len(out)-2] ^= 0x20
			return out
		}, approvals.ErrCorrupt},
		{"another magic", func(_ testing.TB, f []byte) []byte {
			out := bytes.Clone(f)
			out[0] ^= 0xff
			return out
		}, approvals.ErrCorrupt},
		{"a length past the bound", func(_ testing.TB, f []byte) []byte {
			out := bytes.Clone(f)
			binary.BigEndian.PutUint32(out[len(frameMagic):], 1<<30)
			return out
		}, approvals.ErrRecordTooLarge},
		{"a file past the bound", func(t testing.TB, _ []byte) []byte {
			return reframe(t, bytes.Repeat([]byte("x"), approvals.DefaultMaxRecordBytes+1))
		}, approvals.ErrRecordTooLarge},
		{"an empty body", func(t testing.TB, _ []byte) []byte { return reframe(t, nil) }, approvals.ErrMalformed},
		{"a body that is not an object", func(t testing.TB, _ []byte) []byte { return reframe(t, []byte("[1,2,3]")) }, approvals.ErrMalformed},
		{"an unknown field", func(t testing.TB, f []byte) []byte { return withField(t, f, "approved_by", `"someone"`) }, approvals.ErrUnknownField},
		// encoding/json keeps the last of two members of one name, so a
		// second one would make the record read two ways.
		{"a field given twice, the first saying another approval", func(t testing.TB, f []byte) []byte {
			return reframe(t, replaceInBody(t, f, `{"schema_version"`, `{"approval_id":"APPROVAL9","schema_version"`))
		}, approvals.ErrMalformed},
		{"a field given twice with one value", func(t testing.TB, f []byte) []byte {
			return reframe(t, replaceInBody(t, f, `{"schema_version"`, `{"request_id":"req-1","schema_version"`))
		}, approvals.ErrMalformed},
		{"a wrong-typed field", func(t testing.TB, f []byte) []byte { return withField(t, f, "request_id", `7`) }, approvals.ErrFieldType},
		{"a schema version from a later major", func(t testing.TB, f []byte) []byte {
			return withField(t, f, "schema_version", `"3.0"`)
		}, approvals.ErrSchemaVersion},
		{"a schema version from the earlier major", func(t testing.TB, f []byte) []byte {
			return withField(t, f, "schema_version", `"1.0"`)
		}, approvals.ErrSchemaVersion},
		{"no schema version at all", func(t testing.TB, f []byte) []byte { return withField(t, f, "schema_version", `""`) }, approvals.ErrSchemaVersion},
		{"an approval from a later major", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "schemaVersion", `"9.0"`)
		}, approvals.ErrSchemaVersion},
		{"an approval with no schema version", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "schemaVersion", `""`)
		}, approvals.ErrSchemaVersion},
		{"the resolution a 1.0 record carried", func(t testing.TB, f []byte) []byte {
			return reframe(t, replaceInBody(t, f, `"binding":`, `"resolution":"consumed","binding":`))
		}, approvals.ErrUnknownField},
		{"an approval naming another approval", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "approvalId", `"APPROVAL9"`)
		}, approvals.ErrRecordMismatch},
		{"an approval naming another request", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "requestId", `"req-9"`)
		}, approvals.ErrRecordMismatch},
		{"an action digest a byte apart", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "actionDigest",
				`"sha256:0000000000000000000000000000000000000000000000000000000000000000"`)
		}, approvals.ErrRecordMismatch},
		{"a bundle digest a byte apart", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "policyBundleDigest",
				`"sha256:1111111111111111111111111111111111111111111111111111111111111112"`)
		}, approvals.ErrRecordMismatch},
		{"an unknown field inside the approval", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "approvedBy", `"someone"`)
		}, approvals.ErrMalformed},
		// What Answer bounds on the way in, the decoder bounds on the way
		// back: a record written straight into the directory reaches an
		// evidence event otherwise, and nothing downstream reads payloads.
		{"a reason one byte past the bound", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "reason", mustJSON(t, strings.Repeat("a", approvals.MaxReasonBytes+1)))
		}, approvals.ErrReason},
		{"a reason holding a control character", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "reason", `"signed\u0000off"`)
		}, approvals.ErrReason},
		{"a reason ending a line of a listing", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "reason", `"signed off\napproved by nobody"`)
		}, approvals.ErrReason},
		{"an approver id one byte past the bound", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "approverId", mustJSON(t, strings.Repeat("a", approvals.MaxApproverIDBytes+1)))
		}, approvals.ErrApproverID},
		{"an approver id holding a refused code point", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "approverId", `"approver\u0000one"`)
		}, approvals.ErrApproverID},
		{"a decision before the request", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "decidedAt", `"2021-03-01T12:00:00Z"`)
		}, approvals.ErrDecidedAt},
		{"a decision after the expiry", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "decidedAt", `"2026-03-01T12:15:00.000000001Z"`)
		}, approvals.ErrDecidedAt},
		{"an expiry further out than the plane could mint", func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "expiresAt", `"2027-03-01T12:00:00Z"`)
		}, approvals.ErrExpiryWindow},
		{"a record renamed inside and out of step with its file", func(t testing.TB, f []byte) []byte {
			body := replaceInBody(t, f, `"approval_id":"APPROVAL1"`, `"approval_id":"APPROVAL9"`)
			return reframe(t, bytes.Replace(body, []byte(`"approvalId":"APPROVAL1"`), []byte(`"approvalId":"APPROVAL9"`), 1))
		}, approvals.ErrNameMismatch},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, dir := openPlane(t)
			h := held(t, "APPROVAL1", "req-1")
			if err := p.Hold(t.Context(), h, minted); err != nil {
				t.Fatalf("holding: %v", err)
			}
			const name = "APPROVAL1.0-held.rec"
			good := readFile(t, dir, name)
			if _, err := p.Find(t.Context(), h.Binding, minted); err != nil && !errors.Is(err, approvals.ErrNoApproval) {
				t.Fatalf("the record was unreadable before the mutation: %v", err)
			}
			writeFile(t, dir, name, c.mutate(t, good))
			_, err := p.Find(t.Context(), h.Binding, minted)
			if err == nil {
				t.Fatalf("%s was read as a record", c.name)
			}
			assertOnly(t, err, c.want)
		})
	}
}

// assertOnly holds a refusal to exactly one sentinel: the one the case names,
// and none of the others. A refusal that matched two of them would leave a
// caller unable to say what an operator has to fix.
func assertOnly(t *testing.T, err error, want approvals.Error) {
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

// TestARefusalQuotesNoControlCharacterAndNoUnboundedRun: a refusal about a
// forged record is read on a terminal and written to a log.
func TestARefusalQuotesNoControlCharacterAndNoUnboundedRun(t *testing.T) {
	p, dir := openPlane(t)
	h := held(t, "APPROVAL1", "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	hostile := strings.Repeat("A", 4000) + "\x1b[2J\x07"
	body := replaceInBody(t, readFile(t, dir, "APPROVAL1.0-held.rec"), `"schema_version":"2.1"`,
		`"schema_version":`+mustJSON(t, hostile))
	writeFile(t, dir, "APPROVAL1.0-held.rec", reframe(t, body))
	_, err := p.Find(t.Context(), h.Binding, minted)
	if err == nil {
		t.Fatal("a schema version nothing names was read as a record")
	}
	text := err.Error()
	if strings.ContainsAny(text, "\x00\x07\x1b\n\r") {
		t.Errorf("the refusal carries a control character: %q", text)
	}
	if len(text) > 1000 {
		t.Errorf("the refusal is %d bytes of a forged record's own text", len(text))
	}
}

func mustJSON(t testing.TB, s string) string {
	t.Helper()
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return string(out)
}

// findMutated writes body over the held record of a fresh store and returns
// what Find makes of it, so a bound can be named by the input at which the
// answer changes.
func findMutated(t *testing.T, opts []approvals.Option, mutate func(testing.TB, []byte) []byte) error {
	t.Helper()
	p, dir := openPlane(t, opts...)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	const name = "APPROVAL1.0-held.rec"
	writeFile(t, dir, name, mutate(t, readFile(t, dir, name)))
	_, err := p.Find(t.Context(), h.Binding, minted)
	return err
}

// TestTheTextBoundsAreReadAtTheBoundAndRefusedOneByteOver. The refusals are in
// the table above; what stands here is the input one byte under each of them,
// which a bound that bit too early would refuse.
func TestTheTextBoundsAreReadAtTheBoundAndRefusedOneByteOver(t *testing.T) {
	cases := map[string]func(testing.TB, []byte) []byte{
		"a reason of exactly the bound": func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "reason", mustJSON(t, strings.Repeat("a", approvals.MaxReasonBytes)))
		},
		"an approver id of exactly the bound": func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "approverId", mustJSON(t, strings.Repeat("a", approvals.MaxApproverIDBytes)))
		},
		"a decision at the request's own time": func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "decidedAt", `"2026-03-01T12:00:00Z"`)
		},
		"a decision one nanosecond before the expiry": func(t testing.TB, f []byte) []byte {
			return withApprovalField(t, f, "decidedAt", `"2026-03-01T12:14:59.999999999Z"`)
		},
	}
	for name, mutate := range cases {
		if err := findMutated(t, nil, mutate); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}

// TestTheApprovalWindowBoundsHowLongAForgedRecordStands. The fixture's expiry
// is fifteen minutes from its request, so a window of exactly that reads it
// and one nanosecond more does not. It is the same bound in both directions:
// a plane cannot mint what it would refuse to read.
func TestTheApprovalWindowBoundsHowLongAForgedRecordStands(t *testing.T) {
	const window = 15 * time.Minute
	atTheBound := []approvals.Option{approvals.WithMaxApprovalWindow(window)}
	if err := findMutated(t, atTheBound, func(_ testing.TB, f []byte) []byte { return f }); err != nil {
		t.Errorf("an expiry at the window was refused: %v", err)
	}
	err := findMutated(t, atTheBound, func(t testing.TB, f []byte) []byte {
		return withApprovalField(t, f, "expiresAt", `"2026-03-01T12:15:00.000000001Z"`)
	})
	if !errors.Is(err, approvals.ErrExpiryWindow) {
		t.Errorf("one nanosecond past the window = %v, want ErrExpiryWindow", err)
	}

	narrow, _ := openPlane(t, approvals.WithMaxApprovalWindow(window-time.Nanosecond))
	if err := narrow.Hold(t.Context(), held(t, firstApproval, "req-1"), minted); !errors.Is(err, approvals.ErrExpiryWindow) {
		t.Errorf("holding past the plane's own window = %v, want ErrExpiryWindow", err)
	}
	if _, err := approvals.OpenPlane(t.TempDir(), approvals.WithMaxApprovalWindow(0)); !errors.Is(err, approvals.ErrInvalidOption) {
		t.Errorf("a window of zero = %v, want ErrInvalidOption", err)
	}
}
