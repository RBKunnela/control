// The ledger mark decoder's fuzz target, an internal test for the reason
// FuzzEntry is one.
package holdjournal

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// markSeeds are a mark as this build writes one and the ways its frame and
// body go wrong, the body ones framed so they reach the decoder.
func markSeeds(t testing.TB) [][]byte {
	t.Helper()
	valid, err := encodeMark(LedgerEntry{
		SchemaVersion: LedgerSchemaVersion, Mark: MarkConsumed, Binding: "bind-1",
		RequestID: "req-1", ApprovalID: "appr-1", Proof: "duty-officer",
		Written: time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
	}, DefaultMaxEntryBytes)
	if err != nil {
		t.Fatalf("encoding the seed: %v", err)
	}
	body := valid[headerBytes:]
	framed := func(old, with string) []byte {
		b := bytes.Replace(body, []byte(old), []byte(with), 1)
		out := make([]byte, headerBytes+len(b))
		copy(out, ledgerMagic)
		binary.BigEndian.PutUint32(out[len(ledgerMagic):], uint32(len(b))) //nolint:gosec // G115: a seed is small
		binary.BigEndian.PutUint32(out[len(ledgerMagic)+4:], checksum(b))
		copy(out[headerBytes:], b)
		return out
	}
	return [][]byte{
		valid,
		valid[:len(valid)-1],
		append(bytes.Clone(valid), 0),
		framed(`"mark":"consumed"`, `"mark":"not_resumed"`),
		framed(`"proof":"duty-officer"`, `"proof":""`),
		framed(`"written":"2026-03-01T12:00:00Z"`, `"written":"2026-03-01T12:00:00.000Z"`),
		framed(`"request_id":"req-1"`, `"request_id":""`),
		framed(`"schema_version":"1.0"`, `"schema_version":"2.0"`),
		framed(`"binding"`, `"bindinx"`),
		nil,
	}
}

// FuzzLedgerMark holds the mark decoder to three things over any bytes: it
// does not crash, a refusal hands back no mark, and what it accepts is a mark
// this build knows that round-trips through the encoder unchanged.
func FuzzLedgerMark(f *testing.F) {
	for _, seed := range markSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := decodeMark(data, DefaultMaxEntryBytes)
		if err != nil {
			if e != (LedgerEntry{}) {
				t.Fatalf("a refused mark handed back %+v", e)
			}
			return
		}
		holdMark(t, e)
	})
}

// holdMark holds an accepted mark to being one this build knows, named as
// this package names one, and to surviving a round trip unchanged.
func holdMark(t *testing.T, e LedgerEntry) {
	t.Helper()
	if e.Mark != MarkConsumed && e.Mark != MarkNotResumed {
		t.Fatalf("an accepted mark is %v", e.Mark)
	}
	if !isMarkName(markName(e.Binding, e.RequestID, e.ApprovalID, e.Mark)) {
		t.Fatalf("an accepted mark's name is not one this package writes")
	}
	again, err := encodeMark(e, DefaultMaxEntryBytes)
	if err != nil {
		t.Fatalf("a mark that decoded will not encode: %v", err)
	}
	back, err := decodeMark(again, DefaultMaxEntryBytes)
	if err != nil || back.Written.Compare(e.Written) != 0 || back.Mark != e.Mark || back.Binding != e.Binding ||
		back.RequestID != e.RequestID || back.ApprovalID != e.ApprovalID || back.Proof != e.Proof {
		t.Fatalf("the round trip changed the mark: %+v then %+v, %v", e, back, err)
	}
}
