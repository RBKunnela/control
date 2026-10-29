// The decoders' fuzz targets. Every byte a record or a state is read from
// comes from a file anyone with write access to the directory can write.
package runs

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// withoutEachKey is raw once per key, with that key's pair removed.
func withoutEachKey(t testing.TB, raw []byte) [][]byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var out [][]byte
	for k := range m {
		cut := make(map[string]json.RawMessage, len(m))
		for k2, v := range m {
			if k2 != k {
				cut[k2] = v
			}
		}
		b, err := json.Marshal(cut)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func FuzzDecodeRecord(f *testing.F) {
	open := strings.Replace(literalRecord, `"2026-03-01T12:30:00Z"`, `""`, 1)
	root := strings.Replace(strings.Replace(open, `"root":"`+literalParent, `"root":"`+literalID, 1), `"parent":"`+literalParent, `"parent":"`, 1)
	for _, seed := range []string{literalRecord, literalRecordV1, open, root, `{}`, `null`, `{"schema_version":"2.0"}`} {
		f.Add([]byte(seed))
	}
	for _, s := range withoutEachKey(f, []byte(literalRecord)) {
		f.Add(s)
	}
	admin := new(Admin)
	f.Fuzz(func(t *testing.T, raw []byte) {
		rec, err := decodeRecord(raw)
		if err != nil {
			return
		}
		enc, err := admin.encodeRecord(rec)
		if err != nil {
			t.Fatalf("a record that decoded does not encode: %v", err)
		}
		again, err := decodeRecord(enc)
		if err != nil || again != rec {
			t.Fatalf("round trip: %+v, %v; want %+v", again, err, rec)
		}
		if enc2, err := admin.encodeRecord(again); err != nil || string(enc2) != string(enc) {
			t.Fatalf("a second encoding differs: %s", enc2)
		}
		for _, cut := range withoutEachKey(t, enc) {
			if _, err := decodeRecord(cut); !errors.Is(err, ErrMissingField) {
				t.Fatalf("a record missing a key was not refused as such: %v\n%s", err, cut)
			}
		}
	})
}

func FuzzDecodeState(f *testing.F) {
	seed := `{"schema_version":"1.0","root":"` + literalID + `","untrusted":true,"max_read":"CONFIDENTIAL"}`
	for _, s := range []string{seed, `{"schema_version":"1.9","root":"` + literalID + `","untrusted":false,"max_read":"UNKNOWN"}`, `{}`, `[]`} {
		f.Add([]byte(s))
	}
	for _, s := range withoutEachKey(f, []byte(seed)) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		root, s, err := decodeState(raw)
		if err != nil {
			return
		}
		enc, err := encodeState(root, s)
		if err != nil {
			t.Fatalf("a state that decoded does not encode: %v", err)
		}
		root2, s2, err := decodeState(enc)
		if err != nil || root2 != root || s2 != s {
			t.Fatalf("round trip: %s %+v, %v; want %s %+v", root2, s2, err, root, s)
		}
		for _, cut := range withoutEachKey(t, enc) {
			if _, _, err := decodeState(cut); !errors.Is(err, ErrMissingField) {
				t.Fatalf("a state missing a key was not refused as such: %v\n%s", err, cut)
			}
		}
	})
}
