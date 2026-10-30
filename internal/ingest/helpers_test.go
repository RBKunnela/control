package ingest_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"testing"
)

// The fixtures are the importers' own: each kind's descriptor beside the
// input it reads.
const (
	otelFixture  = "otelgenai/testdata/descriptor.json"
	envoyFixture = "egresslog/testdata/envoy.descriptor.json"
	squidFixture = "egresslog/testdata/squid.descriptor.json"
)

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS("."), name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return b
}

var top []string

func set(path []string, key string, v any) func(map[string]any) {
	return func(m map[string]any) { member(m, path...)[key] = v }
}

func drop(path []string, key string) func(map[string]any) {
	return func(m map[string]any) { delete(member(m, path...), key) }
}

func member(m map[string]any, path ...string) map[string]any {
	for _, p := range path {
		m = m[p].(map[string]any)
	}
	return m
}

func jsonEdit(t testing.TB, doc []byte, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encoding the edited fixture: %v", err)
	}
	return out
}
