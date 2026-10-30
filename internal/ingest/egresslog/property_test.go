package egresslog_test

import (
	"bytes"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/ingest/egresslog"
	"github.com/guardana/control/internal/observe"
)

// shaped is a line and what it must become: "" for an observation, else the
// reason it is refused for.
type shaped struct{ line, reason string }

var shapes = []shaped{
	{envoyLine("", ""), ""},
	{envoyLine("method", `"BREW"`), ""},
	{envoyLine("upstream_remote_port", "null"), ""},
	{envoyLine("server_name", `"2001:db8::7"`), ""},
	{envoyLine("downstream_remote_address", `"\u0000"`), ""},
	{"\n", "not_an_object"},
	{"[]\n", "not_an_object"},
	{"{\"a\":\"\xc3\"}\n", "not_an_object"},
	{`{"a":1,"a":2}` + "\n", "duplicate_member"},
	{envoyLine("start_time", `"-"`), "time"},
	{envoyLine("server_name", `"user@host.example"`), "destination"},
	{envoyLine("upstream_remote_port", "65536"), "port"},
	{`{"pad":"` + strings.Repeat("p", egresslog.MaxLineBytes) + `"}` + "\n", "line_too_long"},
}

// Every line of an input lands in exactly one count, whatever the mix: the
// expected counts come from the shapes' own labels, not from the importer.
func TestEveryLineLandsInOneCount(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404: a fixed seed, so a failing round can be replayed
	d := envoy(t)
	for round := range 200 {
		var in strings.Builder
		var read, observed uint64
		want := map[string]uint64{}
		for range r.IntN(20) {
			read++
			s := shapes[r.IntN(len(shapes))]
			in.WriteString(s.line)
			if s.reason == "" {
				observed++
			} else {
				want[s.reason]++
			}
		}
		if r.IntN(2) == 0 {
			in.WriteString(`{"start_time":"2026-10-04T10:00:00Z","server_name":"tail.example"}`)
		}
		b := importBytes(t, []byte(in.String()), d)
		c := b.Report.GetCounts()
		if c.GetRead() != read || c.GetObserved() != observed || !maps.Equal(c.GetRefusedBy(), want) {
			t.Fatalf("round %d: read %d observed %d refused_by %v; want %d, %d, %v",
				round, c.GetRead(), c.GetObserved(), c.GetRefusedBy(), read, observed, want)
		}
	}
}

// Nothing the mapping does not name reaches a record, nor does a mapped
// value the importer refused or dropped.
func TestNothingUnmappedIsCopied(t *testing.T) {
	in := `{"path":"/marker-path?token=marker-token","user_agent":"marker-agent","headers":{"authorization":"marker-auth"},` +
		envoyLine("", "")[1:] +
		envoyLine("bytes_sent", `{"x":"marker-bytes"}`) +
		envoyLine("method", `"MARKER"`) +
		envoyLine("server_name", `"https://marker-url.example/marker"`) +
		envoyLine("downstream_remote_address", `"marker-caller\u0007"`)
	b := importBytes(t, []byte(in), envoy(t))
	if len(b.Observations) != 4 {
		t.Fatalf("%d observations, want 4", len(b.Observations))
	}
	var out bytes.Buffer
	for _, o := range b.Observations {
		line, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_Observation{Observation: o}})
		if err != nil {
			t.Fatal(err)
		}
		out.Write(line)
	}
	line, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: b.Report}})
	if err != nil {
		t.Fatal(err)
	}
	out.Write(line)
	if s := strings.ToLower(out.String()); strings.Contains(s, "marker") {
		t.Fatalf("an unmapped or refused value reached a record:\n%s", out.String())
	}
}

// FuzzImport: any input imports without an error from a reader that cannot
// fail, every record it yields is a valid log line, and every complete line
// lands in exactly one count.
func FuzzImport(f *testing.F) {
	names, err := filepath.Glob(filepath.Join("testdata", "*.jsonl"))
	if err != nil || len(names) == 0 {
		f.Fatalf("no seeds: %v", err)
	}
	for _, name := range names {
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	for _, s := range shapes {
		f.Add([]byte(s.line))
	}
	d := envoy(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		b, err := egresslog.Import(bytes.NewReader(in), d, descSHA, received)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		checkBatch(t, in, b)
	})
}
