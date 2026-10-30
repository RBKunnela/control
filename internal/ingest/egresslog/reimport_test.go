package egresslog_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/ingest/egresslog"
	"github.com/guardana/control/internal/observelog"
)

// testLog is a fresh observation log in a directory only this account may
// enter, which the log requires.
func testLog(t *testing.T) *observelog.Log {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "log")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory, owner-only, as the log requires
		t.Fatal(err)
	}
	l, err := observelog.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return l
}

// write imports in at the given receive time and writes it to l.
func write(t *testing.T, l *observelog.Log, in []byte, at time.Time) (egresslog.Batch, observelog.Written) {
	t.Helper()
	b, err := egresslog.Import(bytes.NewReader(in), envoy(t), descSHA, at)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	checkBatch(t, in, b)
	w, err := l.Write(b.Observations, b.Report)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return b, w
}

func ids(b egresslog.Batch) []string {
	out := make([]string, len(b.Observations))
	for i, o := range b.Observations {
		out[i] = o.GetObservationId()
	}
	return out
}

func TestReimportYieldsOnlyDuplicates(t *testing.T) {
	l := testLog(t)
	in := readTestdata(t, "envoy-sni.jsonl")
	first, w := write(t, l, in, received)
	if w != (observelog.Written{Observations: 2}) {
		t.Fatalf("first import: %+v", w)
	}
	again, w := write(t, l, in, received.Add(time.Hour))
	if w != (observelog.Written{Duplicates: 2}) {
		t.Fatalf("re-import: %+v", w)
	}
	if !slices.Equal(ids(first), ids(again)) {
		t.Fatalf("ids moved: %v, then %v", ids(first), ids(again))
	}
}

// A connection's id is its mapped content, so two lines that differ only in
// a member the mapping does not name are one connection, and two that differ
// in any mapped value are two.
func TestIdentityIsTheMappedContent(t *testing.T) {
	l := testLog(t)
	same := envoyLine("", "")
	unmapped := `{"user_agent":"other/2.0",` + same[1:]
	in := same + same + unmapped +
		envoyLine("downstream_remote_address", `"10.0.0.9"`) +
		envoyLine("start_time", `"2026-10-04T10:00:00.251Z"`) +
		envoyLine("upstream_remote_port", "8443") +
		envoyLine("bytes_sent", "52012")
	_, w := write(t, l, []byte(in), received)
	if w != (observelog.Written{Observations: 5, Duplicates: 2}) {
		t.Fatalf("written %+v, want 5 connections and 2 duplicates", w)
	}
}

// Copy-truncate rotation: the proxy's file is copied aside and truncated in
// place. The copy holds what was read before, and the line the proxy was
// writing at that moment may be split across the two files.
func TestRotatedFile(t *testing.T) {
	l := testLog(t)
	l1 := envoyLine("server_name", `"one.example"`)
	l2 := envoyLine("server_name", `"two.example"`)
	l3 := envoyLine("server_name", `"three.example"`)
	l4 := envoyLine("server_name", `"four.example"`)
	head, tail := l3[:20], l3[20:]

	growing, w := write(t, l, []byte(l1+l2+head), received)
	if w != (observelog.Written{Observations: 2}) || growing.Report.GetInputBytes() != uint64(len(l1+l2)) {
		t.Fatalf("growing file: %+v, input_bytes %d", w, growing.Report.GetInputBytes())
	}
	rotated, w := write(t, l, []byte(l1+l2+head), received.Add(time.Minute))
	if w != (observelog.Written{Duplicates: 2}) || !slices.Equal(ids(rotated), ids(growing)) {
		t.Fatalf("rotated copy: %+v", w)
	}
	fresh, w := write(t, l, []byte(tail+l4), received.Add(2*time.Minute))
	c := fresh.Report.GetCounts()
	if w != (observelog.Written{Observations: 1}) || c.GetRefusedBy()["not_an_object"] != 1 ||
		fresh.Observations[0].GetSubject().GetName() != "four.example" {
		t.Fatalf("truncated file: %+v, counts %v", w, c)
	}
	// The same rotation where the proxy finished the line before the copy:
	// the copy then holds it whole, and it is new.
	l = testLog(t)
	write(t, l, []byte(l1+l2+head), received)
	if _, w := write(t, l, []byte(l1+l2+l3), received.Add(time.Minute)); w != (observelog.Written{Observations: 1, Duplicates: 2}) {
		t.Fatalf("rotated copy with the line finished: %+v", w)
	}
}
