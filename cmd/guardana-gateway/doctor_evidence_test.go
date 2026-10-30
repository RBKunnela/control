package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
)

// TestDoctorNamesTheTornTailAndLeavesIt: a spool whose last segment ends in
// five bytes no record holds keeps them through doctor, and the evidence line
// says how many bytes a start would cut rather than a bare ok.
func TestDoctorNamesTheTornTailAndLeavesIt(t *testing.T) {
	tr := newTree(t)
	sp, err := openSpool(tr.load(t))
	if err != nil {
		t.Fatal(err)
	}
	err = sp.Append(context.Background(), &controlv1.Event{
		EventId: "evt-1", Kind: controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, RequestId: "req-1",
		RunId: "run-1", ProjectId: "orders", TenantId: "acme", SchemaVersion: evidence.SchemaVersion,
	})
	if closeErr := sp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("writing the one record: %v", err)
	}
	segments, err := filepath.Glob(filepath.Join(tr.dir, "spool", "*.seg"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("the spool holds segments %v (%v), want one", segments, err)
	}
	f, err := os.OpenFile(segments[0], os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("torn!"))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	before := sizeOf(t, segments[0])

	line := doctorLine(t, tr, "ok      evidence ")
	if want := "1 segment(s), "; !strings.Contains(line, want) {
		t.Errorf("the evidence line %q does not say %q", line, want)
	}
	if want := "; a start would cut a torn tail of 5 byte(s), which this check left in place; "; !strings.Contains(line, want) {
		t.Errorf("the evidence line %q does not say %q", line, want)
	}
	if after := sizeOf(t, segments[0]); after != before {
		t.Errorf("the segment was %d bytes before doctor and is %d after", before, after)
	}
}

func sizeOf(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// TestDoctorSaysNoTailWasCut: a spool with nothing torn says so, so the
// count above is read from the spool and not printed regardless.
func TestDoctorSaysNoTailWasCut(t *testing.T) {
	line := doctorLine(t, newTree(t), "ok      evidence ")
	if want := "; a start would cut a torn tail of 0 byte(s), "; !strings.Contains(line, want) {
		t.Errorf("the evidence line %q does not say %q", line, want)
	}
}
