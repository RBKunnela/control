//go:build unix

package observelog

import (
	"errors"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

// egressReport is report naming source as an egress source.
func egressReport(source, received string) *observev1.ImportReport {
	r := report(received)
	r.SchemaVersion, r.Source.SourceId, r.Source.Kind = "0.3", source, observe.KindEgressAccessLog
	return r
}

// A source's records are of one kind: a write of another kind under the same
// source, tenant and project is refused, whether the log was written in this
// open or read back from its file, and the same write under another source is
// not.
func TestALogHoldsOneKindPerSource(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, dir)
	write(t, l, egressReport("agent-runtime", "2026-10-04T10:05:00Z"))
	if _, err := l.Write(nil, report("2026-10-04T10:06:00Z")); !errors.Is(err, ErrKind) {
		t.Fatalf("an OpenTelemetry report after an egress one: %v, want ErrKind", err)
	}
	if _, err := l.Write([]*observev1.Observation{observation(spanA, "read_file", "2026-10-04T10:06:00Z")}, egressReport("agent-runtime", "2026-10-04T10:06:00Z")); !errors.Is(err, ErrKind) {
		t.Fatalf("a span's observation beside an egress report: %v, want ErrKind", err)
	}
	other := report("2026-10-04T10:06:00Z")
	other.Source.SourceId = "agent-runtime-2"
	write(t, l, other)
	tenant := report("2026-10-04T10:06:00Z")
	tenant.TenantId = "tenant-b"
	write(t, l, tenant)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l = openLog(t, dir)
	if _, err := l.Write(nil, report("2026-10-04T10:07:00Z")); !errors.Is(err, ErrKind) {
		t.Fatalf("after a reopen: %v, want ErrKind", err)
	}
	if _, err := l.Write(nil, egressReport("agent-runtime-2", "2026-10-04T10:07:00Z")); !errors.Is(err, ErrKind) {
		t.Fatalf("an egress report after an OpenTelemetry one, after a reopen: %v, want ErrKind", err)
	}
	write(t, l, egressReport("agent-runtime", "2026-10-04T10:07:00Z"))
	if got := len(records(t, dir+"/"+FileName)); got != 4 {
		t.Fatalf("%d records, want the 4 written", got)
	}
}
