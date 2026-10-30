package observe_test

import (
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var heardBase = time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)

func liveDescriptor() *observev1.SourceDescriptor {
	return &observev1.SourceDescriptor{SourceId: "s1", Kind: observe.KindOTelGenAI, TenantId: "t1", ProjectId: "p1", HeartbeatSeconds: 60}
}

// heardReport is an import report of source in tenant and project whose
// latest event and receive times are latest and received past heardBase; a
// negative offset leaves that time out.
func heardReport(source, tenant, project string, latest, received time.Duration) *observev1.Record {
	rep := &observev1.ImportReport{TenantId: tenant, ProjectId: project, Source: &observev1.SourceRef{SourceId: source}}
	if latest >= 0 {
		rep.LatestEventTime = timestamppb.New(heardBase.Add(latest))
	}
	if received >= 0 {
		rep.ReceivedTime = timestamppb.New(heardBase.Add(received))
	}
	return &observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: rep}}
}

// kindReport is rec with its source naming kind.
func kindReport(rec *observev1.Record, kind string) *observev1.Record {
	rec.GetImportReport().Source.Kind = kind
	return rec
}

// TestLastHeardCountsOnlyTheSourcesOwnReports: a report of another source,
// tenant, project or kind, or one without both times, is not the source heard; an
// event time after its receive time is taken as the receive time.
func TestLastHeardCountsOnlyTheSourcesOwnReports(t *testing.T) {
	cases := []struct {
		name  string
		rec   *observev1.Record
		heard bool
		last  time.Duration
	}{
		{"its own report", heardReport("s1", "t1", "p1", 10*time.Second, 20*time.Second), true, 10 * time.Second},
		{"an event time past its receive time", heardReport("s1", "t1", "p1", 30*time.Second, 20*time.Second), true, 20 * time.Second},
		{"another source", heardReport("s2", "t1", "p1", 10*time.Second, 20*time.Second), false, 0},
		{"another tenant", heardReport("s1", "t2", "p1", 10*time.Second, 20*time.Second), false, 0},
		{"another project", heardReport("s1", "t1", "p2", 10*time.Second, 20*time.Second), false, 0},
		{"no event time", heardReport("s1", "t1", "p1", -1, 20*time.Second), false, 0},
		{"no receive time", heardReport("s1", "t1", "p1", 10*time.Second, -1), false, 0},
		{"another kind's report", kindReport(heardReport("s1", "t1", "p1", 10*time.Second, 20*time.Second), observe.KindEgressAccessLog), false, 0},
		{"an observation", &observev1.Record{Record: &observev1.Record_Observation{Observation: &observev1.Observation{}}}, false, 0},
	}
	for _, c := range cases {
		last, heard := observe.LastHeard(liveDescriptor(), []*observev1.Record{c.rec})
		if heard != c.heard || (heard && !last.Equal(heardBase.Add(c.last))) || (!heard && !last.IsZero()) {
			t.Errorf("%s: last heard %s, %t; want %t at %s", c.name, last, heard, c.heard, c.last)
		}
	}
	last, heard := observe.LastHeard(liveDescriptor(), []*observev1.Record{
		heardReport("s1", "t1", "p1", 5*time.Second, 50*time.Second),
		heardReport("s1", "t2", "p1", 40*time.Second, 50*time.Second),
		heardReport("s1", "t1", "p1", 15*time.Second, 50*time.Second),
		heardReport("s1", "t1", "p1", 8*time.Second, 50*time.Second),
	})
	if !heard || !last.Equal(heardBase.Add(15*time.Second)) {
		t.Errorf("of three own reports and another tenant's: %s, %t; want the newest own one at 15s", last, heard)
	}
}

// TestLivenessAtItsBounds: a source is live up to its heartbeat after it was
// last heard and lapsed a nanosecond later; heard after the time asked
// about, it is ahead of it; never heard, it is that whatever the times.
func TestLivenessAtItsBounds(t *testing.T) {
	last := heardBase
	cases := []struct {
		name  string
		heard bool
		at    time.Time
		want  observe.Liveness
	}{
		{"never heard", false, last, observe.NeverHeard},
		{"at its last report", true, last, observe.Live},
		{"at its heartbeat", true, last.Add(time.Minute), observe.Live},
		{"a nanosecond past it", true, last.Add(time.Minute + time.Nanosecond), observe.Lapsed},
		{"a nanosecond before its last report", true, last.Add(-time.Nanosecond), observe.Ahead},
	}
	for _, c := range cases {
		if got := observe.LivenessAt(last, c.heard, 60, c.at); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if observe.Liveness(0) != observe.NeverHeard {
		t.Error("the zero Liveness is not NeverHeard")
	}
}
