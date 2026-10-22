package coverage_test

import (
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/coverage"
)

// sampledSource is a live source id at sampling, holding one observation of
// create_issue.
func sampledSource(id string, sampling observev1.Sampling) coverage.Source {
	d := descriptor(id, selfReported)
	d.Sampling = sampling
	return coverage.Source{Descriptor: d, Records: []*observev1.Record{
		report(id, at(-10*time.Second), at(-10*time.Second)), obs{id: "obs-" + id, source: id}.record()}}
}

// TestAPathSeenOnlyThroughASampledSourceIsObservedAndSampled: a source that
// samples may miss a call, so a path only such sources observed says so; one
// complete source among them is enough to say it does not. A descriptor that
// states no sampling reads as partial.
func TestAPathSeenOnlyThroughASampledSourceIsObservedAndSampled(t *testing.T) {
	const (
		complete    = observev1.Sampling_SAMPLING_COMPLETE
		partial     = observev1.Sampling_SAMPLING_PARTIAL
		unspecified = observev1.Sampling_SAMPLING_UNSPECIFIED
	)
	one := toolInventory(t)
	two := mustInventory(t, `{"schema_version":"0.1","paths":[{"id":"gh-create","kind":"mcp_tool",`+
		`"upstream":"github","tool":"create_issue","sources":[{"source_id":"s1","name":"create_issue"},`+
		`{"source_id":"s2","name":"create_issue"}]}]}`)
	const heard = ": last heard 2026-10-05T11:59:50Z, heartbeat 300 s"
	for name, c := range map[string]struct {
		inv     *coverage.Inventory
		sources []coverage.Source
		want    []string
	}{
		"complete": {one, []coverage.Source{sampledSource("s1", complete)},
			[]string{"gh-create observed, self_reported: sources s1", "  source s1: observed, self_reported" + heard}},
		"partial": {one, []coverage.Source{sampledSource("s1", partial)},
			[]string{"gh-create observed, self_reported, sampled: sources s1", "  source s1: observed, self_reported, sampled" + heard}},
		"unstated": {one, []coverage.Source{sampledSource("s1", unspecified)},
			[]string{"gh-create observed, self_reported, sampled: sources s1", "  source s1: observed, self_reported, sampled" + heard}},
		"partial beside complete": {two, []coverage.Source{sampledSource("s1", partial), sampledSource("s2", complete)},
			[]string{"gh-create observed, self_reported: sources s1, s2", "  source s1: observed, self_reported, sampled" + heard,
				"  source s2: observed, self_reported" + heard}},
	} {
		t.Run(name, func(t *testing.T) {
			r := mustMap(t, coverage.Input{Inventory: c.inv, Sources: c.sources})
			got := r.Lines()
			want := append(c.want, "undeclared paths: unknown")
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			if code := coverage.ExitStatus(r, nil); code != coverage.ExitCovered {
				t.Errorf("exit %d, want %d: a sampled observation is still one", code, coverage.ExitCovered)
			}
		})
	}
}
