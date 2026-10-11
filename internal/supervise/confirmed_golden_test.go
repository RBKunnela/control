package supervise_test

import (
	"encoding/hex"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/supervise"
	"google.golang.org/protobuf/proto"
)

const (
	confirmedGolden = "testdata/confirmed-0.1.golden"
	childRun        = "run-11111111111111111111111111111111"
)

// confirmedCorpus is 0.1 supervisions whose CONFIRMED findings are pinned:
// every rule that can confirm, beside a child's events, another tenant's, a
// conflicting event id, a silent source, a span chain that cuts the join, and
// two exports of one trail.
func confirmedCorpus(t *testing.T) map[string]supervise.Input {
	t.Helper()
	p := procWith(t)
	tight := procWith(t, `"max_denials":4`, `"max_denials":2`, `"deadline_seconds":600`, `"deadline_seconds":20`)
	withChild := append(denials(4), call{req: "c1", tool: "wipe_disk", upstream: "ops", at: 5 * time.Second, run: childRun},
		call{req: "c2", tool: "issue_refund", upstream: "pay", at: 6 * time.Second, outcome: "deny", run: childRun},
		call{req: "o1", tool: "drop_table", upstream: "db", at: 7 * time.Second, tenant: "t2"})
	conflicting := export(denials(3, call{req: "w1", tool: "wipe_disk", upstream: "ops", at: 70 * time.Second})...)
	other := export(call{req: "w1", tool: "drop_table", upstream: "db", at: 70 * time.Second})
	silent := source(ob{id: "obs-1", name: "wipe_disk", span: "1111111111111111"})
	silent.Heard = false
	cut := chain(16385, ob{id: "obs-top", name: "wipe_disk"}, observev1.SubjectKind_SUBJECT_KIND_AGENT, "mcp_call")
	return map[string]supervise.Input{
		"denials beside a child and another tenant": {Procedure: p, Run: supervise.Run{Closed: true},
			Exports: []supervise.Export{export(withChild...)}},
		"denials and a deadline at tight bounds": {Procedure: tight,
			Exports: []supervise.Export{export(denials(3, call{req: "z1", tool: "send_mail", upstream: "mail", at: 90 * time.Second})...)}},
		"a conflicting event id": {Procedure: p, Exports: []supervise.Export{conflicting, other}},
		"one trail in two exports": {Procedure: p, Run: supervise.Run{Closed: true},
			Exports: []supervise.Export{export(denials(4)...), export(denials(4)...)}},
		"a silent source": {Procedure: p, Sources: []supervise.Source{silent},
			Exports: []supervise.Export{export(call{req: "w1", tool: "wipe_disk", upstream: "ops", span: "1111111111111111"},
				call{req: "w2", tool: "drop_table", upstream: "db", at: 700 * time.Second})}},
		"a join cut short": {Procedure: p, Sources: []supervise.Source{cut},
			Exports: []supervise.Export{export(decoys(spanAt(16383), spanAt(16384))...)}},
	}
}

// confirmedLines is each CONFIRMED finding of the corpus as its scenario, its
// rule, its id and its deterministic wire bytes in hex.
func confirmedLines(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	corpus := confirmedCorpus(t)
	for _, name := range slices.Sorted(maps.Keys(corpus)) {
		for _, f := range evaluate(t, corpus[name]).Findings {
			if f.GetFinding().GetVerdict() != confirmed {
				continue
			}
			raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			b.WriteString(name + "\t" + f.GetFinding().GetRuleId() + "\t" + f.GetFinding().GetFindingId() + "\t" +
				hex.EncodeToString(raw) + "\n")
		}
	}
	return b.String()
}

// TestA01CorpusKeepsItsConfirmedFindingsByteForByte: the corpus's CONFIRMED
// findings are those the golden holds, byte for byte, and the golden holds
// one of every rule that can confirm. The golden is what a 0.1 procedure
// confirms, so only a rule's new version, which changes its finding ids,
// rewrites its lines.
func TestA01CorpusKeepsItsConfirmedFindingsByteForByte(t *testing.T) {
	got := confirmedLines(t)
	raw, err := os.ReadFile(confirmedGolden)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"REPEATED_DENIAL", "STEP_OUTSIDE_PROCEDURE", "DEADLINE_EXCEEDED"} {
		if !strings.Contains(string(raw), "\t"+rule+"\t") {
			t.Fatalf("the golden holds no CONFIRMED %s", rule)
		}
	}
	if got != string(raw) {
		t.Fatalf("CONFIRMED findings differ from %s:\n got\n%s\nwant\n%s", confirmedGolden, got, raw)
	}
}
