package ingest_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/ingest"
	"github.com/guardana/control/internal/ingest/egresslog"
	"github.com/guardana/control/internal/ingest/otelgenai"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestEveryKindHasExactlyOneEntry: each kind of observe's table has one
// registry entry, and each entry is a kind of that table.
func TestEveryKindHasExactlyOneEntry(t *testing.T) {
	entries := map[string]int{}
	var names []string
	for _, k := range ingest.Kinds() {
		entries[k.Name]++
		names = append(names, k.Name)
		if k.Check == nil || k.Import == nil || k.Labels.Read == "" {
			t.Errorf("entry %q lacks a check, an importer or a read label", k.Name)
		}
		if observe.LookupKind(k.Name).Name != k.Name {
			t.Errorf("entry %q is not a kind of observe's table", k.Name)
		}
	}
	for _, k := range observe.Kinds() {
		if entries[k.Name] != 1 {
			t.Errorf("kind %q has %d registry entries, want 1", k.Name, entries[k.Name])
		}
	}
	if want := []string{"egress-access-log", "otel-genai-traces"}; !slices.Equal(slices.Sorted(slices.Values(names)), want) {
		t.Errorf("registry names %q, want %q", names, want)
	}
}

// TestEachKindsFixtureLoads: each kind's descriptor reads through the one
// entry point, finds its entry, and the OTel descriptor keeps the bytes and
// digest it had before the checks split.
func TestEachKindsFixtureLoads(t *testing.T) {
	for _, c := range []struct{ fixture, kind, read string }{
		{otelFixture, "otel-genai-traces", "spans_read"},
		{envoyFixture, "egress-access-log", "lines_read"},
		{squidFixture, "egress-access-log", "lines_read"},
	} {
		d, err := ingest.ReadDescriptor(readFixture(t, c.fixture))
		if err != nil {
			t.Errorf("%s: %v", c.fixture, err)
			continue
		}
		k, ok := ingest.Lookup(d.GetKind())
		if d.GetKind() != c.kind || !ok || k.Labels.Read != c.read {
			t.Errorf("%s: kind %q, entry %v, read label %q; want %q and %q", c.fixture, d.GetKind(), ok, k.Labels.Read, c.kind, c.read)
		}
	}
	const otelSHA = "7602644155b2785d471d51830e7dd6f4fc86c779802ce6b63bfc7de5fdb2d043"
	if got := observe.DescriptorSHA256(readFixture(t, otelFixture)); got != otelSHA {
		t.Errorf("the 0.1 OTel descriptor's digest is %s, want %s", got, otelSHA)
	}
}

// ownedMemberRefusals is, for each member a kind owns, an edit that observe's
// checks accept and the kind's own checks refuse, and what the refusal names.
var ownedMemberRefusals = map[string]map[string]struct {
	edit  func(map[string]any)
	names string
}{
	observe.KindOTelGenAI: {
		"convention":    {set([]string{"convention"}, "version", "1.40.0"), "convention.version"},
		"otlp_version":  {set(top, "otlp_version", "1.11.0"), "otlp_version"},
		"select":        {set([]string{"select"}, "service_name", "a\tb"), "select.service_name"},
		"run_attribute": {set(top, "run_attribute", "gen_ai.prompt"), "run_attribute"},
	},
	observe.KindEgressAccessLog: {
		"egress_access_log": {set([]string{"egress_access_log"}, "format", "xml"), "format"},
	},
}

// TestEachOwnedMemberIsCheckedByItsKind: a value of a kind's member that
// only the kind's checks judge reads neutrally and is refused by the entry
// point, as a descriptor refusal naming the member.
func TestEachOwnedMemberIsCheckedByItsKind(t *testing.T) {
	fixtures := map[string]string{observe.KindOTelGenAI: otelFixture, observe.KindEgressAccessLog: envoyFixture}
	for _, k := range observe.Kinds() {
		for _, m := range k.Members {
			c, ok := ownedMemberRefusals[k.Name][m]
			if !ok {
				t.Errorf("kind %q member %q has no refused fixture", k.Name, m)
				continue
			}
			doc := jsonEdit(t, readFixture(t, fixtures[k.Name]), c.edit)
			if _, err := observe.ReadNeutral(doc); err != nil {
				t.Errorf("%s %s: observe refused it, so the kind's check is not what is tested: %v", k.Name, m, err)
			}
			_, err := ingest.ReadDescriptor(doc)
			if !errors.Is(err, observe.ErrDescriptor) || !strings.Contains(err.Error(), c.names) {
				t.Errorf("%s %s: ReadDescriptor = %v, want ErrDescriptor naming %q", k.Name, m, err, c.names)
			}
		}
	}
}

// TestIndependentTrustIsTheTablesRule: an OTel descriptor claiming
// independent trust is refused by the entry point and by observe's checks
// alone, while the importer's own check does not judge trust at all, so the
// rule lives in the table and not in an importer.
func TestIndependentTrustIsTheTablesRule(t *testing.T) {
	doc := jsonEdit(t, readFixture(t, otelFixture), set(top, "trust", "TRUST_INDEPENDENT"))
	_, err := ingest.ReadDescriptor(doc)
	if !errors.Is(err, observe.ErrDescriptor) || !strings.Contains(err.Error(), `trust: TRUST_INDEPENDENT is refused for kind "otel-genai-traces"`) {
		t.Errorf("ReadDescriptor = %v, want the trust refusal", err)
	}
	d := &observev1.SourceDescriptor{}
	if err := protojson.Unmarshal(doc, d); err != nil {
		t.Fatal(err)
	}
	if err := observe.CheckNeutral(d); !errors.Is(err, observe.ErrDescriptor) || !strings.Contains(err.Error(), "trust") {
		t.Errorf("CheckNeutral = %v, want the trust refusal", err)
	}
	if err := otelgenai.Check(d); err != nil {
		t.Errorf("otelgenai.Check judged trust: %v", err)
	}
	if _, err := ingest.ReadDescriptor(readFixture(t, envoyFixture)); err != nil {
		t.Errorf("an independent egress descriptor: %v", err)
	}
}

// TestTheDescriptorVersionFollowsItsMembers: the entry point keeps observe's
// version rule, as a descriptor refusal and not a version it lacks.
func TestTheDescriptorVersionFollowsItsMembers(t *testing.T) {
	for name, c := range map[string]struct {
		doc  []byte
		want string
	}{
		"0.2 without the member": {jsonEdit(t, readFixture(t, otelFixture), set(top, "schema_version", "0.2")), `schema_version: "0.2" on a descriptor with no member of "0.2"`},
		"0.1 with the member":    {jsonEdit(t, readFixture(t, envoyFixture), set(top, "schema_version", "0.1")), `egress_access_log: not a member of schema "0.1"`},
	} {
		_, err := ingest.ReadDescriptor(c.doc)
		if !errors.Is(err, observe.ErrDescriptor) || errors.Is(err, observe.ErrVersion) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want ErrDescriptor, not ErrVersion, saying %q", name, err, c.want)
		}
	}
	if _, err := ingest.ReadDescriptor([]byte(`{"schema_version":"0.3"}`)); !errors.Is(err, observe.ErrVersion) {
		t.Errorf("a 0.3 descriptor: %v, want ErrVersion", err)
	}
}

// TestTheLabelsAreEachKinds: the counts observe import prints after the
// shared ones, by kind.
func TestTheLabelsAreEachKinds(t *testing.T) {
	want := map[string]string{
		observe.KindOTelGenAI: "spans_read other_resource refused content_attributes_dropped reasoning_parts_dropped " +
			"content_unparsed run_ids_dropped strings_dropped skipped",
		observe.KindEgressAccessLog: "lines_read refused strings_dropped callers_dropped",
	}
	c := &observev1.ImportCounts{
		Read: 100, OtherResource: 1, Refused: 2, ContentAttributesDropped: 3, ReasoningPartsDropped: 4,
		ContentUnparsed: 5, RunIdsDropped: 6, StringsDropped: 7, Skipped: map[string]uint64{"a": 8, "b": 9}, CallersDropped: 10,
	}
	values := map[string]uint64{
		"other_resource": 1, "refused": 2, "content_attributes_dropped": 3, "reasoning_parts_dropped": 4,
		"content_unparsed": 5, "run_ids_dropped": 6, "strings_dropped": 7, "skipped": 17, "callers_dropped": 10,
	}
	for _, k := range ingest.Kinds() {
		got := []string{k.Labels.Read}
		for _, n := range k.Labels.Counts {
			got = append(got, n.Label)
			if v := n.Of(c); v != values[n.Label] {
				t.Errorf("%s %s reads %d, want %d", k.Name, n.Label, v, values[n.Label])
			}
		}
		if strings.Join(got, " ") != want[k.Name] {
			t.Errorf("%s prints %q, want %q", k.Name, got, want[k.Name])
		}
	}
	if egresslog.ReadLabel != "lines_read" || otelgenai.ReadLabel != "spans_read" {
		t.Error("a read label moved")
	}
}
