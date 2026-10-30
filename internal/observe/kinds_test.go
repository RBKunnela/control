package observe_test

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestTheKindTableIsPinned(t *testing.T) {
	want := []observe.Kind{
		{
			Name:       "otel-genai-traces",
			Members:    []string{"convention", "otlp_version", "select", "run_attribute"},
			Required:   []string{"convention", "otlp_version", "select"},
			ClaimsRuns: true,
		},
		{
			Name:        "egress-access-log",
			Members:     []string{"egress_access_log"},
			Required:    []string{"egress_access_log"},
			Independent: true,
		},
	}
	if got := observe.Kinds(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Kinds() = %+v\nwant %+v", got, want)
	}
	if observe.KindOTelGenAI != "otel-genai-traces" || observe.KindEgressAccessLog != "egress-access-log" {
		t.Fatal("a kind's name moved")
	}
	for _, k := range want {
		if got := observe.LookupKind(k.Name); !reflect.DeepEqual(got, k) {
			t.Errorf("LookupKind(%q) = %+v, want %+v", k.Name, got, k)
		}
	}
}

// A name the table does not hold, an empty one among them, lands on the side
// that grants nothing.
func TestAnUnknownKindIsTheZeroRow(t *testing.T) {
	for _, name := range []string{"", "otel-genai-logs", "EGRESS-ACCESS-LOG", "egress-access-log "} {
		if got := observe.LookupKind(name); !reflect.DeepEqual(got, observe.Kind{}) {
			t.Errorf("LookupKind(%q) = %+v, want the zero Kind", name, got)
		}
	}
}

func TestTheKindTableIsNotTheCallers(t *testing.T) {
	ks := observe.Kinds()
	ks[0].Members[0], ks[1].Independent = "changed", false
	k := observe.LookupKind(observe.KindOTelGenAI)
	k.Required[0] = "changed"
	again := observe.Kinds()
	if again[0].Members[0] != "convention" || !again[1].Independent ||
		observe.LookupKind(observe.KindOTelGenAI).Required[0] != "convention" {
		t.Fatal("a caller's copy of the kind table changed the table")
	}
}

// Every member of the descriptor is neutral or owned by exactly one kind, so a
// member added to the contract without a row is refused on every kind rather
// than read by none.
func TestEveryDescriptorMemberHasOneOwner(t *testing.T) {
	neutral := []string{"schema_version", "source_id", "kind", "trust", "sampling", "heartbeat_seconds", "tenant_id", "project_id"}
	fields := (&observev1.SourceDescriptor{}).ProtoReflect().Descriptor().Fields()
	if fields.Len() != 13 {
		t.Fatalf("the descriptor has %d members, want 13: a new one needs its owner here", fields.Len())
	}
	for i := range fields.Len() {
		name := string(fields.Get(i).Name())
		owners := 0
		for _, k := range observe.Kinds() {
			if slices.Contains(k.Members, name) {
				owners++
			}
		}
		switch {
		case slices.Contains(neutral, name) && owners != 0:
			t.Errorf("%s is neutral and owned by %d kinds", name, owners)
		case !slices.Contains(neutral, name) && owners != 1:
			t.Errorf("%s is owned by %d kinds, want 1", name, owners)
		}
	}
	for _, k := range observe.Kinds() {
		for _, r := range k.Required {
			if !slices.Contains(k.Members, r) {
				t.Errorf("kind %s requires %s, which it does not own", k.Name, r)
			}
		}
	}
}

func TestTheEgressFixtureReadsNeutrally(t *testing.T) {
	d, err := observe.ReadNeutral(readTestdata(t, "descriptor-egress.json"))
	if err != nil {
		t.Fatalf("ReadNeutral(egress fixture): %v", err)
	}
	if d.GetKind() != "egress-access-log" || d.GetTrust() != observev1.Trust_TRUST_INDEPENDENT ||
		d.GetEgressAccessLog().GetFields().GetDestination() != "authority" ||
		d.GetEgressAccessLog().GetCallerBasis() != observev1.CallerBasis_CALLER_BASIS_ADDRESS {
		t.Fatalf("ReadNeutral(egress fixture) = %v", d)
	}
	if _, err := observe.ReadNeutral(readTestdata(t, "descriptor.json")); err != nil {
		t.Fatalf("ReadNeutral(OTel fixture): %v", err)
	}
}

// checkNeutralBoth reads doc through ReadNeutral and, decoded by plain
// protojson, through CheckNeutral alone, and holds both to one answer.
func checkNeutralBoth(t *testing.T, name string, doc []byte, member string) {
	t.Helper()
	_, rerr := observe.ReadNeutral(doc)
	d := &observev1.SourceDescriptor{}
	if err := protojson.Unmarshal(doc, d); err != nil {
		t.Fatalf("%s: protojson: %v", name, err)
	}
	cerr := observe.CheckNeutral(d)
	for via, err := range map[string]error{"ReadNeutral": rerr, "CheckNeutral": cerr} {
		switch {
		case member == "" && err != nil:
			t.Errorf("%s: %s refused: %v", name, via, err)
		case member != "" && (!errors.Is(err, observe.ErrDescriptor) || !strings.Contains(err.Error(), member)):
			t.Errorf("%s: %s = %v, want ErrDescriptor naming %q", name, via, err, member)
		}
	}
}

func TestCheckNeutralOnTheEgressKind(t *testing.T) {
	fixture := readTestdata(t, "descriptor-egress.json")
	eal := []string{"egress_access_log"}
	cases := []descriptorCase{
		{"the fixture", func(map[string]any) {}, ""},
		{"self-reported", set(top, "trust", "TRUST_SELF_REPORTED"), ""},
		{"platform", set(top, "trust", "TRUST_PLATFORM"), ""},
		{"trust absent", drop(top, "trust"), "trust"},
		{"an OTel member: select", set(top, "select", map[string]any{"service_name": "x"}), "select: not a member of kind"},
		{"an OTel member: convention", set(top, "convention", map[string]any{"name": "x"}), "convention: not a member of kind"},
		{"an OTel member: otlp_version", set(top, "otlp_version", "1.11.1"), "otlp_version: not a member of kind"},
		{"an OTel member: run_attribute", set(top, "run_attribute", "app.run_id"), "run_attribute: not a member of kind"},
		{"its member absent at 0.1", func(m map[string]any) {
			m["schema_version"] = "0.1"
			delete(m, "egress_access_log")
		}, "egress_access_log: required for kind"},
		{"its member absent at 0.2", drop(top, "egress_access_log"), "schema_version"},
		{"its member empty", set(top, "egress_access_log", map[string]any{}), ""},
		{"a format no importer reads", set(eal, "format", "xml"), ""},
		{"a destination naming a path", set([]string{"egress_access_log", "fields"}, "destination", "a.b"), ""},
		{"an unknown kind", set(top, "kind", "egress-access-logs"), `kind: "egress-access-logs" is not a kind this build reads`},
		{"kind absent", drop(top, "kind"), "kind: required"},
		{"heartbeat 0", set(top, "heartbeat_seconds", 0), "heartbeat_seconds"},
	}
	for _, c := range cases {
		checkNeutralBoth(t, c.name, jsonEdit(t, fixture, c.edit), c.member)
	}
}

func TestCheckNeutralOnTheOTelKind(t *testing.T) {
	fixture := readTestdata(t, "descriptor.json")
	cases := []descriptorCase{
		{"the fixture", func(map[string]any) {}, ""},
		{"independent", set(top, "trust", "TRUST_INDEPENDENT"), `trust: TRUST_INDEPENDENT is refused for kind "otel-genai-traces"`},
		{"independent by number", set(top, "trust", 3), "trust"},
		{"the egress member at 0.2", func(m map[string]any) {
			m["schema_version"] = "0.2"
			m["egress_access_log"] = map[string]any{"format": "json-lines"}
		}, "egress_access_log: not a member of kind"},
		{"the egress member at 0.1", set(top, "egress_access_log", map[string]any{"format": "json-lines"}), `egress_access_log: not a member of schema "0.1"`},
		{"convention absent", drop(top, "convention"), "convention: required for kind"},
		{"otlp_version absent", drop(top, "otlp_version"), "otlp_version: required for kind"},
		{"select absent", drop(top, "select"), "select: required for kind"},
		{"run_attribute absent", drop(top, "run_attribute"), ""},
		{"a convention no importer reads", set([]string{"convention"}, "version", "1.40.0"), ""},
		{"an empty selector", set(top, "select", map[string]any{}), ""},
	}
	for _, c := range cases {
		checkNeutralBoth(t, c.name, jsonEdit(t, fixture, c.edit), c.member)
	}
	if err := observe.CheckNeutral(nil); !errors.Is(err, observe.ErrDescriptor) {
		t.Errorf("CheckNeutral(nil) = %v, want ErrDescriptor", err)
	}
}

// The version rule refuses a descriptor whose version and members disagree,
// and says so as a descriptor refusal, not as a version this reader lacks.
func TestTheDescriptorVersionFollowsItsMembers(t *testing.T) {
	egress := readTestdata(t, "descriptor-egress.json")
	otel := readTestdata(t, "descriptor.json")
	cases := map[string]struct {
		doc  []byte
		want string
	}{
		"0.2 without the member": {jsonEdit(t, otel, set(top, "schema_version", "0.2")), `schema_version: "0.2" on a descriptor with no member of "0.2"`},
		"0.1 with the member":    {jsonEdit(t, egress, set(top, "schema_version", "0.1")), `egress_access_log: not a member of schema "0.1"`},
	}
	for name, c := range cases {
		_, err := observe.ReadNeutral(c.doc)
		if !errors.Is(err, observe.ErrDescriptor) || errors.Is(err, observe.ErrVersion) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: ReadNeutral = %v, want ErrDescriptor, not ErrVersion, saying %q", name, err, c.want)
		}
	}
	for _, v := range []string{"0.3", "0.0", "1.2"} {
		if _, err := observe.ReadNeutral(jsonEdit(t, egress, set(top, "schema_version", v))); !errors.Is(err, observe.ErrVersion) {
			t.Errorf("an egress descriptor at %s: %v, want ErrVersion", v, err)
		}
	}
}
