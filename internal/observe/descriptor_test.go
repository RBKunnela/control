package observe_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/proto"
)

func TestTheFixtureDescriptorReads(t *testing.T) {
	d, err := observe.ReadNeutral(readTestdata(t, "descriptor.json"))
	if err != nil {
		t.Fatalf("ReadNeutral(fixture): %v", err)
	}
	want := &observev1.SourceDescriptor{
		SchemaVersion:    "0.1",
		SourceId:         "agent-runtime",
		Kind:             "otel-genai-traces",
		Trust:            observev1.Trust_TRUST_SELF_REPORTED,
		Convention:       &observev1.Convention{Name: "opentelemetry.gen_ai", Version: "1.41.0"},
		OtlpVersion:      "1.11.1",
		Select:           &observev1.Selector{ServiceName: "support-agent"},
		Sampling:         observev1.Sampling_SAMPLING_COMPLETE,
		HeartbeatSeconds: 300,
		TenantId:         "tenant-a",
		ProjectId:        "project-a",
		RunAttribute:     "app.run_id",
	}
	if !proto.Equal(d, want) {
		t.Fatalf("ReadNeutral(fixture) = %v\nwant %v", d, want)
	}
}

func TestDescriptorSHA256(t *testing.T) {
	if got := observe.DescriptorSHA256(readTestdata(t, "descriptor.json")); got != fixtureDescriptorSHA256 {
		t.Errorf("DescriptorSHA256(fixture) = %s, want %s", got, fixtureDescriptorSHA256)
	}
	const empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := observe.DescriptorSHA256(nil); got != empty {
		t.Errorf("DescriptorSHA256(nil) = %s, want %s", got, empty)
	}
}

func TestTheConstantsArePinned(t *testing.T) {
	if observe.KindOTelGenAI != "otel-genai-traces" || observe.KindEgressAccessLog != "egress-access-log" ||
		observe.MaxHeartbeatSeconds != 604800 || observe.MaxLineBytes != 65536 || observe.MaxTextBytes != 256 {
		t.Fatal("a pinned constant moved")
	}
}

type descriptorCase struct {
	name   string
	edit   func(m map[string]any)
	member string // "" accepts; otherwise the member the refusal names
}

func set(path []string, key string, v any) func(map[string]any) {
	return func(m map[string]any) { member(m, path...)[key] = v }
}

func drop(path []string, key string) func(map[string]any) {
	return func(m map[string]any) { delete(member(m, path...), key) }
}

func runDescriptorCases(t *testing.T, cases []descriptorCase) {
	t.Helper()
	fixture := readTestdata(t, "descriptor.json")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := jsonEdit(t, fixture, c.edit)
			_, err := observe.ReadNeutral(doc)
			if c.member == "" {
				if err != nil {
					t.Fatalf("refused %s: %v", doc, err)
				}
				return
			}
			if !errors.Is(err, observe.ErrDescriptor) {
				t.Fatalf("ReadNeutral(%s) = %v, want ErrDescriptor", doc, err)
			}
			if !strings.Contains(err.Error(), c.member) {
				t.Fatalf("refusal %q does not name %q", err, c.member)
			}
		})
	}
}

var top []string

func TestDescriptorIdentity(t *testing.T) {
	runDescriptorCases(t, []descriptorCase{
		{"version absent", drop(top, "schema_version"), "schema_version"},
		{"version next minor", set(top, "schema_version", "0.2"), "schema_version"},
		{"version major", set(top, "schema_version", "1.0"), "schema_version"},
		{"source_id absent", drop(top, "source_id"), "source_id"},
		{"source_id slash", set(top, "source_id", "agent/runtime"), "source_id"},
		{"source_id space", set(top, "source_id", "agent runtime"), "source_id"},
		{"source_id non-ASCII", set(top, "source_id", "agent-\u00e9"), "source_id"},
		{"source_id every allowed byte", set(top, "source_id", "Az09._:-"), ""},
		{"source_id 128", set(top, "source_id", strings.Repeat("s", 128)), ""},
		{"source_id 129", set(top, "source_id", strings.Repeat("s", 129)), "source_id"},
		{"kind absent", drop(top, "kind"), "kind"},
		{"kind other", set(top, "kind", "otel-genai-logs"), "kind"},
		{"convention absent", drop(top, "convention"), "convention: required for kind"},
		{"otlp absent", drop(top, "otlp_version"), "otlp_version"},
		{"tenant absent", drop(top, "tenant_id"), "tenant_id"},
		{"tenant slash", set(top, "tenant_id", "a/b"), "tenant_id"},
		{"tenant 128", set(top, "tenant_id", strings.Repeat("t", 128)), ""},
		{"tenant 129", set(top, "tenant_id", strings.Repeat("t", 129)), "tenant_id"},
		{"project absent", drop(top, "project_id"), "project_id"},
		{"project newline", set(top, "project_id", "p\n"), "project_id"},
		{"project 128", set(top, "project_id", strings.Repeat("p", 128)), ""},
		{"project 129", set(top, "project_id", strings.Repeat("p", 129)), "project_id"},
	})
}

func TestDescriptorTrustAndSampling(t *testing.T) {
	runDescriptorCases(t, []descriptorCase{
		{"trust absent", drop(top, "trust"), "trust"},
		{"trust unspecified", set(top, "trust", "TRUST_UNSPECIFIED"), "trust"},
		{"trust zero number", set(top, "trust", 0), "trust"},
		{"trust independent", set(top, "trust", "TRUST_INDEPENDENT"), "trust"},
		{"trust independent by number", set(top, "trust", 3), "trust"},
		{"trust undeclared number", set(top, "trust", 7), "trust"},
		{"trust negative number", set(top, "trust", -1), "trust"},
		{"trust platform", set(top, "trust", "TRUST_PLATFORM"), ""},
		{"trust self-reported by number", set(top, "trust", 1), ""},
		{"trust unknown name", set(top, "trust", "TRUST_FULL"), "trust"},
		{"sampling absent", drop(top, "sampling"), ""},
		{"sampling unspecified", set(top, "sampling", "SAMPLING_UNSPECIFIED"), ""},
		{"sampling partial", set(top, "sampling", "SAMPLING_PARTIAL"), ""},
		{"sampling undeclared number", set(top, "sampling", 3), "sampling"},
		{"sampling a sampled flag", set(top, "sampling", true), "sampling"},
	})
}

// The values of select and run_attribute are the importer's to judge; this
// package holds only that select is there.
func TestDescriptorSelectAndHeartbeat(t *testing.T) {
	runDescriptorCases(t, []descriptorCase{
		{"select absent", drop(top, "select"), "select: required for kind"},
		{"heartbeat absent", drop(top, "heartbeat_seconds"), "heartbeat_seconds"},
		{"heartbeat 0", set(top, "heartbeat_seconds", 0), "heartbeat_seconds"},
		{"heartbeat 1", set(top, "heartbeat_seconds", 1), ""},
		{"heartbeat 604800", set(top, "heartbeat_seconds", 604800), ""},
		{"heartbeat 604801", set(top, "heartbeat_seconds", 604801), "heartbeat_seconds"},
		{"heartbeat negative", set(top, "heartbeat_seconds", -1), "heartbeat"},
		{"run_attribute absent", drop(top, "run_attribute"), ""},
	})
}

func TestDescriptorStrictJSON(t *testing.T) {
	runDescriptorCases(t, []descriptorCase{
		{"a capture setting", set(top, "capture_content", true), "capture_content"},
		{"a sampled flag", set(top, "sampled", true), "sampled"},
		{"an unknown nested member", set([]string{"select"}, "pattern", "*"), "pattern"},
		{"a null member", set(top, "run_attribute", nil), "null"},
		{"a null message", set(top, "select", nil), "null"},
		{"camelCase spelling", func(m map[string]any) {
			m["sourceId"] = m["source_id"]
			delete(m, "source_id")
		}, ""},
	})
	fixture := readTestdata(t, "descriptor.json")
	for name, doc := range map[string]string{
		"duplicate member":                 `{"source_id":"a",` + string(fixture[1:]),
		"duplicate member, other spelling": `{"sourceId":"a",` + string(fixture[1:]),
		"duplicate nested member":          strings.Replace(string(fixture), `"service_name": "support-agent"`, `"service_name": "a", "serviceName": "b"`, 1),
		"an array":                         `[` + string(fixture) + `]`,
		"two documents":                    string(fixture) + string(fixture),
		"empty":                            ``,
		"truncated":                        string(fixture[:len(fixture)/2]),
		"invalid UTF-8 in a text member":   strings.Replace(string(fixture), "support-agent", "support\xffagent", 1),
	} {
		if _, err := observe.ReadNeutral([]byte(doc)); !errors.Is(err, observe.ErrDescriptor) {
			t.Errorf("%s: ReadNeutral = %v, want ErrDescriptor", name, err)
		}
	}
}

func TestDescriptorSizeBound(t *testing.T) {
	fixture := bytes.TrimSpace(readTestdata(t, "descriptor.json"))
	var compact bytes.Buffer
	if err := json.Compact(&compact, fixture); err != nil {
		t.Fatal(err)
	}
	pad := func(n int) []byte {
		return append(bytes.Repeat([]byte(" "), n-compact.Len()), compact.Bytes()...)
	}
	if _, err := observe.ReadNeutral(pad(65536)); err != nil {
		t.Fatalf("a descriptor of 65536 bytes is refused: %v", err)
	}
	_, err := observe.ReadNeutral(pad(65537))
	if !errors.Is(err, observe.ErrDescriptor) || !strings.Contains(err.Error(), "65537 bytes") {
		t.Fatalf("a descriptor of 65537 bytes: %v, want a size refusal", err)
	}
}
