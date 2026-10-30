package ingest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/guardana/control/internal/ingest"
	"github.com/guardana/control/internal/ingest/otelgenai"
	"github.com/guardana/control/internal/observe"
)

func TestTheOTelPinsAreFixed(t *testing.T) {
	if otelgenai.ConventionName != "opentelemetry.gen_ai" || otelgenai.ConventionVersion != "1.41.0" || otelgenai.OTLPVersion != "1.11.1" {
		t.Fatal("a pinned constant moved")
	}
	want := []string{
		"gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions",
		"gen_ai.tool.call.arguments", "gen_ai.tool.call.result", "gen_ai.tool.definitions",
		"gen_ai.prompt", "gen_ai.completion",
	}
	if strings.Join(otelgenai.ContentAttributes, ",") != strings.Join(want, ",") {
		t.Fatalf("ContentAttributes = %q, want %q", otelgenai.ContentAttributes, want)
	}
}

type otelCase struct {
	name   string
	edit   func(map[string]any)
	member string // "" accepts; otherwise the member the refusal names
}

// TestTheOTelMembersValues: the values of the members kind
// otel-genai-traces owns, read through the entry point.
func TestTheOTelMembersValues(t *testing.T) {
	sel := []string{"select"}
	conv := []string{"convention"}
	cases := []otelCase{
		{"the fixture", func(map[string]any) {}, ""},
		{"convention name", set(conv, "name", "opentelemetry.genai"), "convention.name"},
		{"convention version", set(conv, "version", "1.40.0"), "convention.version"},
		{"convention version absent", drop(conv, "version"), "convention.version: required"},
		{"convention empty", set(top, "convention", map[string]any{}), "convention.name: required"},
		{"otlp other", set(top, "otlp_version", "1.11.0"), "otlp_version"},
		{"service_name absent", drop(sel, "service_name"), "select.service_name"},
		{"service_name empty", set(sel, "service_name", ""), "select.service_name"},
		{"service_name 256", set(sel, "service_name", strings.Repeat("n", 256)), ""},
		{"service_name 257", set(sel, "service_name", strings.Repeat("n", 257)), "select.service_name"},
		{"service_name 256 bytes of runes", set(sel, "service_name", strings.Repeat("\u00e9", 128)), ""},
		{"service_name 258 bytes of runes", set(sel, "service_name", strings.Repeat("\u00e9", 129)), "select.service_name"},
		{"service_name tab", set(sel, "service_name", "a\tb"), "select.service_name"},
		{"service_name DEL", set(sel, "service_name", "a\u007fb"), "select.service_name"},
		{"service_name NEL", set(sel, "service_name", "a\u0085b"), "select.service_name"},
		{"service_name space", set(sel, "service_name", "support agent"), ""},
		{"service_name zero-width space", set(sel, "service_name", "a\u200bb"), "select.service_name"},
		{"service_name bidi override", set(sel, "service_name", "x\u202ey"), "select.service_name"},
		{"service_name byte order mark", set(sel, "service_name", "\ufeffsupport"), "select.service_name"},
		{"service_name a space", set(sel, "service_name", " "), "select.service_name"},
		{"service_name a tab", set(sel, "service_name", "\t"), "select.service_name"},
		{"service_name an ideographic space", set(sel, "service_name", "\u3000"), "select.service_name"},
		{"service_name non-ASCII", set(sel, "service_name", "agent-\u00e9"), ""},
		{"run_attribute absent", drop(top, "run_attribute"), ""},
		{"run_attribute a neighbour of content", set(top, "run_attribute", "gen_ai.conversation.id"), ""},
		{"run_attribute 256", set(top, "run_attribute", strings.Repeat("r", 256)), ""},
		{"run_attribute 257", set(top, "run_attribute", strings.Repeat("r", 257)), "run_attribute"},
		{"run_attribute control", set(top, "run_attribute", "run\u0000id"), "run_attribute"},
		{"run_attribute zero-width space", set(top, "run_attribute", "a\u200bb"), "run_attribute"},
		{"run_attribute bidi override", set(top, "run_attribute", "x\u202ey"), "run_attribute"},
		{"run_attribute a space", set(top, "run_attribute", " "), "run_attribute"},
		{"run_attribute a tab", set(top, "run_attribute", "\t"), "run_attribute"},
	}
	for _, attr := range []string{
		"gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions",
		"gen_ai.tool.call.arguments", "gen_ai.tool.call.result", "gen_ai.tool.definitions",
		"gen_ai.prompt", "gen_ai.completion",
	} {
		cases = append(cases, otelCase{"run_attribute " + attr, set(top, "run_attribute", attr), "run_attribute"})
	}
	fixture := readFixture(t, otelFixture)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := jsonEdit(t, fixture, c.edit)
			_, err := ingest.ReadDescriptor(doc)
			if c.member == "" {
				if err != nil {
					t.Fatalf("refused %s: %v", doc, err)
				}
				return
			}
			if !errors.Is(err, observe.ErrDescriptor) || !errors.Is(err, otelgenai.ErrDescriptor) || !strings.Contains(err.Error(), c.member) {
				t.Fatalf("ReadDescriptor(%s) = %v, want the importer's refusal naming %q", doc, err, c.member)
			}
		})
	}
}
