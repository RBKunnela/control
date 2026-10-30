package otelgenai

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

const (
	// ConventionName names the GenAI semantic conventions the input is read
	// under.
	ConventionName = "opentelemetry.gen_ai"
	// ConventionVersion pins them: they are still in development, so no
	// other version is assumed to mean the same.
	ConventionVersion = "1.41.0"
	// OTLPVersion pins the OTLP release whose JSON encoding the input uses.
	OTLPVersion = "1.11.1"
)

// ReadLabel names what the import's read count counts: spans.
const ReadLabel = "spans_read"

// ContentAttributes are the GenAI attributes that carry what a prompt or a
// tool held. A descriptor's run_attribute may not name one, and the importer
// drops them.
var ContentAttributes = []string{
	"gen_ai.input.messages",
	"gen_ai.output.messages",
	"gen_ai.system_instructions",
	"gen_ai.tool.call.arguments",
	"gen_ai.tool.call.result",
	"gen_ai.tool.definitions",
	"gen_ai.prompt",
	"gen_ai.completion",
}

var (
	// ErrDescriptor reports a descriptor this importer cannot serve. The
	// message names the member.
	ErrDescriptor = errors.New("otelgenai: descriptor not served")
	// ErrReceived reports a receive time no record can carry.
	ErrReceived = errors.New("otelgenai: received time refused")
)

// Check holds the members kind otel-genai-traces owns to what the importer
// reads: the pinned convention and OTLP release, a service name, and a run
// attribute that is text and no content attribute. It judges nothing
// observe.CheckNeutral judges, and a caller runs both.
func Check(d *observev1.SourceDescriptor) error {
	if d == nil {
		return fmt.Errorf("%w: absent", ErrDescriptor)
	}
	checks := []struct {
		member string
		err    error
	}{
		{"kind", exactly(d.GetKind(), observe.KindOTelGenAI)},
		{"convention.name", exactly(d.GetConvention().GetName(), ConventionName)},
		{"convention.version", exactly(d.GetConvention().GetVersion(), ConventionVersion)},
		{"otlp_version", exactly(d.GetOtlpVersion(), OTLPVersion)},
		{"select.service_name", text(d.GetSelect().GetServiceName(), true)},
		{"run_attribute", runAttribute(d.GetRunAttribute())},
	}
	for _, c := range checks {
		if c.err != nil {
			return fmt.Errorf("%w: %s: %w", ErrDescriptor, c.member, c.err)
		}
	}
	return nil
}

func exactly(got, want string) error {
	if got == want {
		return nil
	}
	if got == "" {
		return errors.New("required")
	}
	return fmt.Errorf("%s, want %q", quoted(got), want)
}

// text refuses a control or a format character, which can hide or reorder
// what an operator reads, and a value of whitespace alone, which reads as
// unset. protojson has already refused invalid UTF-8.
func text(s string, required bool) error {
	if s == "" {
		if required {
			return errors.New("required")
		}
		return nil
	}
	if len(s) > observe.MaxTextBytes {
		return fmt.Errorf("%d bytes, limit %d", len(s), observe.MaxTextBytes)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("control or format character %U in %s", r, quoted(s))
		}
	}
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("whitespace only: %s", quoted(s))
	}
	return nil
}

func runAttribute(s string) error {
	if err := text(s, false); err != nil {
		return err
	}
	if slices.Contains(ContentAttributes, s) {
		return fmt.Errorf("%q is a content attribute", s)
	}
	return nil
}

// quoted cuts s to observe.MaxTextBytes and quotes it in ASCII, so a refusal
// carries no control byte and no unbounded run of the descriptor's bytes.
func quoted(s string) string {
	if len(s) > observe.MaxTextBytes {
		return strconv.QuoteToASCII(s[:observe.MaxTextBytes]) + " (truncated)"
	}
	return strconv.QuoteToASCII(s)
}
