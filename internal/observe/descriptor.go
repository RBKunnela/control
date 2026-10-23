package observe

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	// KindOTelGenAI is the one source kind this version reads.
	KindOTelGenAI = "otel-genai-traces"
	// ConventionName names the GenAI semantic conventions the input is read
	// under.
	ConventionName = "opentelemetry.gen_ai"
	// ConventionVersion pins them: they are still in development, so no
	// other version is assumed to mean the same.
	ConventionVersion = "1.41.0"
	// OTLPVersion pins the OTLP release whose JSON encoding the input uses.
	OTLPVersion = "1.11.1"
	// MaxHeartbeatSeconds is one week.
	MaxHeartbeatSeconds = 604800
)

// MaxTextBytes bounds a string copied from a descriptor or an input into a record.
const MaxTextBytes = 256

const (
	maxDescriptorBytes = 64 << 10
	maxIdentifierBytes = 128
)

// ContentAttributes are the GenAI attributes that carry what a prompt or a
// tool held. A descriptor's run_attribute may not name one, and an importer
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

// ErrDescriptor reports a source descriptor this package refuses. The message
// names the member.
var ErrDescriptor = errors.New("observe: source descriptor refused")

// ReadDescriptor parses an operator's source descriptor and enforces every
// rule of ADR-0040. An enum number the contract does not declare is refused
// here, where a record would read it as its restrictive meaning: an operator's
// statement of trust is taken only as written.
func ReadDescriptor(b []byte) (*observev1.SourceDescriptor, error) {
	if len(b) > maxDescriptorBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrDescriptor, len(b), maxDescriptorBytes)
	}
	d := &observev1.SourceDescriptor{}
	if err := unmarshalStrict(b, d); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDescriptor, err)
	}
	if err := checkDescriptor(d); err != nil {
		return nil, err
	}
	return d, nil
}

func checkDescriptor(d *observev1.SourceDescriptor) error {
	if err := checkVersion(d.GetSchemaVersion(), descriptorMinors); err != nil {
		return refuse("schema_version", err)
	}
	checks := []struct {
		member string
		err    error
	}{
		{"source_id", identifier(d.GetSourceId())},
		{"kind", exactly(d.GetKind(), KindOTelGenAI)},
		{"trust", trust(d.GetTrust())},
		{"convention.name", exactly(d.GetConvention().GetName(), ConventionName)},
		{"convention.version", exactly(d.GetConvention().GetVersion(), ConventionVersion)},
		{"otlp_version", exactly(d.GetOtlpVersion(), OTLPVersion)},
		{"select.service_name", text(d.GetSelect().GetServiceName(), true)},
		{"sampling", declared(d.GetSampling())},
		{"heartbeat_seconds", heartbeat(d.GetHeartbeatSeconds())},
		{"tenant_id", identifier(d.GetTenantId())},
		{"project_id", identifier(d.GetProjectId())},
		{"run_attribute", runAttribute(d.GetRunAttribute())},
	}
	for _, c := range checks {
		if c.err != nil {
			return refuse(c.member, c.err)
		}
	}
	return nil
}

func refuse(member string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrDescriptor, member, err)
}

// DescriptorSHA256 is the lowercase hex SHA-256 of a descriptor's bytes.
func DescriptorSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func exactly(got, want string) error {
	if got == want {
		return nil
	}
	if got == "" {
		return errors.New("required")
	}
	return fmt.Errorf("%s, want %q", quoted(got, MaxTextBytes), want)
}

// identifier holds source, tenant and project ids to a set no reader can
// mistake for a separator, a path or a control sequence.
func identifier(s string) error {
	if s == "" {
		return errors.New("required")
	}
	if len(s) > maxIdentifierBytes {
		return fmt.Errorf("%d bytes, limit %d", len(s), maxIdentifierBytes)
	}
	for i := range len(s) {
		if !identifierByte(s[i]) {
			return fmt.Errorf("byte %d of %s is outside [A-Za-z0-9._:-]", i, quoted(s, maxIdentifierBytes))
		}
	}
	return nil
}

func identifierByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '.' || c == '_' || c == ':' || c == '-'
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
	if len(s) > MaxTextBytes {
		return fmt.Errorf("%d bytes, limit %d", len(s), MaxTextBytes)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("control or format character %U in %s", r, quoted(s, MaxTextBytes))
		}
	}
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("whitespace only: %s", quoted(s, MaxTextBytes))
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

// trust refuses TRUST_INDEPENDENT because this kind's spans are written by
// the agent's own process.
func trust(t observev1.Trust) error {
	if t == observev1.Trust_TRUST_UNSPECIFIED {
		return errors.New("required")
	}
	if err := declared(t); err != nil {
		return err
	}
	if t == observev1.Trust_TRUST_INDEPENDENT {
		return fmt.Errorf("%s is refused for kind %q, whose spans the agent writes", t, KindOTelGenAI)
	}
	return nil
}

type enum interface {
	Descriptor() protoreflect.EnumDescriptor
	Number() protoreflect.EnumNumber
}

func declared(e enum) error {
	if e.Descriptor().Values().ByNumber(e.Number()) == nil {
		return fmt.Errorf("%d is not a declared value", e.Number())
	}
	return nil
}

func heartbeat(s uint32) error {
	if s < 1 || s > MaxHeartbeatSeconds {
		return fmt.Errorf("%d, want 1 to %d", s, MaxHeartbeatSeconds)
	}
	return nil
}
