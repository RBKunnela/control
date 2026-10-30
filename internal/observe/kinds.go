package observe

import (
	"errors"
	"fmt"
	"slices"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	// KindOTelGenAI is an agent runtime's OpenTelemetry traces under the
	// GenAI conventions.
	KindOTelGenAI = "otel-genai-traces"
	// KindEgressAccessLog is an egress proxy's access log.
	KindEgressAccessLog = "egress-access-log"
)

// Kind is what this package holds about one source kind: the descriptor
// members it owns and the trust and runs it may claim. It is the one place
// that policy lives; an importer checks the values of its kind's members and
// nothing else. The zero Kind, which LookupKind returns for a name it does not
// know, owns nothing, refuses independent trust and claims no runs.
type Kind struct {
	Name string
	// Members are the descriptor members, by proto field name, that only a
	// descriptor of this kind may carry.
	Members []string
	// Required are the Members a descriptor of this kind must carry.
	Required []string
	// Independent reports whether a descriptor of this kind may declare
	// TRUST_INDEPENDENT.
	Independent bool
	// ClaimsRuns reports whether an observation of this kind can name a run.
	ClaimsRuns bool
}

var kinds = []Kind{
	{
		Name:       KindOTelGenAI,
		Members:    []string{"convention", "otlp_version", "select", "run_attribute"},
		Required:   []string{"convention", "otlp_version", "select"},
		ClaimsRuns: true,
	},
	{
		Name:        KindEgressAccessLog,
		Members:     []string{"egress_access_log"},
		Required:    []string{"egress_access_log"},
		Independent: true,
	},
}

// neutralMembers are the descriptor members every kind carries.
var neutralMembers = []string{
	"schema_version", "source_id", "kind", "trust", "sampling", "heartbeat_seconds", "tenant_id", "project_id",
}

// Kinds returns the kind table in a copy the caller may change.
func Kinds() []Kind {
	out := make([]Kind, len(kinds))
	for i, k := range kinds {
		out[i] = k.clone()
	}
	return out
}

// LookupKind returns the row of the named kind, or the zero Kind.
func LookupKind(name string) Kind {
	for _, k := range kinds {
		if k.Name == name {
			return k.clone()
		}
	}
	return Kind{}
}

func (k Kind) clone() Kind {
	k.Members, k.Required = slices.Clone(k.Members), slices.Clone(k.Required)
	return k
}

// ReadNeutral parses a source descriptor and holds it to CheckNeutral only.
// The values of its kind's members are still unchecked: ingest.ReadDescriptor
// is the reader that runs the kind's checks after it. An enum number the
// contract does not declare is refused here, where a record would read it as
// its restrictive meaning: an operator's statement of trust is taken only as
// written.
func ReadNeutral(b []byte) (*observev1.SourceDescriptor, error) {
	if len(b) > maxDescriptorBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrDescriptor, len(b), maxDescriptorBytes)
	}
	d := &observev1.SourceDescriptor{}
	if err := unmarshalStrict(b, d); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDescriptor, err)
	}
	if err := CheckNeutral(d); err != nil {
		return nil, err
	}
	return d, nil
}

// CheckNeutral holds a descriptor to the rules every kind shares: its version
// and the members its version calls for, its identity, a kind in the table, a
// declared trust the kind allows, sampling, heartbeat, and exactly the
// members its kind owns with the required ones present. It does not judge the
// values of a kind's own members.
func CheckNeutral(d *observev1.SourceDescriptor) error {
	if d == nil {
		return fmt.Errorf("%w: absent", ErrDescriptor)
	}
	if err := checkVersion(d.GetSchemaVersion(), descriptorMinors); err != nil {
		return refuse("schema_version", err)
	}
	if err := checkDescriptorSchema(d); err != nil {
		return err
	}
	kind := LookupKind(d.GetKind())
	checks := []struct {
		member string
		err    error
	}{
		{"source_id", identifier(d.GetSourceId())},
		{"kind", knownKind(d.GetKind(), kind)},
		{"trust", trust(d.GetTrust(), kind)},
		{"sampling", declared(d.GetSampling())},
		{"heartbeat_seconds", heartbeat(d.GetHeartbeatSeconds())},
		{"tenant_id", identifier(d.GetTenantId())},
		{"project_id", identifier(d.GetProjectId())},
	}
	for _, c := range checks {
		if c.err != nil {
			return refuse(c.member, c.err)
		}
	}
	return checkMembers(d, kind)
}

func knownKind(name string, k Kind) error {
	switch {
	case name == "":
		return errors.New("required")
	case k.Name == "":
		return fmt.Errorf("%s is not a kind this build reads", quoted(name, maxIdentifierBytes))
	}
	return nil
}

// trust refuses TRUST_INDEPENDENT for a kind whose records the agent's own
// process can write.
func trust(t observev1.Trust, k Kind) error {
	if t == observev1.Trust_TRUST_UNSPECIFIED {
		return errors.New("required")
	}
	if err := declared(t); err != nil {
		return err
	}
	if t == observev1.Trust_TRUST_INDEPENDENT && !k.Independent {
		return fmt.Errorf("%s is refused for kind %q", t, k.Name)
	}
	return nil
}

// checkMembers refuses a member that is neither neutral nor the kind's own,
// so a member of another kind, or one no kind owns, never rides along unread.
func checkMembers(d *observev1.SourceDescriptor, k Kind) error {
	m := d.ProtoReflect()
	var err error
	m.Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		name := string(fd.Name())
		if slices.Contains(neutralMembers, name) || slices.Contains(k.Members, name) {
			return true
		}
		err = refuse(name, fmt.Errorf("not a member of kind %q", k.Name))
		return false
	})
	if err != nil {
		return err
	}
	fields := m.Descriptor().Fields()
	for _, name := range k.Required {
		fd := fields.ByName(protoreflect.Name(name))
		if fd == nil || !m.Has(fd) {
			return refuse(name, fmt.Errorf("required for kind %q", k.Name))
		}
	}
	return nil
}

// checkDescriptorSchema holds a descriptor to the version its members call
// for: 0.2 exactly when it carries egress_access_log. The refusal is not
// ErrVersion, since the version itself is one this package reads.
func checkDescriptorSchema(d *observev1.SourceDescriptor) error {
	has := d.GetEgressAccessLog() != nil
	switch v := d.GetSchemaVersion(); {
	case v == descriptorSchema01 && has:
		return refuse("egress_access_log", fmt.Errorf("not a member of schema %q", descriptorSchema01))
	case v == descriptorSchema02 && !has:
		return refuse("schema_version", fmt.Errorf("%q on a descriptor with no member of %q", descriptorSchema02, descriptorSchema02))
	}
	return nil
}
