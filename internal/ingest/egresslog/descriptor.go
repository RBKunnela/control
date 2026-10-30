package egresslog

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Format is the one input format a descriptor may name.
const Format = "json-lines"

// MaxMemberNameBytes bounds a member name the mapping gives.
const MaxMemberNameBytes = 128

// ReadLabel names what the import's read count counts: lines.
const ReadLabel = "lines_read"

var (
	// ErrDescriptor reports a descriptor this importer cannot serve. The
	// message names the member.
	ErrDescriptor = errors.New("egresslog: descriptor not served")
	// ErrReceived reports a receive time no record can carry.
	ErrReceived = errors.New("egresslog: received time refused")
)

// Check holds the members kind egress-access-log owns to what the importer
// can read: the one format, a mapping whose names are distinct, text and at
// most MaxMemberNameBytes, time and destination mapped, a declared time
// format and destination form, and a declared caller basis exactly when a
// caller is mapped. It
// judges nothing observe.CheckNeutral judges, and a caller runs both.
func Check(d *observev1.SourceDescriptor) error {
	if d == nil {
		return fmt.Errorf("%w: absent", ErrDescriptor)
	}
	if d.GetKind() != observe.KindEgressAccessLog {
		return refuse("kind", fmt.Errorf("%q, want %q", d.GetKind(), observe.KindEgressAccessLog))
	}
	e := d.GetEgressAccessLog()
	if e == nil {
		return refuse("egress_access_log", errors.New("required"))
	}
	if e.GetFormat() != Format {
		return refuse("format", fmt.Errorf("%q, want %q", e.GetFormat(), Format))
	}
	if _, err := mapping(e.GetFields()); err != nil {
		return err
	}
	return callerBasis(e)
}

// mapping checks the fields and returns the field each mapped name stands
// for.
func mapping(f *observev1.EgressFields) (map[string]field, error) {
	names := map[string]field{}
	for _, m := range fieldMembers(f) {
		if m.name == "" {
			if m.field == fieldTime || m.field == fieldDestination {
				return nil, refuse("fields."+m.field.String(), errors.New("required"))
			}
			continue
		}
		if err := memberName(m.name); err != nil {
			return nil, refuse("fields."+m.field.String(), err)
		}
		if other, ok := names[m.name]; ok {
			return nil, refuse("fields."+m.field.String(), fmt.Errorf("%q is also fields.%s", m.name, other))
		}
		names[m.name] = m.field
	}
	format := f.GetTimeFormat()
	if format == observev1.TimeFormat_TIME_FORMAT_UNSPECIFIED || !declared(format) {
		return nil, refuse("fields.time_format", fmt.Errorf("%d is not a declared format", format))
	}
	if form := f.GetDestinationForm(); form == observev1.DestinationForm_DESTINATION_FORM_UNSPECIFIED || !declared(form) {
		return nil, refuse("fields.destination_form", fmt.Errorf("%d is not a declared form", form))
	}
	return names, nil
}

func callerBasis(e *observev1.EgressAccessLog) error {
	b := e.GetCallerBasis()
	mapped := e.GetFields().GetCaller() != ""
	switch {
	case mapped && (b == observev1.CallerBasis_CALLER_BASIS_UNSPECIFIED || !declared(b)):
		return refuse("caller_basis", fmt.Errorf("%d is not a declared basis, and a mapped caller needs one", b))
	case !mapped && b != observev1.CallerBasis_CALLER_BASIS_UNSPECIFIED:
		return refuse("caller_basis", fmt.Errorf("%s with no caller mapped", b))
	}
	return nil
}

// memberName holds a mapped name to the text rules a descriptor's strings
// keep.
func memberName(s string) error {
	if len(s) > MaxMemberNameBytes {
		return fmt.Errorf("%d bytes, limit %d", len(s), MaxMemberNameBytes)
	}
	if !observe.CopyableText(s) {
		return fmt.Errorf("%q holds a control or format character or is only whitespace", s)
	}
	return nil
}

// InputForbidden is the permission bits an input file may not carry under
// this descriptor: under independent trust, writable by group or others, since
// independent states that the agent cannot write the log. The command reads
// the input refusing these bits, judged from the descriptor it opened.
func InputForbidden(d *observev1.SourceDescriptor) fs.FileMode {
	if observe.TrustOf(d.GetTrust()) == observev1.Trust_TRUST_INDEPENDENT {
		return 0o022
	}
	return 0
}

// checkDescriptor is what Import serves: a descriptor through both halves of
// its checks and a digest in the one form a record carries.
func checkDescriptor(d *observev1.SourceDescriptor, sha string) error {
	if d == nil {
		return fmt.Errorf("%w: absent", ErrDescriptor)
	}
	if err := observe.CheckNeutral(d); err != nil {
		return fmt.Errorf("%w: %w", ErrDescriptor, err)
	}
	if err := Check(d); err != nil {
		return err
	}
	if len(sha) != 64 || strings.Trim(sha, "0123456789abcdef") != "" {
		return fmt.Errorf("%w: descriptor digest is not 64 lowercase hex digits", ErrDescriptor)
	}
	return nil
}

func refuse(member string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrDescriptor, member, err)
}

type enum interface {
	Descriptor() protoreflect.EnumDescriptor
	Number() protoreflect.EnumNumber
}

func declared(e enum) bool { return e.Descriptor().Values().ByNumber(e.Number()) != nil }
