package observe

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// MaxHeartbeatSeconds is one week.
const MaxHeartbeatSeconds = 604800

// MaxTextBytes bounds a string copied from a descriptor or an input into a record.
const MaxTextBytes = 256

const (
	maxDescriptorBytes = 64 << 10
	maxIdentifierBytes = 128
)

// ErrDescriptor reports a source descriptor this package refuses. The message
// names the member.
var ErrDescriptor = errors.New("observe: source descriptor refused")

func refuse(member string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrDescriptor, member, err)
}

// DescriptorSHA256 is the lowercase hex SHA-256 of a descriptor's bytes.
func DescriptorSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
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
