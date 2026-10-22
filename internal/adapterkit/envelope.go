package adapterkit

import (
	"fmt"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/pkg/contract"
)

// TraceContext returns the trace id and the caller's span id a traceparent
// of version 00 names, or two empty strings for anything else. The value is
// the client's claim: it correlates a call with a trace and decides nothing.
func TraceContext(v string) (traceID, spanID string) {
	if len(v) != 55 {
		return "", ""
	}
	parts := strings.Split(v, "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return "", ""
	}
	for _, p := range parts[1:] {
		if !lowerHex(p) {
			return "", ""
		}
	}
	if allZero(parts[1]) || allZero(parts[2]) {
		return "", ""
	}
	return parts[1], parts[2]
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func allZero(s string) bool {
	return strings.Trim(s, "0") == ""
}

// HashInto puts the arguments hash in the envelope, so that even an envelope
// nothing classifies names the bytes it was about.
func HashInto(env *controlv1.ActionEnvelope, args []byte) error {
	hash, err := canon.ArgumentsHashV1(args)
	if err != nil {
		return &contract.ValidationError{Field: "arguments.canonical_hash", Err: fmt.Errorf("%w: %w", contract.ErrInvalidValue, err)}
	}
	env.Arguments = &controlv1.Arguments{CanonicalHash: hash}
	return nil
}
