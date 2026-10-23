package classify

import (
	"fmt"
	"strings"
)

// ErrPointer is a resource pointer that is not RFC 6901 or is outside the
// bound.
const ErrPointer Sentinel = "classify: the resource pointer is not RFC 6901 or is outside the bound"

// Bounds on a resource pointer: enough for any argument shape a tool reads,
// and small enough that resolving one costs nothing.
const (
	MaxPointerTokens    = 8
	MaxPointerTokenSize = 64
)

// CheckPointer refuses a resource pointer that is not RFC 6901 or is outside
// the bound with ErrPointer. The empty pointer names no resource and is
// allowed. The refusal never repeats the pointer, which a configuration may
// hold anything in.
func CheckPointer(p string) error {
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: it does not start with /", ErrPointer)
	}
	tokens := strings.Split(p[1:], "/")
	if len(tokens) > MaxPointerTokens {
		return fmt.Errorf("%w: %d tokens, limit %d", ErrPointer, len(tokens), MaxPointerTokens)
	}
	for _, tok := range tokens {
		if len(tok) > MaxPointerTokenSize {
			return fmt.Errorf("%w: a token of %d bytes, limit %d", ErrPointer, len(tok), MaxPointerTokenSize)
		}
		for i := 0; i < len(tok); i++ {
			if tok[i] == '~' && (i+1 >= len(tok) || (tok[i+1] != '0' && tok[i+1] != '1')) {
				return fmt.Errorf("%w: a ~ that escapes neither ~ nor /", ErrPointer)
			}
		}
	}
	return nil
}
