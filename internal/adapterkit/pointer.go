package adapterkit

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/guardana/control/internal/gateway"
)

// ResourceID reads the resource id at pointer p in the arguments, as the
// pipeline reads it when it holds rewritten bytes to the decided resource.
func ResourceID(args []byte, p string) string {
	return gateway.ResourceID(args, p)
}

// OverlongPrefix starts the placeholder of a name or a resource id past the
// contract's bound; the digest after it ties the record to the original
// without holding it (ADR-0043).
const OverlongPrefix = "overlong:sha256:"

// Placeholder is what a name or resource id past the bound is recorded as;
// nothing stays nothing.
func Placeholder(original string) string {
	if original == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(original))
	return OverlongPrefix + hex.EncodeToString(sum[:])
}
