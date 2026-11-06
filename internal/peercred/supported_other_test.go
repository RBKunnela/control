//go:build !linux && !darwin

package peercred_test

import (
	"errors"
	"testing"

	"github.com/guardana/control/internal/peercred"
)

// TestAnUnsupportedPlatformRefuses: where the platform names no peer, a
// Unix socket's peer is refused, never read as uid zero.
func TestAnUnsupportedPlatformRefuses(t *testing.T) {
	a, b, err := pair()
	if err != nil {
		t.Skip("no Unix socket pair on this platform:", err)
	}
	defer a.Close() //nolint:errcheck // a test's connection
	defer b.Close() //nolint:errcheck // a test's connection
	if _, err := peercred.UID(a); !errors.Is(err, peercred.ErrUnsupported) {
		t.Errorf("an unsupported platform: %v, want ErrUnsupported", err)
	}
}
