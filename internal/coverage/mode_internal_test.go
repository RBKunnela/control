package coverage

import (
	"errors"
	"fmt"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

// TestModeClassAgreesWithTheGateway walks the contract's enum against the
// plane's own table: a mode the plane can block in enforces, one it runs
// without blocking decides, one it refuses at start classifies nothing, and
// one it does not declare is refused here too.
func TestModeClassAgreesWithTheGateway(t *testing.T) {
	values := controlv1.EnforcementMode(0).Descriptor().Values()
	if values.Len() < 7 {
		t.Fatalf("the contract declares %d modes; this test was written for 7", values.Len())
	}
	modes := make([]controlv1.EnforcementMode, 0, values.Len()+1)
	for i := range values.Len() {
		modes = append(modes, controlv1.EnforcementMode(values.Get(i).Number()))
	}
	modes = append(modes, controlv1.EnforcementMode(values.Get(values.Len()-1).Number()+1))
	for _, mode := range modes {
		if msg := disagreement(mode); msg != "" {
			t.Errorf("%s: %s", mode, msg)
		}
	}
}

// disagreement says how classOf departs from the plane's own table for mode,
// or nothing when they agree.
func disagreement(mode controlv1.EnforcementMode) string {
	need, gerr := gateway.Requirements(mode)
	class, err := classOf(mode)
	var want modeClass
	switch {
	case errors.Is(gerr, gateway.ErrMode):
		if !errors.Is(err, ErrInput) {
			return fmt.Sprintf("the plane refuses it as configuration, classOf = %v, %v", class, err)
		}
		return ""
	case errors.Is(gerr, gateway.ErrModePlanned):
		want = modeRefused
	case gerr != nil:
		return fmt.Sprintf("Requirements: %v", gerr)
	case need.Enforcement >= gateway.EnforcementCooperative:
		want = modeEnforces
	default:
		want = modeDecides
	}
	if err != nil || class != want {
		return fmt.Sprintf("classOf = %v, %v; the plane's table says %v", class, err, want)
	}
	return ""
}
