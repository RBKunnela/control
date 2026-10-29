package gateway

import (
	"fmt"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
)

// modeRow is what one enforcement mode needs from the adapter, and whether
// this build enforces it.
type modeRow struct {
	needs       Capabilities
	implemented bool
}

// observe is what every mode that records needs: to see the call and the
// answer.
var observe = Capabilities{ObserveRequest: true, ObserveResult: true}

// enforce is observe plus a decision someone enforces: the adapter itself, or
// the caller it hands the decision to (ADR-0051).
var enforce = Capabilities{ObserveRequest: true, ObserveResult: true, Enforcement: EnforcementCooperative}

// modes is the table ADR-0013 names, one row per declared mode. UNSPECIFIED is
// absent on purpose: it is refused as configuration, not mapped. SHADOW acts
// on the enforced decision and only records the candidate, so it needs to
// block.
var modes = map[controlv1.EnforcementMode]modeRow{
	controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE:  {needs: observe, implemented: true},
	controlv1.EnforcementMode_ENFORCEMENT_MODE_SHADOW:   {needs: enforce},
	controlv1.EnforcementMode_ENFORCEMENT_MODE_WARN:     {needs: observe},
	controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE:  {needs: enforce, implemented: true},
	controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE:  {needs: enforce, implemented: true},
	controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN: {needs: enforce, implemented: true},
}

// Requirements returns the capabilities mode needs from an adapter. It refuses
// the zero value and any number the contract does not declare with ErrMode,
// and a declared mode this build does not enforce with ErrModePlanned beside
// the capabilities its row names, so the row is readable before it is built.
func Requirements(mode controlv1.EnforcementMode) (Capabilities, error) {
	if mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
		return Capabilities{}, fmt.Errorf("%w: the zero value names no mode", ErrMode)
	}
	row, ok := modes[mode]
	if !ok {
		return Capabilities{}, fmt.Errorf("%w: mode %d is not declared in this build", ErrMode, mode)
	}
	if !row.implemented {
		return row.needs, fmt.Errorf("%w: %s", ErrModePlanned, mode)
	}
	return row.needs, nil
}

// checkAdapter refuses, at start, an adapter that cannot enforce mode or
// declares an enforcement this build does not know, an adapter named after no
// protocol or declaring another strength than its protocol's, an adapter that
// declares an obligation the catalogue lacks, and an adapter that binds an end
// user on a listener that authenticates nobody.
func checkAdapter(mode controlv1.EnforcementMode, name string, caps Capabilities) error {
	need, err := Requirements(mode)
	if err != nil {
		return err
	}
	if caps.Enforcement > EnforcementInline || !caps.covers(need) {
		return fmt.Errorf("%w: %s under %s", ErrCapability, name, mode)
	}
	if !channel.KnownProtocol(name) {
		return fmt.Errorf("%w: %q", ErrProtocol, name)
	}
	if caps.Enforcement != channel.StrengthOf(name) {
		return fmt.Errorf("%w: %s", ErrStrength, name)
	}
	if err := checkObligations(caps.Obligations); err != nil {
		return err
	}
	if caps.BindEndUser && !caps.Authenticates {
		return fmt.Errorf("%w: %s", ErrUnauthenticatedBinding, name)
	}
	return nil
}
