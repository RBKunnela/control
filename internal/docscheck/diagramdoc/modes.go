package diagramdoc

import (
	"errors"
	"fmt"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

// modeTable renders one row per declared enforcement mode from what the
// gateway answers for it, with the two refusals the table rests on: the zero
// value and a number no build declares are both refused as configuration.
func modeTable() ([]byte, error) {
	values := controlv1.EnforcementMode(0).Descriptor().Values()
	var b strings.Builder
	b.WriteString("| Mode | Needs from the adapter | In this build |\n| --- | --- | --- |\n")
	undeclared := controlv1.EnforcementMode(0)
	for i := 0; i < values.Len(); i++ {
		mode := controlv1.EnforcementMode(values.Get(i).Number())
		if mode >= undeclared {
			undeclared = mode + 1
		}
		name := strings.TrimPrefix(mode.String(), "ENFORCEMENT_MODE_")
		needs, err := gateway.Requirements(mode)
		switch {
		case mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED:
			if !errors.Is(err, gateway.ErrMode) {
				return nil, fmt.Errorf("%w: the zero mode is not refused: %w", ErrBlock, err)
			}
			fmt.Fprintf(&b, "| `%s` | nothing: refused as configuration | refused at start |\n", name)
		case errors.Is(err, gateway.ErrModePlanned):
			fmt.Fprintf(&b, "| `%s` | %s | planned: refused at start |\n", name, capabilityList(needs))
		case err != nil:
			return nil, fmt.Errorf("%w: mode %s: %w", ErrBlock, name, err)
		default:
			fmt.Fprintf(&b, "| `%s` | %s | runs |\n", name, capabilityList(needs))
		}
	}
	if _, err := gateway.Requirements(undeclared); !errors.Is(err, gateway.ErrMode) {
		return nil, fmt.Errorf("%w: mode number %d, which no build declares, is not refused: %w", ErrBlock, undeclared, err)
	}
	fmt.Fprintf(&b, "| a number no build declares | nothing: refused as configuration | refused at start |\n")
	return []byte(b.String()), nil
}

func capabilityList(c gateway.Capabilities) string {
	var names []string
	for _, cap := range []struct {
		on   bool
		name string
	}{
		{c.ObserveRequest, "observe the request"}, {c.ObserveResult, "observe the result"},
		{c.Enforcement == gateway.EnforcementCooperative, "cooperative or inline enforcement"},
		{c.Enforcement == gateway.EnforcementInline, "inline enforcement"},
		{c.Authenticates, "authenticate"}, {c.BindEndUser, "bind the end user"},
		{c.SeeDelegation, "see the delegation"}, {c.SeeResourceIDs, "see resource identifiers"},
	} {
		if cap.on {
			names = append(names, cap.name)
		}
	}
	if len(names) == 0 {
		return "nothing"
	}
	return strings.Join(names, ", ")
}
