package gatewayconfig

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// writeCapabilities are the capabilities, by their bit in a status file's
// CapEff mask, that let a process write, chown or chmod what access(2) says
// it may not.
var writeCapabilities = []struct {
	bit  uint
	name string
}{{0, "CAP_CHOWN"}, {1, "CAP_DAC_OVERRIDE"}, {2, "CAP_DAC_READ_SEARCH"}, {3, "CAP_FOWNER"}}

// capabilityRefusal refuses the status of a process holding any of
// writeCapabilities, naming each, and a status whose effective mask cannot
// be read.
func capabilityRefusal(status string) error {
	for line := range strings.Lines(status) {
		mask, found := strings.CutPrefix(line, "CapEff:")
		if !found {
			continue
		}
		bits, err := strconv.ParseUint(strings.TrimSpace(mask), 16, 64)
		if err != nil {
			return fmt.Errorf("the plane's effective capabilities cannot be read: %w", err)
		}
		var held []string
		for _, c := range writeCapabilities {
			if bits&(1<<c.bit) != 0 {
				held = append(held, c.name)
			}
		}
		if len(held) > 0 {
			return fmt.Errorf("the plane holds %s, which writes past what access(2) answers", strings.Join(held, ", "))
		}
		return nil
	}
	return errors.New("the plane's status names no effective capabilities")
}
