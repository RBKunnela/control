package gatewayconfig

import (
	"strings"
	"testing"
)

// TestACapabilityThatWritesPastAccessIsRefused: each capability that writes,
// chowns or chmods past access(2) is refused by name; a mask holding others
// alone passes; a status whose mask cannot be read is refused.
func TestACapabilityThatWritesPastAccessIsRefused(t *testing.T) {
	for _, c := range []struct{ mask, says string }{
		{"0000000000000001", "CAP_CHOWN"},
		{"0000000000000002", "CAP_DAC_OVERRIDE"},
		{"0000000000000004", "CAP_DAC_READ_SEARCH"},
		{"0000000000000008", "CAP_FOWNER"},
	} {
		err := capabilityRefusal("Name:\tgateway\nCapInh:\t0000000000000000\nCapEff:\t" + c.mask + "\n")
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("capabilityRefusal(CapEff %s) = %v, want a refusal naming %s", c.mask, err, c.says)
		}
	}
	if err := capabilityRefusal("Name:\tgateway\nCapEff:\t00000000000004f0\n"); err != nil {
		t.Errorf("capabilityRefusal of a mask without them: %v", err)
	}
	for _, status := range []string{"CapEff:\tzz\n", "Name:\tgateway\n", ""} {
		if err := capabilityRefusal(status); err == nil {
			t.Errorf("capabilityRefusal(%q) was accepted", status)
		}
	}
}
