package gatewayconfig

import (
	"errors"
	"strings"
	"testing"
)

// TestTheCapabilitiesAreReadBeforeTheKernelIsAsked: a status naming a
// capability that writes past access(2), or no status at all, refuses the
// question; a clean one lets it be asked.
func TestTheCapabilitiesAreReadBeforeTheKernelIsAsked(t *testing.T) {
	dir := tempDir(t)
	was := procStatus
	t.Cleanup(func() { procStatus = was })
	procStatus = func() ([]byte, error) { return []byte("Name:\tgateway\nCapEff:\t0000000000000002\n"), nil }
	if _, err := accessWrite(dir); err == nil || !strings.Contains(err.Error(), "CAP_DAC_OVERRIDE") {
		t.Errorf("accessWrite holding CAP_DAC_OVERRIDE = %v, want a refusal naming it", err)
	}
	procStatus = func() ([]byte, error) { return nil, errors.New("no status") }
	if _, err := accessWrite(dir); err == nil {
		t.Error("accessWrite with no status to read was answered")
	}
	procStatus = func() ([]byte, error) { return []byte("CapEff:\t0000000000000000\n"), nil }
	if _, err := accessWrite(dir); err != nil {
		t.Errorf("accessWrite with no capability: %v", err)
	}
}
