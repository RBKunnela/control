//go:build !linux && !darwin

package gatewayconfig

import (
	"os"
	"strings"
	"testing"
)

// TestAPeerCheckedKeyIsRefusedWhereNoPeerIsNamed: on a platform that cannot
// name a socket peer's account, a unix endpoint and a health socket are
// refused at load rather than served to anyone.
func TestAPeerCheckedKeyIsRefusedWhereNoPeerIsNamed(t *testing.T) {
	path := write(t, "")
	setEnv(t, "export.endpoint", "unix:///run/c.sock")
	setEnv(t, "export.allow_plaintext", "false")
	setEnv(t, "export.collector_uid", "7")
	if _, err := Load(path, os.Environ()); err == nil || !strings.Contains(err.Error(), "export.endpoint: this platform cannot name") {
		t.Errorf("a unix endpoint: %v", err)
	}
	if _, err := Load(write(t, "health:\n  socket: health.sock\n"), os.Environ()); err == nil || !strings.Contains(err.Error(), "health.socket: this platform cannot name") {
		t.Errorf("a health socket: %v", err)
	}
}
