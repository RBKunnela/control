//go:build linux || darwin

package gatewayconfig

import (
	"os"
	"strings"
	"testing"
)

// unixExport sets the document's endpoint to a unix socket with the account
// its collector runs as, and leaves allow_plaintext off.
func unixExport(t *testing.T, endpoint, uid string) {
	t.Helper()
	setEnv(t, "export.endpoint", endpoint)
	setEnv(t, "export.allow_plaintext", "false")
	if uid != "" {
		setEnv(t, "export.collector_uid", uid)
	}
}

// TestAUnixEndpointNamesItsCollectorsAccount: unix:///path with a numeric
// user id loads, and the id is read as a literal says.
func TestAUnixEndpointNamesItsCollectorsAccount(t *testing.T) {
	path := write(t, "")
	unixExport(t, "unix:///run/collector/logs.sock", "4242")
	cfg := load(t, path)
	if got, ok := UnixEndpoint(cfg.Export.Endpoint); !ok || got != "/run/collector/logs.sock" {
		t.Errorf("UnixEndpoint = %q, %v", got, ok)
	}
	if cfg.Export.CollectorUID != (AccountID{ID: 4242, Set: true}) {
		t.Errorf("export.collector_uid = %+v, want 4242", cfg.Export.CollectorUID)
	}
	if _, ok := UnixEndpoint("https://127.0.0.1:4318/v1/logs"); ok {
		t.Error("an https endpoint is read as a unix one")
	}
}

// TestAUnixEndpointIsRefusedWithoutWhatChecksIt: each configuration breaks
// one rule of a unix endpoint or an account key, and the refusal names the
// key.
func TestAUnixEndpointIsRefusedWithoutWhatChecksIt(t *testing.T) {
	for name, tc := range map[string]struct {
		endpoint, uid, plaintext, want string
	}{
		"no collector account":            {"unix:///run/c.sock", "", "false", "export.collector_uid: a unix endpoint needs"},
		"a relative path":                 {"unix://run/c.sock", "7", "false", "export.endpoint: a unix endpoint is"},
		"one slash":                       {"unix:/run/c.sock", "7", "false", "export.endpoint: a unix endpoint is"},
		"a path that is not clean":        {"unix:///run/../c.sock", "7", "false", "export.endpoint: a unix endpoint is"},
		"a query":                         {"unix:///run/c.sock?x=1", "7", "false", "export.endpoint: a unix endpoint is"},
		"a fragment":                      {"unix:///run/c.sock#x", "7", "false", "export.endpoint: a unix endpoint is"},
		"no path":                         {"unix://", "7", "false", "export.endpoint: a unix endpoint is"},
		"an account on an https endpoint": {"https://127.0.0.1:4318/v1/logs", "7", "false", "export.collector_uid: only a unix:// endpoint"},
		"an id past the bound":            {"unix:///run/c.sock", "4294967295", "false", "not an account's numeric user id"},
		"a negative id":                   {"unix:///run/c.sock", "-1", "false", "not an account's numeric user id"},
		"a name for an id":                {"unix:///run/c.sock", "collector", "false", "not an account's numeric user id"},
	} {
		t.Run(name, func(t *testing.T) {
			path := write(t, "")
			setEnv(t, "export.endpoint", tc.endpoint)
			setEnv(t, "export.allow_plaintext", tc.plaintext)
			if tc.uid != "" {
				setEnv(t, "export.collector_uid", tc.uid)
			}
			_, err := Load(path, os.Environ())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load = %v, want a refusal holding %q", err, tc.want)
			}
		})
	}
}

// TestAUnixEndpointsPathFitsASocketAddress: a socket path of 103 bytes, the
// most a socket address holds, loads, and one of 104 is refused at load with
// both lengths named.
func TestAUnixEndpointsPathFitsASocketAddress(t *testing.T) {
	socket := func(n int) string {
		base := "/run/collector/"
		return base + strings.Repeat("s", n-len(base))
	}
	path := write(t, "")
	unixExport(t, "unix://"+socket(103), "7")
	if got, _ := UnixEndpoint(load(t, path).Export.Endpoint); len(got) != 103 {
		t.Fatalf("the socket path loaded is %d bytes, want 103", len(got))
	}
	path = write(t, "")
	unixExport(t, "unix://"+socket(104), "7")
	_, err := Load(path, os.Environ())
	if err == nil || !strings.Contains(err.Error(), "export.endpoint: the socket path is 104 bytes, and a socket path is at most 103") {
		t.Errorf("Load = %v, want the 104-byte path refused", err)
	}
}

// TestTheLargestAccountIDIsTaken: the bound refuses (uid_t)-1 and nothing
// below it.
func TestTheLargestAccountIDIsTaken(t *testing.T) {
	path := write(t, "")
	unixExport(t, "unix:///run/c.sock", "4294967294")
	if got := load(t, path).Export.CollectorUID; got != (AccountID{ID: 4294967294, Set: true}) {
		t.Errorf("export.collector_uid = %+v", got)
	}
}

// TestTheHealthSocketIsRead: the socket and the one other account it answers
// load, and an account without a socket, or a socket that is the
// enforcement API's, is refused.
func TestTheHealthSocketIsRead(t *testing.T) {
	cfg := load(t, write(t, "health:\n  socket: health.sock\n  socket_uid: 0\n"))
	if cfg.Health.Socket != "health.sock" || cfg.Health.SocketUID != (AccountID{ID: 0, Set: true}) {
		t.Errorf("health = %+v", cfg.Health)
	}
	if got := load(t, write(t, "")).Health; got.Socket != "" || got.SocketUID.Set {
		t.Errorf("a health socket is configured by default: %+v", got)
	}
	_, err := Load(write(t, "health:\n  socket_uid: 0\n"), os.Environ())
	if err == nil || !strings.Contains(err.Error(), "health.socket_uid: names who may read health.socket, which is not set") {
		t.Errorf("an account without a socket: %v", err)
	}
}

// TestTheHealthSocketIsNotTheEnforcementAPIs: one path cannot be both.
func TestTheHealthSocketIsNotTheEnforcementAPIs(t *testing.T) {
	refusedSaying(t, enforceDocument, map[string]string{"health.socket": "/run/plane/enforce.sock"},
		"health.socket: it is listener.socket too")
	if _, err := Load(writeDocument(t, enforceDocument+"health:\n  socket: /run/plane/health.sock\n"), os.Environ()); err != nil {
		t.Errorf("a health socket beside the enforcement API's: %v", err)
	}
}
