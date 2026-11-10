package gatewayconfig

import (
	"os"
	"strings"
	"testing"
)

// exportLine is the document's collector endpoint, an https URL.
const exportLine = "  endpoint: https://127.0.0.1:4318/v1/logs\n"

// TestAnHTTPSCollectorLoads: the document's https endpoint loads with no
// plaintext setting, and so does an explicit false.
func TestAnHTTPSCollectorLoads(t *testing.T) {
	if !strings.Contains(document, exportLine) || strings.Contains(document, "allow_plaintext") {
		t.Fatal("the document no longer exports to an https collector alone")
	}
	if got := load(t, write(t, "")).Export.Endpoint; got != "https://127.0.0.1:4318/v1/logs" {
		t.Errorf("export.endpoint = %q", got)
	}
	path := write(t, "")
	setEnv(t, "export.endpoint", "https://collector.example/v1/logs")
	setEnv(t, "export.allow_plaintext", "false")
	if cfg := load(t, path); cfg.Export.AllowPlaintext {
		t.Error("export.allow_plaintext: false reads as true")
	}
}

// TestPlaintextExportIsRefusedNamingTheRelease: an http endpoint, on the
// loopback or not, and export.allow_plaintext set true beside any endpoint
// are refused at load, each naming the release that removed plaintext export
// and the two ways that remain, and never printing the endpoint's userinfo.
func TestPlaintextExportIsRefusedNamingTheRelease(t *testing.T) {
	for name, tc := range map[string]struct {
		endpoint, plaintext, uid, key string
	}{
		"http on the loopback":            {"http://127.0.0.1:4318/v1/logs", "false", "", "export.endpoint: "},
		"http under the old setting":      {"http://127.0.0.1:4318/v1/logs", "true", "", "export.allow_plaintext: "},
		"http to another host":            {"http://collector.example:4318/v1/logs", "false", "", "export.endpoint: "},
		"http carrying a credential":      {"http://user:hunter2@127.0.0.1:4318/v1/logs", "false", "", "export.endpoint: "},
		"an upper-case scheme":            {"HTTP://127.0.0.1:4318/v1/logs", "false", "", "export.endpoint: "},
		"the old setting beside https":    {"https://collector.example/v1/logs", "true", "", "export.allow_plaintext: "},
		"the old setting beside a socket": {"unix:///run/c.sock", "true", "7", "export.allow_plaintext: "},
	} {
		t.Run(name, func(t *testing.T) {
			path := write(t, "")
			setEnv(t, "export.endpoint", tc.endpoint)
			setEnv(t, "export.allow_plaintext", tc.plaintext)
			if tc.uid != "" {
				setEnv(t, "export.collector_uid", tc.uid)
			}
			_, err := Load(path, os.Environ())
			if err == nil {
				t.Fatal("Load accepted it")
			}
			msg := err.Error()
			for _, want := range []string{tc.key, "removed in 0.17", "unix:///path with export.collector_uid", "https://"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal %q does not say %q", msg, want)
				}
			}
			if strings.Contains(msg, "hunter2") {
				t.Errorf("the refusal %q prints the endpoint's credential", msg)
			}
		})
	}
}

// TestACollectorEndpointThatIsNoneOfTheTwoIsRefused: a scheme that is
// neither unix nor https, and an https URL with no host, are refused naming
// the two forms, without the value's credential.
func TestACollectorEndpointThatIsNoneOfTheTwoIsRefused(t *testing.T) {
	for _, endpoint := range []string{"ftp://collector.example/v1/logs", "https:///v1/logs", "collector:4318",
		"grpc://user:hunter2@collector:4317"} {
		path := write(t, "")
		setEnv(t, "export.endpoint", endpoint)
		_, err := Load(path, os.Environ())
		if err == nil || !strings.Contains(err.Error(), "export.endpoint: ") ||
			!strings.Contains(err.Error(), "is not unix:///path or an https URL") || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: Load = %v", endpoint, err)
		}
	}
}
