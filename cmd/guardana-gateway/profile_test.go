package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/guardana/control/internal/gatewayconfig"
)

// TestTheFilesystemProfileIsAConfigurationThisBuildReads: the profile the
// connect guide ships loads once its collector's account is filled in, serves
// stateful HTTP, names the approval-for-writes
// pack's bundle, and classifies the fourteen tools of the server version it
// names, each once, on its one upstream, with the resource each one reads. Whether the fingerprints still match
// that server takes the server itself, which this test does not start.
func TestTheFilesystemProfileIsAConfigurationThisBuildReads(t *testing.T) {
	root := filepath.Join("..", "..")
	raw, err := os.ReadFile("../../examples/connect-a-filesystem-server/plane.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "collector_uid: COLLECTOR_UID_FROM_ID\n") != 1 {
		t.Fatal("the profile names no collector account to fill in")
	}
	profile := filepath.Join(t.TempDir(), "plane.yaml")
	if err := os.WriteFile(profile, bytes.Replace(raw, []byte("COLLECTOR_UID_FROM_ID"), []byte("1001"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := gatewayconfig.Load(profile, nil)
	if err != nil {
		t.Fatalf("the profile does not load: %v", err)
	}
	bundle := packBundleID(t, filepath.Join(root, "examples", "starter-packs", "approval-for-writes", "policy.json"))
	if cfg.Listener.Kind != "stateful_http" || cfg.Policy.BundleID != bundle || len(cfg.Upstreams) != 1 {
		t.Fatalf("listener %q, bundle %q (the pack's is %q), %d upstream(s)", cfg.Listener.Kind, cfg.Policy.BundleID, bundle, len(cfg.Upstreams))
	}
	got := profileClasses(t, cfg.Overrides, cfg.Upstreams[0].Name)
	read := func(rtype, from string) string { return "READ " + rtype + " " + from + " TRUSTED_INTERNAL" }
	write := func(rtype, from string) string { return "WRITE " + rtype + " " + from + " TRUSTED_INTERNAL" }
	want := map[string]string{
		"read_file": read("file", "/path"), "read_text_file": read("file", "/path"), "read_media_file": read("file", "/path"),
		"read_multiple_files": read("file", ""), "list_directory": read("directory", "/path"),
		"list_directory_with_sizes": read("directory", "/path"), "directory_tree": read("directory", "/path"),
		"search_files": read("directory", "/path"), "get_file_info": read("file", "/path"),
		"list_allowed_directories": read("directory", ""),
		"write_file":               write("file", "/path"), "edit_file": write("file", "/path"),
		"create_directory": write("directory", "/path"), "move_file": write("file", "/source"),
	}
	if len(got) != len(want) {
		t.Errorf("%d tools classified, want %d", len(got), len(want))
	}
	for tool, class := range want {
		if got[tool] != class {
			t.Errorf("%s is classified %q, want %q", tool, got[tool], class)
		}
	}
}

// packBundleID is the bundle id a starter pack's document names.
func packBundleID(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a pack this repository ships
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Bundle struct {
			ID string `json:"id"`
		} `json:"bundle"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil || pack.Bundle.ID == "" {
		t.Fatalf("reading the pack's bundle id: %v", err)
	}
	return pack.Bundle.ID
}

// profileClasses maps each overridden tool to its effect, resource type,
// resource pointer and trust zone, and fails an override that names another
// upstream, repeats a tool or carries no fingerprint.
func profileClasses(t *testing.T, overrides []gatewayconfig.OverrideConfig, upstream string) map[string]string {
	t.Helper()
	fingerprint := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	classes := map[string]string{}
	for _, o := range overrides {
		if _, twice := classes[o.Tool]; twice || o.Upstream != upstream || !fingerprint.MatchString(o.Fingerprint) {
			t.Errorf("override %+v", o)
		}
		classes[o.Tool] = o.Effect + " " + o.ResourceType + " " + o.ResourceFrom + " " + o.TrustZone
	}
	return classes
}
