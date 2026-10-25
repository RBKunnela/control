package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/guardana/control/internal/policy"
)

const paramRefusal = "rules: a parameter the obligation's type does not declare or requires"

// legacyCaseDir holds one case: the obligated read with an advisory cap_rate
// carrying per_minute, which the parameter check refuses and Load takes.
func legacyCaseDir(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "cases", "obligated-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	const anchor = `"fields": "ssn"
            }
          }`
	if strings.Count(string(raw), anchor) != 1 {
		t.Fatalf("obligated-read.json no longer holds its one redact_fields obligation as this test spells it")
	}
	legacy := strings.Replace(string(raw), anchor, anchor+`,
          {"type": "cap_rate", "params": {"per_minute": "60"}, "advisory": true}`, 1)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "legacy.json"), []byte(legacy), 0o600); err != nil { //nolint:gosec // G703: a path in this test's own directory
		t.Fatal(err)
	}
	return dir
}

// TestPolicyExplainExplainsWhatSigningRefuses: explain explains a document a
// plane loads although signing refuses it, while policy test and lint, which
// sign or stand for signing, refuse it for the parameter.
func TestPolicyExplainExplainsWhatSigningRefuses(t *testing.T) {
	dir := legacyCaseDir(t)
	path := filepath.Join(dir, "legacy.json")

	code, stdout, stderr := invoke(t, "policy", "explain", path)
	if code != exitOK || stderr != "" || !strings.Contains(stdout, "redacted-reads") || !strings.Contains(stdout, "expect: met") {
		t.Errorf("explain: exit %d, stdout %q, stderr %q; want 0 explaining the rule with its expect met", code, stdout, stderr)
	}

	code, stdout, _ = invoke(t, "policy", "test", dir)
	if code != exitFail || !strings.Contains(stdout, "FAIL legacy.json: ") || !strings.Contains(stdout, paramRefusal) ||
		strings.Contains(stdout, string(policy.ErrDocument)) {
		t.Errorf("test: exit %d, stdout %q; want 1 with the parameter's refusal and not the document's", code, stdout)
	}

	code, _, stderr = invoke(t, "policy", "lint", writeDocumentOf(t, path))
	if code != exitFail || !strings.Contains(stderr, paramRefusal) {
		t.Errorf("lint: exit %d, stderr %q; want 1 with the parameter's refusal", code, stderr)
	}
}

// writeDocumentOf writes the document member of the case at path to a file
// of its own, as an author lints it.
func writeDocumentOf(t *testing.T, path string) string {
	t.Helper()
	raw, err := readBounded(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := readCaseExpecting(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	return write(t, "document.json", c.document)
}

// TestSignLoadableSignsAsSignDoes: on each sample document, and on one whose
// bundle id, version and staleness budget differ from both samples', the
// signer explain uses returns the bundle Sign returns; on a document Parse
// refuses it refuses with Sign's refusal.
func TestSignLoadableSignsAsSignDoes(t *testing.T) {
	key := ed25519.NewKeyFromSeed([]byte(signingSeed))
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "policy", "documents", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no sample document: %v", err)
	}
	documents := map[string][]byte{
		"another bundle": []byte(`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"orders-eu","version":"r42","serial":3,"maxStaleSeconds":120},` +
			`"rules":[{"id":"reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}}]}`),
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: a sample document of the repository
		if err != nil {
			t.Fatal(err)
		}
		documents[path] = raw
	}
	for name, raw := range documents {
		want, err := policy.Sign(raw, key, signingKeyID)
		if err != nil {
			t.Fatalf("%s: Sign: %v", name, err)
		}
		got, err := signLoadable(raw, key, signingKeyID)
		if err != nil || !proto.Equal(got, want) {
			t.Errorf("%s: signLoadable = %v, %v; want Sign's %v", name, got, err, want)
		}
	}
	if _, err := signLoadable([]byte(`{"apiVersion":"agent-policy/v1alpha1"}`), key, signingKeyID); !errors.Is(err, policy.ErrDocument) {
		t.Errorf("a document Parse refuses: %v, want ErrDocument", err)
	}
}
