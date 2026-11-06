package gatewayconfig

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"strings"
	"testing"

	"github.com/guardana/control/internal/policykey"
)

// keyFile is a key file of a fixed key and its body line.
func keyFile(t *testing.T) (pemFile, body string) {
	t.Helper()
	raw, err := policykey.MarshalPrivate(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), strings.Split(string(raw), "\n")[1]
}

// repeatsKeyText reports whether text holds any of the key file's text.
func repeatsKeyText(text, pemFile, body string) bool {
	return strings.Contains(text, body[:21]) || strings.Contains(text, "-----") || strings.Contains(text, strings.TrimSpace(pemFile))
}

// TestAPathHoldingKeyTextIsRefusedByItsKey: each key that names a file or a
// directory refuses a value holding a key's body line, the start of one
// inside a path, a whole PEM or a closing marker, naming the key and not the
// value; the start one character short is a path like any other.
func TestAPathHoldingKeyTextIsRefusedByItsKey(t *testing.T) {
	pemFile, body := keyFile(t)
	values := map[string]string{
		"a body line":         body,
		"a body line in path": "keys/" + body + "/policy.bundle",
		"a whole PEM":         pemFile,
		"a closing marker":    "-----END PRIVATE KEY-----",
	}
	for _, key := range []string{"policy.bundle_file", "policy.statement_file", "policy.state_dir", "approvals.dir", "approvals.hold_journal_dir", "pause.file", "evidence.dir", "upstreams.0.command"} {
		for name, value := range values {
			path := write(t, "")
			setEnv(t, key, value)
			_, err := Load(path, os.Environ())
			switch {
			case err == nil:
				t.Errorf("%s holding %s: loaded", key, name)
			case !strings.Contains(err.Error(), key+": holds a PEM marker"):
				t.Errorf("%s holding %s: %v, want a refusal naming the key", key, name, err)
			case repeatsKeyText(err.Error(), pemFile, body):
				t.Errorf("%s holding %s: the refusal repeats key text: %q", key, name, err)
			}
		}
	}
	path := write(t, "")
	setEnv(t, "pause.file", "pause/"+body[:20])
	if _, err := Load(path, os.Environ()); err != nil {
		t.Errorf("a path holding the start of a body line one character short: %v", err)
	}
}

// TestKeyTextOutsideAPathIsLoaded: a key that is not a path, and an
// upstream's argument, which may carry a certificate, take key text; only
// printing it is withheld. No envelope carries policy.key_id, a hint to the
// key's name and no free text either, so it takes the whole file; an
// identifier an envelope carries takes no line break, so only the body line
// goes to one.
func TestKeyTextOutsideAPathIsLoaded(t *testing.T) {
	pemFile, body := keyFile(t)
	path := write(t, "")
	setEnv(t, "policy.key_id", pemFile)
	setEnv(t, "project_id", body)
	cfg := load(t, path)
	if cfg.Policy.KeyID != pemFile || cfg.ProjectID != body {
		t.Errorf("the values were not taken as given")
	}
	doc := strings.Replace(document, "    endpoint: http://127.0.0.1:1/mcp\n",
		"    command: server\n    args:\n      - --ca=-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----\n", 1)
	cfg = load(t, writeDocument(t, doc))
	if got := cfg.Upstreams[0].Args; len(got) != 1 || !strings.Contains(got[0], "-----BEGIN CERTIFICATE-----") {
		t.Errorf("the upstream's argument is %q", got)
	}
}

// TestARefusalQuotesAValueWithoutItsKeyText: a value a refusal quotes, from
// the environment or from the file, keeps its key text out of the refusal and
// still says where the value was.
func TestARefusalQuotesAValueWithoutItsKeyText(t *testing.T) {
	pemFile, body := keyFile(t)
	for name, c := range map[string]struct {
		key, value, where string
	}{
		"an integer": {"approvals.max_held", body, "approvals.max_held: not an integer: \"[key text withheld]\""},
		"a mode":     {"mode", "x " + body, "mode: not one of"},
		"a duration": {"pdp.timeout", pemFile, "pdp.timeout: not a duration such as 30s or 10m: \"[key text withheld]\\n\""},
	} {
		path := write(t, "")
		setEnv(t, c.key, c.value)
		_, err := Load(path, os.Environ())
		switch {
		case err == nil:
			t.Errorf("%s: loaded", name)
		case !strings.Contains(err.Error(), c.where) || !strings.Contains(err.Error(), policykey.KeyTextWithheld):
			t.Errorf("%s: %v, want %q and the value withheld", name, err, c.where)
		case repeatsKeyText(err.Error(), pemFile, body):
			t.Errorf("%s: the refusal repeats key text: %q", name, err)
		}
	}
	_, err := Load(writeDocument(t, strings.Replace(document, "tenant_id: acme", `tenant_id: "`+body, 1)), os.Environ())
	if err == nil || !strings.Contains(err.Error(), "tenant_id") || !strings.Contains(err.Error(), policykey.KeyTextWithheld) ||
		repeatsKeyText(err.Error(), pemFile, body) {
		t.Errorf("a quoted scalar with no closing quote: %v", err)
	}
}
