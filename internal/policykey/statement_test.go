package policykey_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// envelopeFile is a statement file as a signer writes it: the payload is the
// two bytes "{}" (e30=) and the signature the three bytes 0, 1, 2 (AAEC).
const envelopeFile = `{"payloadType":"application/vnd.agent-policy-freshness+json","payload":"e30=","signatures":[{"keyid":"f1","sig":"AAEC"}]}`

// statementFileRefusals is every refusal ParseStatement may return.
func statementFileRefusals() []error {
	return []error{
		policykey.ErrStatementFileTooLarge, policykey.ErrStatementEnvelope, policykey.ErrStatementEnvelopeMember,
		policykey.ErrStatementEnvelopeRepeated, policykey.ErrStatementBase64,
	}
}

func expectFileRefusal(t testing.TB, what string, err, want error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: accepted, want %q", what, want)
		return
	}
	for _, s := range statementFileRefusals() {
		if got, wanted := errors.Is(err, s), errors.Is(s, want); got != wanted {
			t.Errorf("%s: errors.Is(%q, %q) = %v, want %v", what, err, s, got, wanted)
		}
	}
}

func TestParseStatementReadsTheEnvelope(t *testing.T) {
	env, err := policykey.ParseStatement([]byte(envelopeFile))
	if err != nil {
		t.Fatalf("ParseStatement: %v", err)
	}
	if env.PayloadType != "application/vnd.agent-policy-freshness+json" || string(env.Payload) != "{}" ||
		len(env.Signatures) != 1 || env.Signatures[0].KeyID != "f1" || !bytes.Equal(env.Signatures[0].Signature, []byte{0, 1, 2}) {
		t.Fatalf("ParseStatement = %+v", env)
	}
}

// The envelope hands every signature it holds to the policy package, which
// takes exactly one.
func TestParseStatementPassesEverySignatureOn(t *testing.T) {
	for _, c := range []struct {
		name, sigs string
		n          int
	}{
		{"none", `[]`, 0},
		{"two", `[{"keyid":"f1","sig":"AAEC"},{"keyid":"f2","sig":"AAEC"}]`, 2},
	} {
		raw := strings.Replace(envelopeFile, `[{"keyid":"f1","sig":"AAEC"}]`, c.sigs, 1)
		env, err := policykey.ParseStatement([]byte(raw))
		if err != nil || len(env.Signatures) != c.n {
			t.Fatalf("%s: %d signatures, %v", c.name, len(env.Signatures), err)
		}
		if _, err := policy.VerifyStatement(env, bundle.Keyring{"f1": ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)}); !errors.Is(err, policy.ErrStatementSignatures) {
			t.Errorf("%s: VerifyStatement = %v, want ErrStatementSignatures", c.name, err)
		}
	}
}

func TestParseStatementRefusesABadEnvelope(t *testing.T) {
	edit := func(old, replacement string) string {
		if !strings.Contains(envelopeFile, old) {
			t.Fatalf("%q is not in the envelope", old)
		}
		return strings.Replace(envelopeFile, old, replacement, 1)
	}
	cases := []struct {
		name, raw string
		want      error
	}{
		{"an unknown member", edit(`{"payloadType"`, `{"x":1,"payloadType"`), policykey.ErrStatementEnvelopeMember},
		{"a member in another case", edit(`"payloadType"`, `"PayloadType"`), policykey.ErrStatementEnvelopeMember},
		{"no payloadType", edit(`"payloadType":"application/vnd.agent-policy-freshness+json",`, ``), policykey.ErrStatementEnvelopeMember},
		{"no payload", edit(`"payload":"e30=",`, ``), policykey.ErrStatementEnvelopeMember},
		{"no signatures", edit(`,"signatures":[{"keyid":"f1","sig":"AAEC"}]`, ``), policykey.ErrStatementEnvelopeMember},
		{"an unknown signature member", edit(`"sig":"AAEC"`, `"sig":"AAEC","cert":"x"`), policykey.ErrStatementEnvelopeMember},
		{"no keyid", edit(`"keyid":"f1",`, ``), policykey.ErrStatementEnvelopeMember},
		{"no sig", edit(`,"sig":"AAEC"`, ``), policykey.ErrStatementEnvelopeMember},
		{"payload twice", edit(`"payload":"e30=",`, `"payload":"e30=","payload":"e30=",`), policykey.ErrStatementEnvelopeRepeated},
		{"payload twice, once escaped", edit(`"payload":"e30=",`, `"payload":"e30=","payl\u006fad":"e30=",`), policykey.ErrStatementEnvelopeRepeated},
		{"keyid twice", edit(`"keyid":"f1",`, `"keyid":"f2","keyid":"f1",`), policykey.ErrStatementEnvelopeRepeated},
		{"URL-safe base64", edit(`"e30="`, `"-_8="`), policykey.ErrStatementBase64},
		{"a line break in the base64", edit(`"e30="`, `"e3\n0="`), policykey.ErrStatementBase64},
		{"no padding", edit(`"e30="`, `"e30"`), policykey.ErrStatementBase64},
		{"padding bits set", edit(`"e30="`, `"e31="`), policykey.ErrStatementBase64},
		{"a sig in URL-safe base64", edit(`"AAEC"`, `"_-_-"`), policykey.ErrStatementBase64},
		{"a null payload", edit(`"e30="`, `null`), policykey.ErrStatementEnvelope},
		{"a payload that is a number", edit(`"e30="`, `1`), policykey.ErrStatementEnvelope},
		{"signatures as an object", edit(`[{"keyid":"f1","sig":"AAEC"}]`, `{"keyid":"f1","sig":"AAEC"}`), policykey.ErrStatementEnvelope},
		{"a signature that is a string", edit(`[{"keyid":"f1","sig":"AAEC"}]`, `["AAEC"]`), policykey.ErrStatementEnvelope},
		{"a keyid that is a number", edit(`"f1"`, `1`), policykey.ErrStatementEnvelope},
		{"an array", `[]`, policykey.ErrStatementEnvelope},
		{"nothing", ``, policykey.ErrStatementEnvelope},
		{"a second object after it", envelopeFile + `{}`, policykey.ErrStatementEnvelope},
		{"an unclosed object", strings.TrimSuffix(envelopeFile, "}"), policykey.ErrStatementEnvelope},
		{"invalid UTF-8", edit(`"f1"`, "\"f\xff1\""), policykey.ErrStatementEnvelope},
		{"an unpaired surrogate", edit(`"f1"`, `"f\ud8001"`), policykey.ErrStatementEnvelope},
	}
	for _, c := range cases {
		env, err := policykey.ParseStatement([]byte(c.raw))
		expectFileRefusal(t, c.name, err, c.want)
		if env.Payload != nil || env.Signatures != nil || env.PayloadType != "" {
			t.Errorf("%s: parts beside the refusal", c.name)
		}
	}
}

// The file's bound is exactly MaxStatementFileBytes, 4 KiB, padded here with
// white space the format allows.
func TestStatementFileBound(t *testing.T) {
	if policykey.MaxStatementFileBytes != 4096 {
		t.Fatalf("MaxStatementFileBytes = %d, want 4096", policykey.MaxStatementFileBytes)
	}
	at := envelopeFile + strings.Repeat(" ", 4096-len(envelopeFile))
	if _, err := policykey.ParseStatement([]byte(at)); err != nil {
		t.Fatalf("a file of 4096 bytes: %v", err)
	}
	_, err := policykey.ParseStatement([]byte(at + " "))
	expectFileRefusal(t, "a file of 4097 bytes", err, policykey.ErrStatementFileTooLarge)

	dir := t.TempDir()
	path := filepath.Join(dir, "statement.json")
	if err := os.WriteFile(path, []byte(at+" "), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policykey.ReadStatement(path); !errors.Is(err, files.ErrTooLarge) {
		t.Errorf("ReadStatement of a file of 4097 bytes: %v, want files.ErrTooLarge", err)
	}
	if err := os.WriteFile(path, []byte(at), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policykey.ReadStatement(path); err != nil {
		t.Errorf("ReadStatement of a file of 4096 bytes: %v", err)
	}
}

// A statement signed, written, read and verified is the statement signed.
func TestAStatementRoundTripsThroughItsFile(t *testing.T) {
	key := rfcKey(t)
	pub := key.Public().(ed25519.PublicKey)
	issued := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("ab", 32)
	env, err := policy.SignStatement("orders-policy", 3, digest, issued, key, rfcKeyID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "statement.json")
	if err := policykey.WriteStatement(t.Context(), path, env); err != nil {
		t.Fatalf("WriteStatement: %v", err)
	}
	if mode := modeOf(t, path); mode != 0o644 {
		t.Errorf("the statement file has mode %04o, want 0644", mode)
	}
	read, err := policykey.ReadStatement(path)
	if err != nil {
		t.Fatalf("ReadStatement: %v", err)
	}
	st, err := policy.VerifyStatement(read, bundle.Keyring{rfcKeyID: pub})
	if err != nil {
		t.Fatalf("VerifyStatement: %v", err)
	}
	if st.BundleID() != "orders-policy" || st.Serial() != 3 || st.Digest() != digest || !st.IssuedAt().Equal(issued) {
		t.Fatalf("the statement read back is %q %d %s %v", st.BundleID(), st.Serial(), st.Digest(), st.IssuedAt())
	}
}

func TestMarshalStatementWritesTheEnvelope(t *testing.T) {
	raw, err := policykey.MarshalStatement(policy.StatementEnvelope{
		PayloadType: "application/vnd.agent-policy-freshness+json",
		Payload:     []byte("{}"),
		Signatures:  []policy.StatementSignature{{KeyID: "f1", Signature: []byte{0, 1, 2}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != envelopeFile+"\n" {
		t.Fatalf("MarshalStatement = %q, want %q", raw, envelopeFile+"\n")
	}
	if !policykey.IsStatement(raw) {
		t.Error("IsStatement refuses what MarshalStatement wrote")
	}
	bundleType := strings.Replace(envelopeFile, "agent-policy-freshness+json", "agent-policy+json", 1)
	if policykey.IsStatement([]byte(bundleType)) {
		t.Error("IsStatement takes an envelope of the bundle type")
	}
	if _, err := policykey.MarshalStatement(policy.StatementEnvelope{
		PayloadType: "application/vnd.agent-policy-freshness+json",
		Payload:     bytes.Repeat([]byte{'x'}, 4096),
		Signatures:  []policy.StatementSignature{{KeyID: "f1", Signature: []byte{0}}},
	}); !errors.Is(err, policykey.ErrStatementFileTooLarge) {
		t.Errorf("MarshalStatement of a file over the bound: %v", err)
	}
}

// signedStatement is a statement signed by the RFC key.
func signedStatement(t *testing.T) policy.StatementEnvelope {
	t.Helper()
	env, err := policy.SignStatement("orders-policy", 3, "sha256:"+strings.Repeat("ab", 32), now, rfcKey(t), rfcKeyID)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// WriteStatement replaces a statement by rename and leaves no temporary file.
func TestWriteStatementReplacesAStatement(t *testing.T) {
	env := signedStatement(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "statement.json")
	if err := os.WriteFile(path, []byte(envelopeFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policykey.WriteStatement(t.Context(), path, env); err != nil {
		t.Fatalf("replacing a statement: %v", err)
	}
	want, err := policykey.MarshalStatement(env)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); !bytes.Equal(got, want) {
		t.Fatalf("the replaced statement holds %q", got)
	}
	if mode := modeOf(t, path); mode != 0o644 {
		t.Errorf("the replaced statement has mode %04o, want 0644", mode)
	}
	for _, name := range names(t, dir) {
		if files.IsTemp(name) {
			t.Errorf("a temporary file %s is left", name)
		}
	}
}

// WriteStatement refuses a key, a bundle and any other file, leaving each as
// it was.
func TestWriteStatementRefusesAnotherFile(t *testing.T) {
	key := rfcKey(t)
	env := signedStatement(t)
	dir := t.TempDir()
	private, err := policykey.MarshalPrivate(key)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := policykey.SignBundle([]byte(document), key, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := policykey.WriteBundle(filepath.Join(dir, "policy.bundle"), b); err != nil {
		t.Fatal(err)
	}
	others := map[string][]byte{"signing.key": private, "notes.txt": []byte("a note\n")}
	for name, body := range others {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	others["policy.bundle"] = readFile(t, filepath.Join(dir, "policy.bundle"))
	for name, body := range others {
		p := filepath.Join(dir, name)
		if err := policykey.WriteStatement(t.Context(), p, env); !errors.Is(err, policykey.ErrStatementOut) {
			t.Errorf("%s: WriteStatement = %v, want ErrStatementOut", name, err)
		}
		if got := readFile(t, p); !bytes.Equal(got, body) {
			t.Errorf("%s: changed by a refused write", name)
		}
	}
}

// WriteStatement refuses a directory and a link, even one to a statement,
// and writes nothing for an envelope of another payload type.
func TestWriteStatementRefusesALinkADirectoryAndAnotherType(t *testing.T) {
	env := signedStatement(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "statement.json")
	if err := os.WriteFile(path, []byte(envelopeFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := policykey.WriteStatement(t.Context(), filepath.Join(dir, "sub"), env); !errors.Is(err, policykey.ErrStatementOut) {
		t.Errorf("a directory: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := policykey.WriteStatement(t.Context(), link, env); !errors.Is(err, policykey.ErrStatementOut) {
		t.Errorf("a link to a statement: %v", err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was replaced")
	}
	if got := readFile(t, path); string(got) != envelopeFile {
		t.Errorf("the statement behind the link was changed")
	}
	if err := policykey.WriteStatement(t.Context(), filepath.Join(dir, "missing", "statement.json"), env); err == nil {
		t.Error("a path in a missing directory was written")
	}
	other := env
	other.PayloadType = "application/vnd.agent-policy+json"
	fresh := filepath.Join(dir, "fresh.json")
	if err := policykey.WriteStatement(t.Context(), fresh, other); !errors.Is(err, policy.ErrStatementPayloadType) {
		t.Errorf("an envelope of the bundle type: %v", err)
	}
	if _, err := os.Lstat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused envelope left a file: %v", err)
	}
}

// An existing statement padded to the file bound is replaced; one byte past
// it, it is not judged a statement and is left as it was.
func TestWriteStatementReadsTheExistingFileToItsBound(t *testing.T) {
	env := signedStatement(t)
	dir := t.TempDir()
	at := filepath.Join(dir, "at.json")
	over := filepath.Join(dir, "over.json")
	padded := envelopeFile + strings.Repeat(" ", 4096-len(envelopeFile))
	if err := os.WriteFile(at, []byte(padded), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(over, []byte(padded+" "), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policykey.WriteStatement(t.Context(), at, env); err != nil {
		t.Errorf("a statement of 4096 bytes: %v", err)
	}
	if err := policykey.WriteStatement(t.Context(), over, env); !errors.Is(err, policykey.ErrStatementOut) {
		t.Errorf("a statement of 4097 bytes: %v, want ErrStatementOut", err)
	}
	if got := readFile(t, over); string(got) != padded+" " {
		t.Error("the file over the bound was changed")
	}
}

// TestWriteStatementReplacesOnlyTheStatementItJudged: a statement renamed
// over the path once the write judged it is kept and the write refused; the
// control, the path as it was judged, is replaced.
func TestWriteStatementReplacesOnlyTheStatementItJudged(t *testing.T) {
	env := signedStatement(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "statement.json")
	if err := os.WriteFile(path, []byte(envelopeFile), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.json")
	const another = envelopeFile + "\n"
	policykey.BeforeStatementReplaced(t, func() {
		if err := os.WriteFile(other, []byte(another), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(other, path); err != nil {
			t.Fatal(err)
		}
	})
	if err := policykey.WriteStatement(t.Context(), path, env); !errors.Is(err, files.ErrNotJudged) {
		t.Errorf("a write over a statement renamed in after it was judged = %v, want files.ErrNotJudged", err)
	}
	if got := readFile(t, path); string(got) != another {
		t.Errorf("the statement renamed in now holds %q", got)
	}
	policykey.BeforeStatementReplaced(t, func() {})
	if err := policykey.WriteStatement(t.Context(), path, env); err != nil {
		t.Errorf("the control, the statement as it was judged: %v", err)
	}
}
