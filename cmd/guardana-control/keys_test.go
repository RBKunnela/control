package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// The key of RFC 8032, section 7.1, TEST 1, built at run time; the public
// line and the id are computed outside this code (standard base64 of the
// RFC's public key, and the first 16 hex digits of SHA-256 over its bytes).
const (
	rfcSeedHex    = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	rfcPublicHex  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	rfcPublicLine = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
	rfcKeyID      = "ed25519-21fe31dfa154a261"
)

const signDocument = `{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"orders-policy","version":"2026-09-24.1","serial":3,"maxStaleSeconds":600},
  "rules":[{"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}}]}`

func rfcSeed(t *testing.T) []byte {
	t.Helper()
	seed, err := hex.DecodeString(rfcSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

// failingWriter refuses every write, as a closed stdout does.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// signTree is a key pair written through the package keygen uses, a document
// and an output path under one fresh directory.
type signTree struct{ dir, key, doc, out string }

func newSignTree(t *testing.T) signTree {
	t.Helper()
	dir := t.TempDir()
	if err := policykey.WriteKeyPair(filepath.Join(dir, "keys"), ed25519.NewKeyFromSeed(rfcSeed(t))); err != nil {
		t.Fatalf("writing the key pair: %v", err)
	}
	doc := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(doc, []byte(signDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	return signTree{dir: dir, key: filepath.Join(dir, "keys", "signing.key"), doc: doc, out: filepath.Join(dir, "policy.bundle")}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(raw)
}

func TestKeygenPrintsTheTwoConfigurationLines(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	var stdout, stderr bytes.Buffer
	if code := keygen(dir, bytes.NewReader(rfcSeed(t)), &stdout, &stderr); code != exitOK {
		t.Fatalf("keygen exit %d: %s", code, stderr.String())
	}
	if want := "key_id: " + rfcKeyID + "\npublic_key: " + rfcPublicLine + "\n"; stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want nothing", stderr.String())
	}
	if got := readFile(t, filepath.Join(dir, "signing.pub")); got != rfcPublicLine+"\n" {
		t.Errorf("signing.pub = %q", got)
	}
}

// TestKeygenThroughTheCommandLine: the dispatched command draws its own key;
// what it prints is the public half it wrote, in the two lines' form.
func TestKeygenThroughTheCommandLine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	code, stdout, stderr := invoke(t, "policy", "keygen", "--out", dir)
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	m := regexp.MustCompile(`^key_id: (ed25519-[0-9a-f]{16})\npublic_key: ([A-Za-z0-9+/]{43}=)\n$`).FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("stdout %q is not the two lines", stdout)
	}
	if got := readFile(t, filepath.Join(dir, "signing.pub")); got != m[2]+"\n" {
		t.Errorf("printed %q and wrote %q", m[2], got)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the directory: %v, mode %v", err, info.Mode())
	}
}

// TestKeygenRefusesAnExistingPath: nothing is written, and a directory holding
// only a public half is left holding only that.
func TestKeygenRefusesAnExistingPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signing.pub"), []byte("old\n"), 0o644); err != nil { //nolint:gosec // G306: a public half is public
		t.Fatal(err)
	}
	code, stdout, stderr := invoke(t, "policy", "keygen", "--out", dir)
	line := oneStderrLine(t, stderr)
	if code != exitFail || stdout != "" || !strings.Contains(line, "the path exists") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, line)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || readFile(t, filepath.Join(dir, "signing.pub")) != "old\n" {
		t.Errorf("the directory changed: %v", entries)
	}
}

func TestKeygenFailures(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	var stdout, stderr bytes.Buffer
	if code := keygen(dir, bytes.NewReader(rfcSeed(t)[:10]), &stdout, &stderr); code != exitFail {
		t.Errorf("a short random source: exit %d", code)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a key that could not be drawn left the directory: %v", err)
	}
	stderr.Reset()
	if code := keygen(dir, bytes.NewReader(rfcSeed(t)), failingWriter{}, &stderr); code != exitFail {
		t.Errorf("a closed stdout: exit %d", code)
	}
	if line := oneStderrLine(t, stderr.String()); !strings.Contains(line, "the key pair was written to "+dir) {
		t.Errorf("a closed stdout: stderr %q does not say where the pair went", line)
	}
}

func TestKeysUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"keygen without --out":     {"policy", "keygen"},
		"keygen with an argument":  {"policy", "keygen", "--out", "a", "b"},
		"keygen with a bare word":  {"policy", "keygen", "a"},
		"keygen with another flag": {"policy", "keygen", "--key", "a"},
		"sign without --key":       {"policy", "sign", "--out", "o", "d"},
		"sign without --out":       {"policy", "sign", "--key", "k", "d"},
		"sign without a document":  {"policy", "sign", "--key", "k", "--out", "o"},
		"sign with two documents":  {"policy", "sign", "--key", "k", "--out", "o", "d", "e"},
		"sign with a flag after":   {"policy", "sign", "--key", "k", "d", "--out", "o"},
		"sign with --key-id":       {"policy", "sign", "--key", "k", "--key-id", "x", "--out", "o", "d"},
		"sign asking for help":     {"policy", "sign", "-h"},
		"keygen asking for help":   {"policy", "keygen", "--help"},
		"keygen with a bare dash":  {"policy", "keygen", "---out", "a"},
	} {
		code, stdout, stderr := invoke(t, args...)
		if code != exitUsage || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q; want %d and nothing", name, code, stdout, exitUsage)
		}
		// The flag package's own diagnostics and usage block never reach
		// stderr; the command writes one line of its own.
		if line := oneStderrLine(t, stderr); !strings.HasPrefix(line, brand.CLI+": policy "+args[1]+": takes ") {
			t.Errorf("%s: stderr %q is not the command's own usage line", name, line)
		}
	}
}

// TestSignWritesALoadableBundle: the output lines are pinned, the digest
// checked against SHA-256 over the canonical bytes read back from the file,
// and the bundle loads under the RFC's public key.
func TestSignWritesALoadableBundle(t *testing.T) {
	tr := newSignTree(t)
	code, stdout, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, tr.doc)
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var b controlv1.PolicyBundle
	if err := proto.Unmarshal([]byte(readFile(t, tr.out)), &b); err != nil {
		t.Fatalf("the output is not a bundle: %v", err)
	}
	sum := sha256.Sum256(b.GetCanonical())
	want := "bundle_id: orders-policy\nversion: 2026-09-24.1\nserial: 3\n" +
		"digest: sha256:" + hex.EncodeToString(sum[:]) + "\nkey_id: " + rfcKeyID + "\nout: " + tr.out + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	pub, _ := hex.DecodeString(rfcPublicHex)
	if _, err := policy.Load(&b, bundle.Keyring{rfcKeyID: pub}, time.Now()); err != nil {
		t.Errorf("the bundle does not load under the RFC's key: %v", err)
	}
	info, err := os.Stat(tr.out)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("the bundle: %v, mode %v, want 0644", err, info.Mode())
	}
	second := filepath.Join(tr.dir, "second.bundle")
	if code, _, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", second, tr.doc); code != exitOK {
		t.Fatalf("second sign: exit %d, %q", code, stderr)
	}
	if readFile(t, second) != readFile(t, tr.out) {
		t.Error("two signs of one document with one key differ")
	}
}

// TestSignRefusesAnOutThatIsAnInput: by a relative spelling, a hard link and
// a symbolic link, an --out that reaches the key or the document is refused
// and the file keeps its bytes.
func TestSignRefusesAnOutThatIsAnInput(t *testing.T) {
	tr := newSignTree(t)
	t.Chdir(tr.dir)
	keyAlias := filepath.Join(tr.dir, "key-link")
	docAlias := filepath.Join(tr.dir, "doc-link")
	if err := os.Link(tr.key, keyAlias); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(tr.doc, docAlias); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(tr.dir, "key-symlink")
	if err := os.Symlink(tr.key, symlink); err != nil {
		t.Fatal(err)
	}
	keyBefore, docBefore := readFile(t, tr.key), readFile(t, tr.doc)
	for name, c := range map[string]struct{ key, out, doc, names string }{
		"the key, spelled relatively":      {tr.key, "./keys/../keys/signing.key", tr.doc, "--key"},
		"the key, by a hard link":          {"keys/signing.key", keyAlias, tr.doc, "--key"},
		"the key, by a symbolic link":      {tr.key, symlink, tr.doc, "--key"},
		"the document, spelled relatively": {tr.key, "./policy.json", tr.doc, "the document"},
		"the document, by a hard link":     {tr.key, docAlias, "policy.json", "the document"},
	} {
		code, stdout, stderr := invoke(t, "policy", "sign", "--key", c.key, "--out", c.out, c.doc)
		line := oneStderrLine(t, stderr)
		if code != exitFail || stdout != "" || !strings.Contains(line, "is the same file as "+c.names) {
			t.Errorf("%s: exit %d, stderr %q", name, code, line)
		}
	}
	if readFile(t, tr.key) != keyBefore || readFile(t, tr.doc) != docBefore {
		t.Error("a refused sign changed the key or the document")
	}
}

// TestSignRefusalsLeaveOutAsItWas: a document the parser refuses is refused
// before the key is opened (the key here would be refused too, for its mode),
// and neither refusal touches the bundle already at --out.
func TestSignRefusalsLeaveOutAsItWas(t *testing.T) {
	tr := newSignTree(t)
	if code, _, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, tr.doc); code != exitOK {
		t.Fatalf("signing the bundle a plane runs: exit %d, %q", code, stderr)
	}
	before := readFile(t, tr.out)
	bad := filepath.Join(tr.dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"apiVersion":"agent-policy/v1alpha1","rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tr.key, 0o640); err != nil { //nolint:gosec // G302: the key file mode sign must refuse
		t.Fatal(err)
	}
	code, _, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, bad)
	if line := oneStderrLine(t, stderr); code != exitFail || !strings.Contains(line, "rules:") || strings.Contains(line, "policykey") {
		t.Errorf("a refused document: exit %d, stderr %q; want the document's refusal, not the key's", code, line)
	}
	code, _, stderr = invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, tr.doc)
	if line := oneStderrLine(t, stderr); code != exitFail || !strings.Contains(line, string(policykey.ErrKeyFileMode)) {
		t.Errorf("a key readable by the group: exit %d, stderr %q", code, line)
	}
	if got := readFile(t, tr.out); got != before {
		t.Errorf("--out changed from %d bytes to %d", len(before), len(got))
	}
}

// TestSignRefusesAParameterBeforeTheKey: a document the obligation parameter
// check refuses is refused before the key is opened, which would be refused
// for its mode, and the bundle already at --out stays as it was.
func TestSignRefusesAParameterBeforeTheKey(t *testing.T) {
	tr := newSignTree(t)
	if code, _, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, tr.doc); code != exitOK {
		t.Fatalf("signing the bundle a plane runs: exit %d, %q", code, stderr)
	}
	before := readFile(t, tr.out)
	param := filepath.Join(tr.dir, "param.json")
	doc := `{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"p","version":"1","serial":1,"maxStaleSeconds":300},` +
		`"rules":[{"id":"r","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"read_only","params":{"x":"1"}}],"when":{"action":{"effect":["READ"]}}}]}`
	if err := os.WriteFile(param, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tr.key, 0o640); err != nil { //nolint:gosec // G302: the key file mode sign must refuse
		t.Fatal(err)
	}
	code, _, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, param)
	if line := oneStderrLine(t, stderr); code != exitFail || !strings.Contains(line, "rules: a parameter the obligation's type does not declare") {
		t.Errorf("a parameter read_only does not declare: exit %d, stderr %q; want the parameter's refusal, not the key's", code, line)
	}
	if got := readFile(t, tr.out); got != before {
		t.Errorf("--out changed from %d bytes to %d", len(before), len(got))
	}
}

// TestSignRefusesAnOutItCannotWrite: the key is left readable by the group, so
// an --out check that did not refuse would show as the key's refusal instead.
func TestSignRefusesAnOutItCannotWrite(t *testing.T) {
	tr := newSignTree(t)
	if err := os.Chmod(tr.key, 0o640); err != nil { //nolint:gosec // G302: the key file mode sign must refuse
		t.Fatal(err)
	}
	missing := filepath.Join(tr.dir, "none")
	for name, c := range map[string]struct{ out, want string }{
		"a missing directory": {
			filepath.Join(missing, "policy.bundle"),
			"--out " + filepath.Join(missing, "policy.bundle") + ": stat " + missing + ": no such file or directory",
		},
		"a directory": {tr.dir, "--out " + tr.dir + ": files: not a regular file: a directory"},
	} {
		code, stdout, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", c.out, tr.doc)
		if code != exitFail || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q", name, code, stdout)
		}
		if line, want := oneStderrLine(t, stderr), brand.CLI+": policy sign: "+c.want; line != want {
			t.Errorf("%s: stderr %q, want %q", name, line, want)
		}
	}
}

// TestSignReplacesOnlyABundle: an --out that exists is replaced only when it
// holds a policy bundle. Every other file, another key pair's two halves
// among them, is refused and left as it was, byte for byte and mode for mode.
func TestSignReplacesOnlyABundle(t *testing.T) {
	tr := newSignTree(t)
	other := filepath.Join(tr.dir, "other")
	if err := policykey.WriteKeyPair(other, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))); err != nil {
		t.Fatal(err)
	}
	another := filepath.Join(tr.dir, "another.json")
	if err := os.WriteFile(another, []byte(signDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(tr.dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{
		"another private key":       filepath.Join(other, "signing.key"),
		"another public key file":   filepath.Join(other, "signing.pub"),
		"the key's own public half": filepath.Join(tr.dir, "keys", "signing.pub"),
		"another document":          another,
		"an empty file":             empty,
	} {
		refusedAndKept(t, name, tr, out)
	}
}

// refusedAndKept runs sign over tr into out, which must be refused as not a
// bundle and left with its bytes and its mode.
func refusedAndKept(t *testing.T, name string, tr signTree, out string) {
	t.Helper()
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	before := readFile(t, out)
	code, stdout, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", out, tr.doc)
	line := oneStderrLine(t, stderr)
	if want := brand.CLI + ": policy sign: --out " + out + " exists and is not a policy bundle, and sign replaces nothing else"; code != exitFail || stdout != "" || line != want {
		t.Errorf("%s: exit %d, stdout %q, stderr %q; want %q", name, code, stdout, line, want)
	}
	after, err := os.Stat(out)
	if readFile(t, out) != before || err != nil || after.Mode() != info.Mode() {
		t.Errorf("%s: the refused --out changed (%v)", name, err)
	}
}

func TestSignReplacesAnEarlierBundle(t *testing.T) {
	tr := newSignTree(t)
	if code, _, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, tr.doc); code != exitOK {
		t.Fatalf("the first sign: exit %d, %q", code, stderr)
	}
	first := readFile(t, tr.out)
	later := strings.Replace(signDocument, `"serial":3`, `"serial":4`, 1)
	if err := os.WriteFile(tr.doc, []byte(later), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, tr.doc)
	if code != exitOK || !strings.Contains(stdout, "\nserial: 4\n") {
		t.Fatalf("replacing an earlier bundle: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if readFile(t, tr.out) == first {
		t.Error("the earlier bundle was not replaced")
	}
}

// TestSignRefusesAnOutThroughALinkAndDotDot: "sub/.." after a link to another
// directory is that directory's parent to the kernel and the link's own
// directory to a lexical clean. Either file beside the link is refused under
// that spelling and keeps its bytes.
func TestSignRefusesAnOutThroughALinkAndDotDot(t *testing.T) {
	for name, c := range map[string]struct{ file, refusal string }{
		"the key":         {"signing.key", "is the same file as --key, which the bundle would replace"},
		"its public half": {"signing.pub", "exists and is not a policy bundle"},
	} {
		tr := newSignTree(t)
		keys := filepath.Dir(tr.key)
		elsewhere := filepath.Join(t.TempDir(), "elsewhere", "deep")
		if err := os.MkdirAll(elsewhere, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(keys, "sub")); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(keys, c.file)
		before := readFile(t, path)
		out := filepath.Join(keys, "sub") + "/../" + c.file
		code, stdout, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", out, tr.doc)
		if code != exitFail || stdout != "" || !strings.Contains(stderr, c.refusal) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
		if after := readFile(t, path); after != before {
			t.Errorf("%s: replaced through --out %q (%d bytes, now %d)", name, out, len(before), len(after))
		}
		if entries, err := os.ReadDir(elsewhere); err != nil || len(entries) != 0 {
			t.Errorf("%s: the link's target holds %v (%v)", name, entries, err)
		}
	}
}
