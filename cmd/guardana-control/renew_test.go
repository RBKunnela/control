package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	"github.com/guardana/control/internal/policystate"
)

// The freshness key is RFC 8032, section 7.1, TEST 2, apart from the bundle
// key, which is TEST 1. Its public half is the RFC's.
const (
	freshSeedHex   = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
	freshPublicHex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)

// renewDocument is a policy of orders-policy at serial, whose one rule is
// named rule, so two rule names at one serial are two digests.
func renewDocument(serial int, rule string) string {
	return fmt.Sprintf(`{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"orders-policy","version":"2026-10-02.%d","serial":%d,"maxStaleSeconds":600},
  "rules":[{"id":%q,"effect":"ALLOW","when":{"action":{"effect":["READ"]}}}]}`, serial, serial, rule)
}

// renewTree is everything renew reads, under one fresh directory: the bundle
// key pair, the freshness key pair, a bundle of serial 3, a signer's floor
// directory initialised for orders-policy, and an output path not yet there.
type renewTree struct {
	dir, bundleKey, bundlePub, freshKey, freshPub, bundle, floor, out string
	bundleSigner                                                      ed25519.PrivateKey
}

func newRenewTree(t *testing.T) renewTree {
	t.Helper()
	dir := t.TempDir()
	r := renewTree{
		dir:       dir,
		bundleKey: filepath.Join(dir, "policy-key", policykey.PrivateFile),
		bundlePub: filepath.Join(dir, "policy-key", policykey.PublicFile),
		freshKey:  filepath.Join(dir, "freshness-key", policykey.PrivateFile),
		freshPub:  filepath.Join(dir, "freshness-key", policykey.PublicFile),
		bundle:    filepath.Join(dir, "orders.bundle"),
		floor:     filepath.Join(dir, "signer-floors"),
		out:       filepath.Join(dir, "orders.statement"),
	}
	r.bundleSigner = ed25519.NewKeyFromSeed(rfcSeed(t))
	if err := policykey.WriteKeyPair(filepath.Dir(r.bundleKey), r.bundleSigner); err != nil {
		t.Fatal(err)
	}
	if err := policykey.WriteKeyPair(filepath.Dir(r.freshKey), freshSigner(t)); err != nil {
		t.Fatal(err)
	}
	writeBundle(t, r.bundle, renewDocument(3, "allow-reads"), r.bundleSigner)
	if err := policystate.Init(context.Background(), r.floor, policystate.KindSigner, "orders-policy"); err != nil {
		t.Fatal(err)
	}
	return r
}

// negatedPublic writes, under dir, the freshness key's public half with bit
// 255 flipped: the negated point, which the freshness seed can sign for.
func negatedPublic(t *testing.T, dir string) string {
	t.Helper()
	pub := bytes.Clone(freshSigner(t).Public().(ed25519.PublicKey))
	pub[ed25519.PublicKeySize-1] ^= 0x80
	path := filepath.Join(dir, "negated.pub")
	if err := os.WriteFile(path, []byte(policykey.FormatPublic(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func freshSigner(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(freshSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func writeBundle(t *testing.T, path, document string, key ed25519.PrivateKey) {
	t.Helper()
	b, _, err := policykey.SignBundle([]byte(document), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := policykey.WriteBundle(path, b); err != nil {
		t.Fatal(err)
	}
}

// args is a whole renew call, with extra flags after the five, which win
// over the ones they repeat.
func (r renewTree) args(extra ...string) []string {
	return append([]string{"policy", "renew", "--key", r.freshKey, "--bundle", r.bundle,
		"--bundle-public-key", r.bundlePub, "--floor", r.floor, "--out", r.out}, extra...)
}

// bundleDigest is SHA-256 over the canonical bytes of the bundle file at path.
func bundleDigest(t *testing.T, path string) string {
	t.Helper()
	var b controlv1.PolicyBundle
	if err := proto.Unmarshal([]byte(readFile(t, path)), &b); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b.GetCanonical())
	return "sha256:" + hex.EncodeToString(sum[:])
}

// keyIDOf is the id of the hex public key, as ADR-0018 derives it.
func keyIDOf(t *testing.T, publicHex string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, err := hex.DecodeString(publicHex)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	return "ed25519-" + hex.EncodeToString(sum[:8]), pub
}

func signerFloor(t *testing.T, dir string) policy.Floor {
	t.Helper()
	s, err := policystate.Open(dir, policystate.KindSigner)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	f, err := s.Floor(context.Background(), "orders-policy")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

var issuedAtShape = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// renewed runs renew and returns the issued_at it printed, holding stdout to
// the four lines for the bundle at path.
func renewed(t *testing.T, r renewTree, bundlePath string, serial int) time.Time {
	t.Helper()
	code, stdout, stderr := invoke(t, r.args("--bundle", bundlePath)...)
	if code != exitOK || stderr != "" {
		t.Fatalf("renew: exit %d, stderr %q", code, stderr)
	}
	head := fmt.Sprintf("bundle_id: orders-policy\nserial: %d\ndigest: %s\nissued_at: ", serial, bundleDigest(t, bundlePath))
	stamp, ok := strings.CutPrefix(stdout, head)
	stamp, newline := strings.CutSuffix(stamp, "\n")
	if !ok || !newline || !issuedAtShape.MatchString(stamp) {
		t.Fatalf("renew printed %q, want %q and a time", stdout, head)
	}
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// freshStatement reads the statement file at path, which is public, mode
// 0644, and verifies it under the freshness key alone.
func freshStatement(t *testing.T, path string) (policy.StatementEnvelope, policy.Statement) {
	t.Helper()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("the statement file: %v, mode %v, want 0644", err, info.Mode())
	}
	env, err := policykey.ReadStatement(path)
	if err != nil {
		t.Fatalf("the statement file: %v", err)
	}
	freshID, freshPub := keyIDOf(t, freshPublicHex)
	st, err := policy.VerifyStatement(env, bundle.Keyring{freshID: freshPub})
	if err != nil {
		t.Fatalf("the statement does not verify under the freshness key: %v", err)
	}
	return env, st
}

// TestRenewWritesAStatementForTheBundle: the statement verifies under the
// freshness key and under no other, names the bundle's id, serial and
// digest at the time printed, and the signer's floor holds it.
func TestRenewWritesAStatementForTheBundle(t *testing.T) {
	r := newRenewTree(t)
	before := time.Now().Truncate(time.Second)
	at := renewed(t, r, r.bundle, 3)
	if at.Before(before) || at.After(time.Now()) {
		t.Errorf("issued_at %s is not the time of the run", at)
	}
	env, st := freshStatement(t, r.out)
	digest := bundleDigest(t, r.bundle)
	if st.BundleID() != "orders-policy" || st.Serial() != 3 || st.Digest() != digest || !st.IssuedAt().Equal(at) {
		t.Errorf("the statement names %s %d %s %s", st.BundleID(), st.Serial(), st.Digest(), st.IssuedAt())
	}
	bundleID, bundlePub := keyIDOf(t, rfcPublicHex)
	if _, err := policy.VerifyStatement(env, bundle.Keyring{bundleID: bundlePub}); err == nil {
		t.Error("the statement verifies under the bundle key, which did not sign it")
	}
	f := signerFloor(t, r.floor)
	if f.Serial() != 3 || f.Digest() != digest || !f.IssuedAt().Equal(at) {
		t.Errorf("the signer floor holds %d %s %s, want the statement", f.Serial(), f.Digest(), f.IssuedAt())
	}
}

// TestRenewReplacesAnEarlierStatement: a second renewal of the floor's own
// bundle is taken and replaces the statement it wrote first; a higher serial
// then moves the floor.
func TestRenewReplacesAnEarlierStatement(t *testing.T) {
	r := newRenewTree(t)
	renewed(t, r, r.bundle, 3)
	second := renewed(t, r, r.bundle, 3)
	higher := filepath.Join(r.dir, "higher.bundle")
	writeBundle(t, higher, renewDocument(4, "allow-reads"), r.bundleSigner)
	third := renewed(t, r, higher, 4)
	if third.Before(second) {
		t.Errorf("the third statement is dated %s, before the second's %s", third, second)
	}
	if _, st := freshStatement(t, r.out); st.Serial() != 4 {
		t.Errorf("--out holds the statement for serial %d, want 4", st.Serial())
	}
	if f := signerFloor(t, r.floor); f.Serial() != 4 || f.Digest() != bundleDigest(t, higher) {
		t.Errorf("the signer floor holds serial %d, want 4", f.Serial())
	}
}

// renewRefused runs renew and holds it to one refusal line holding want, an
// empty stdout, an --out left as it was and a floor left as it was.
func renewRefused(t *testing.T, name string, r renewTree, want string, args ...string) {
	t.Helper()
	outBefore := outState(r.out)
	floorBefore := signerFloor(t, r.floor)
	code, stdout, stderr := invoke(t, args...)
	line := oneStderrLine(t, stderr)
	if code != exitFail || stdout != "" || !strings.HasPrefix(line, brand.CLI+": policy renew: ") || !strings.Contains(line, want) {
		t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d and a line holding %q", name, code, stdout, line, exitFail, want)
	}
	if outState(r.out) != outBefore {
		t.Errorf("%s: --out changed", name)
	}
	if !signerFloor(t, r.floor).Equal(floorBefore) {
		t.Errorf("%s: the signer floor moved", name)
	}
}

// TestRenewRefusesABundleThatDoesNotVerify: a bundle signed by another key,
// and one whose signature was altered, are each refused under the bundle
// public key, and nothing is written or raised.
func TestRenewRefusesABundleThatDoesNotVerify(t *testing.T) {
	r := newRenewTree(t)
	otherKey := filepath.Join(r.dir, "other.bundle")
	writeBundle(t, otherKey, renewDocument(3, "allow-reads"), freshSigner(t))
	altered := filepath.Join(r.dir, "altered.bundle")
	var b controlv1.PolicyBundle
	if err := proto.Unmarshal([]byte(readFile(t, r.bundle)), &b); err != nil {
		t.Fatal(err)
	}
	b.Signature[0] ^= 1
	if err := policykey.WriteBundle(altered, &b); err != nil {
		t.Fatal(err)
	}
	renewRefused(t, "another key", r, "--bundle "+otherKey+": "+string(policy.ErrSignature), r.args("--bundle", otherKey)...)
	renewRefused(t, "an altered signature", r, "--bundle "+altered+": "+string(policy.ErrSignature), r.args("--bundle", altered)...)
	renewRefused(t, "not a bundle", r, "--bundle "+r.bundlePub+": "+string(errNotABundle), r.args("--bundle", r.bundlePub)...)
}

// TestRenewRefusesAFileThatIsNotItsKey: a public key file given as --key, and
// a private key given as --bundle-public-key, are refused by what they are,
// and no refusal repeats a byte of the file.
func TestRenewRefusesAFileThatIsNotItsKey(t *testing.T) {
	r := newRenewTree(t)
	ownerOnly := filepath.Join(r.dir, "public-0600")
	pubLine := readFile(t, r.freshPub)
	if err := os.WriteFile(ownerOnly, []byte(pubLine), 0o600); err != nil {
		t.Fatal(err)
	}
	privateBody := strings.Split(readFile(t, r.bundleKey), "\n")[1]
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"a public key file, readable by others": {r.args("--key", r.freshPub), "--key: " + string(policykey.ErrKeyFileMode)},
		"a public key file, the owner's alone":  {r.args("--key", ownerOnly), "--key: " + string(policykey.ErrPreamble)},
		"the bundle file as --key":              {r.args("--key", r.bundle), "--key: " + string(policykey.ErrKeyFileMode)},
		"a private key as the bundle public key": {
			r.args("--bundle-public-key", r.bundleKey), "--bundle-public-key: " + string(policykey.ErrPublicLine),
		},
	} {
		code, _, stderr := invoke(t, c.args...)
		if strings.Contains(stderr, strings.TrimSuffix(pubLine, "\n")) || strings.Contains(stderr, privateBody) {
			t.Errorf("%s: stderr %q repeats key text", name, stderr)
		}
		if code != exitFail {
			t.Errorf("%s: exit %d", name, code)
		}
		renewRefused(t, name, r, c.want, c.args...)
	}
}

// TestRenewRefusesAPlanesFloor: a plane's floor directory is not a signer's,
// and renew writes nothing into it.
func TestRenewRefusesAPlanesFloor(t *testing.T) {
	r := newRenewTree(t)
	plane := filepath.Join(r.dir, "plane-floors")
	if err := policystate.Init(context.Background(), plane, policystate.KindPlane, "orders-policy"); err != nil {
		t.Fatal(err)
	}
	renewRefused(t, "a plane's floor", r, "--floor "+plane+": "+string(policystate.ErrWrongKind), r.args("--floor", plane)...)
	s, err := policystate.Open(plane, policystate.KindPlane)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if f, err := s.Floor(context.Background(), "orders-policy"); err != nil || f.HasSerial() {
		t.Errorf("the plane's floor holds %v, %v", f, err)
	}
	none := filepath.Join(r.dir, "no-floor")
	if err := policystate.Init(context.Background(), none, policystate.KindSigner, "another-policy"); err != nil {
		t.Fatal(err)
	}
	renewRefused(t, "a floor with no file for the id", r, "bundle id orders-policy: "+string(policystate.ErrNoFloor), r.args("--floor", none)...)
}

// TestRenewRefusesABundleTheFloorRefuses: below the floor, and the floor's
// serial with another digest, are refused naming the floor, and the
// statement already at --out stays.
func TestRenewRefusesABundleTheFloorRefuses(t *testing.T) {
	r := newRenewTree(t)
	at := renewed(t, r, r.bundle, 3)
	floor := "the signer floor holds serial 3 digest " + bundleDigest(t, r.bundle) + " issued_at " + at.Format(time.RFC3339)
	lower := filepath.Join(r.dir, "lower.bundle")
	writeBundle(t, lower, renewDocument(2, "allow-reads"), r.bundleSigner)
	beside := filepath.Join(r.dir, "beside.bundle")
	writeBundle(t, beside, renewDocument(3, "allow-reads-too"), r.bundleSigner)
	renewRefused(t, "below the floor", r, string(policy.ErrBelowFloor), r.args("--bundle", lower)...)
	renewRefused(t, "below the floor, named", r, floor, r.args("--bundle", lower)...)
	renewRefused(t, "the serial with another digest", r, string(policy.ErrFloorSerialReused), r.args("--bundle", beside)...)
	renewRefused(t, "the serial with another digest, named", r, floor, r.args("--bundle", beside)...)
}

// TestRenewReplacesNothingButAStatement: an --out holding a key or a bundle
// is refused before the floor is raised, and keeps its bytes.
func TestRenewReplacesNothingButAStatement(t *testing.T) {
	r := newRenewTree(t)
	outs := map[string]string{
		"the freshness key":     r.freshKey,
		"the bundle key":        r.bundleKey,
		"the public key":        r.freshPub,
		"the bundle":            r.bundle,
		"a directory":           r.dir,
		"a link to a statement": linkToAStatement(t, r.dir),
	}
	for name, out := range specialOuts(t, r.dir) {
		outs[name] = out
	}
	for name, out := range outs {
		r.out = out
		renewRefused(t, name, r, "--out "+out+": ", r.args()...)
		if f := signerFloor(t, r.floor); f.HasSerial() {
			t.Fatalf("%s: the floor was raised for a statement never written", name)
		}
	}
	r.out = filepath.Join(r.dir, "none", "orders.statement")
	renewRefused(t, "a missing directory", r, "--out "+r.out+": ", r.args()...)
}

// outState is what stands at path: its type, and a regular file's bytes. A
// pipe is not opened, since nobody writes to it.
func outState(path string) string {
	info, err := os.Lstat(path)
	if err != nil {
		return "absent"
	}
	if !info.Mode().IsRegular() {
		return info.Mode().Type().String()
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a fixture path this test made
	if err != nil {
		return "unreadable"
	}
	return "file " + string(raw)
}

// linkToAStatement is a symbolic link in dir to a statement another tree's
// renew wrote, so the file behind it is one --out may replace.
func linkToAStatement(t *testing.T, dir string) string {
	t.Helper()
	other := newRenewTree(t)
	renewed(t, other, other.bundle, 3)
	link := filepath.Join(dir, "statement-link")
	if err := os.Symlink(other.out, link); err != nil {
		t.Fatal(err)
	}
	return link
}

// TestRenewWritesNoStatementIntoAFloorDirectory: an --out in the signer's own
// floor directory, by its path or through a link, and one in a plane's floor
// directory are refused before the raise, and no directory gains a file.
func TestRenewWritesNoStatementIntoAFloorDirectory(t *testing.T) {
	r := newRenewTree(t)
	plane := filepath.Join(r.dir, "plane-floors")
	if err := policystate.Init(context.Background(), plane, policystate.KindPlane, "orders-policy"); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(r.dir, "floor-link")
	if err := os.Symlink(r.floor, link); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{
		"the signer's floor":            filepath.Join(r.floor, "orders.statement"),
		"the signer's floor, by a link": filepath.Join(link, "orders.statement"),
		"a plane's floor":               filepath.Join(plane, "orders.statement"),
	} {
		r.out = out
		renewRefused(t, name, r, "--out "+out+": "+errFloorDirectory, r.args()...)
		if _, err := os.Lstat(out); err == nil {
			t.Errorf("%s: a statement was written into a floor directory", name)
		}
	}
	if signerFloor(t, r.floor).HasSerial() {
		t.Error("the floor was raised for a statement never written")
	}
}

// TestRenewKeepsTheTwoKeysApart: the freshness key named as the bundle's
// public key, or the bundle key as the freshness key, is refused before the
// bundle is read, so a bundle the freshness key signed is never vouched for.
func TestRenewKeepsTheTwoKeysApart(t *testing.T) {
	r := newRenewTree(t)
	forged := filepath.Join(r.dir, "forged.bundle")
	writeBundle(t, forged, renewDocument(9, "allow-everything"), freshSigner(t))
	renewRefused(t, "the freshness key as the bundle's", r, errOneKey,
		r.args("--bundle", forged, "--bundle-public-key", r.freshPub)...)
	renewRefused(t, "the bundle key as the freshness key", r, errOneKey, r.args("--key", r.bundleKey)...)
	renewRefused(t, "before the bundle is read", r, errOneKey,
		r.args("--bundle", filepath.Join(r.dir, "none"), "--key", r.bundleKey)...)
	renewRefused(t, "the freshness key negated as the bundle's", r, errOneKey,
		r.args("--bundle", forged, "--bundle-public-key", negatedPublic(t, r.dir))...)
	if signerFloor(t, r.floor).HasSerial() {
		t.Error("the floor moved for one key named twice")
	}
}

// TestRenewUsageErrors: a missing flag, an argument and an unknown flag are
// each the command's own one-line usage error, and nothing is written.
func TestRenewUsageErrors(t *testing.T) {
	r := newRenewTree(t)
	full := r.args()
	for i := 2; i < len(full); i += 2 {
		args := append(append([]string{}, full[:i]...), full[i+2:]...)
		checkRenewUsage(t, "without "+full[i], args)
	}
	checkRenewUsage(t, "with an argument", append(r.args(), "extra"))
	checkRenewUsage(t, "with --statement", r.args("--statement", r.out))
	checkRenewUsage(t, "asking for help", []string{"policy", "renew", "-h"})
	if _, err := os.Stat(r.out); err == nil {
		t.Error("a usage error wrote the statement")
	}
	if signerFloor(t, r.floor).HasSerial() {
		t.Error("a usage error raised the floor")
	}
}

func checkRenewUsage(t *testing.T, name string, args []string) {
	t.Helper()
	code, stdout, stderr := invoke(t, args...)
	if code != exitUsage || stdout != "" {
		t.Errorf("%s: exit %d, stdout %q; want %d and nothing", name, code, stdout, exitUsage)
	}
	if line := oneStderrLine(t, stderr); !strings.HasPrefix(line, brand.CLI+": policy renew: takes ") {
		t.Errorf("%s: stderr %q is not the command's own usage line", name, line)
	}
}

// TestRenewTakesABundleSignedUnderAConfiguredKeyID: a bundle naming an id a
// plane configures for its key, not the id the key derives, verifies under
// the public key given and is renewed; the same id over a signature by
// another key is refused.
func TestRenewTakesABundleSignedUnderAConfiguredKeyID(t *testing.T) {
	r := newRenewTree(t)
	aliased := filepath.Join(r.dir, "aliased.bundle")
	writeAliasedBundle(t, aliased, r.bundleSigner)
	renewed(t, r, aliased, 3)
	if _, st := freshStatement(t, r.out); st.Digest() != bundleDigest(t, aliased) {
		t.Errorf("--out holds the statement for %s, want the aliased bundle's", st.Digest())
	}
	forged := filepath.Join(r.dir, "forged.bundle")
	writeAliasedBundle(t, forged, freshSigner(t))
	renewRefused(t, "a bundle under the alias signed by another key", r, "--bundle "+forged+": "+string(policy.ErrSignature), r.args("--bundle", forged)...)
}

// writeAliasedBundle writes the renew document at serial 3 signed by key
// under the configured id orders-prod.
func writeAliasedBundle(t *testing.T, path string, key ed25519.PrivateKey) {
	t.Helper()
	b, err := policy.Sign([]byte(renewDocument(3, "allow-reads")), key, "orders-prod")
	if err != nil {
		t.Fatal(err)
	}
	if err := policykey.WriteBundle(path, b); err != nil {
		t.Fatal(err)
	}
}
