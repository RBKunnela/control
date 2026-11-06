package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// signedStore is newStore under the signed authority.
func signedStore(t *testing.T) (string, *approvals.Plane) {
	t.Helper()
	dir := t.TempDir()
	p, err := approvals.OpenPlane(dir, approvals.WithAuthority(approvals.HeldUnderSigned))
	if err != nil {
		t.Fatalf("opening a signed plane over %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return dir, p
}

// operatorKey writes an operator's key pair and returns the private key
// file, its public half and an empty inbox.
func operatorKey(t *testing.T) (keyFile string, pub ed25519.PublicKey, inbox string) {
	t.Helper()
	root := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	if err := policykey.WriteKeyPair(filepath.Join(root, "operator"), key); err != nil {
		t.Fatal(err)
	}
	inbox = filepath.Join(root, "inbox")
	if err := os.Mkdir(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "operator", policykey.PrivateFile), key.Public().(ed25519.PublicKey), inbox
}

// keyLabel is the key id the answer file is named by, computed apart from
// the code under test.
func keyLabel(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519-" + hex.EncodeToString(sum[:8])
}

// TestASignedAnswerIsTheRecordsSigned: approve files one answer in the inbox,
// named for the approval, the key and the decision, mode 0644, whose body
// names the plane's tenant, project, request, approval and digests, signed
// by the operator's key under the answer payload type; the approvals
// directory is left as it was.
func TestASignedAnswerIsTheRecordsSigned(t *testing.T) {
	dir, plane := signedStore(t)
	hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
	keyFile, pub, inbox := operatorKey(t)
	before := files(t, dir)
	code, stdout, stderr := invoke(t, "approvals", "approve", "--key", keyFile, "--inbox", inbox, "--reason", "checked", dir, waitingID)
	if code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	// The test runs as the account owning the directory, the plane's.
	if line := oneStderrLine(t, stderr); !strings.Contains(line, "plane's account") || !strings.Contains(line, "operator's own account") {
		t.Errorf("signing as the directory's owner warned %q, want the separation named", line)
	}
	name := waitingID + "." + keyLabel(pub) + "-approve.answer"
	if !strings.Contains(stdout, string(digestOf(t, waitingID))) || !strings.Contains(stdout, filepath.Join(inbox, name)) {
		t.Errorf("stdout %q names neither the digest signed nor the file", stdout)
	}
	body := signedBody(t, filepath.Join(inbox, name), pub)
	for member, want := range map[string]string{
		"tenant": "tenant-1", "project": "proj-1", "requestId": requestOf(waitingID), "approvalId": waitingID,
		"actionDigest": string(digestOf(t, waitingID)), "bundleDigest": string(fixtureBundle),
		"decision": "approve", "reason": "checked", "keyId": keyLabel(pub), "alg": "ed25519",
	} {
		if body[member] != want {
			t.Errorf("%s = %q, want %q", member, body[member], want)
		}
	}
	if after := files(t, dir); !maps.Equal(before, after) {
		t.Error("signing an answer changed the approvals directory")
	}
}

// signedBody is the body of the answer file at path, which has to be mode
// 0644 and one envelope signed by pub under the answer payload type.
func signedBody(t *testing.T, path string, pub ed25519.PublicKey) map[string]string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("the answer file: %v %v, want mode 0644", info, err)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own inbox
	if err != nil {
		t.Fatal(err)
	}
	env, err := policykey.ParseEnvelope(raw, 1<<16)
	if err != nil || len(env.Signatures) != 1 {
		t.Fatalf("the answer file is no envelope of one signature: %v", err)
	}
	const payloadType = "application/vnd.agent-approval-answer+json"
	if env.PayloadType != payloadType || !ed25519.Verify(pub, bundle.PAE(payloadType, env.Payload), env.Signatures[0].Signature) {
		t.Fatalf("the answer is not signed by the operator's key under %s", payloadType)
	}
	var body map[string]string
	if err := json.Unmarshal(env.Payload, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// TestASignedHoldTakesNoClaim: a claim for a hold under the signed authority
// is refused, naming the signing form, and the directory is left as it was;
// the same claim for a hold under the directory is filed.
func TestASignedHoldTakesNoClaim(t *testing.T) {
	dir, plane := signedStore(t)
	hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
	before := files(t, dir)
	code, stdout, stderr := invoke(t, "approvals", "approve", "--approver-id", "duty-officer", dir, waitingID)
	line := oneStderrLine(t, stderr)
	if code != exitFail || stdout != "" || !strings.Contains(line, "signed authority") || !strings.Contains(line, "--key") || !strings.Contains(line, "--inbox") {
		t.Fatalf("exit %d, stdout %q, stderr %q; want a refusal naming the signing form", code, stdout, line)
	}
	if after := files(t, dir); !maps.Equal(before, after) {
		t.Error("a refused claim changed the directory")
	}
	plain, other := newStore(t)
	hold(t, other, waitingID, clockNow().Add(15*time.Minute))
	if code, _, stderr := invoke(t, "approvals", "approve", "--approver-id", "duty-officer", plain, waitingID); code != exitOK {
		t.Fatalf("a claim for a directory hold: exit %d, %q", code, stderr)
	}
}

// TestASignedAnswerRefusesAndFilesNothing: a key file the group may read, an
// approval the directory does not hold, a hold under the directory
// authority, and an answer file of the same name already filed each refuse,
// and the inbox is left as it was.
func TestASignedAnswerRefusesAndFilesNothing(t *testing.T) {
	for name, c := range map[string]struct {
		arrange func(t *testing.T, keyFile, inbox, dir string) (id string)
		want    string
	}{
		"a key file others may read": {func(t *testing.T, keyFile, _, _ string) string {
			if err := os.Chmod(keyFile, 0o640); err != nil { //nolint:gosec // G302: the mode under test is one the command refuses
				t.Fatal(err)
			}
			return waitingID
		}, "--key"},
		"an approval the directory does not hold": {func(*testing.T, string, string, string) string { return "NOSUCH" },
			"no record under that approval id"},
		"an answer of that name filed already": {func(t *testing.T, keyFile, inbox, dir string) string {
			if code, _, stderr := invoke(t, "approvals", "approve", "--key", keyFile, "--inbox", inbox, dir, waitingID); code != exitOK {
				t.Fatalf("the first answer: %d %q", code, stderr)
			}
			return waitingID
		}, "owned by uid"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, plane := signedStore(t)
			hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
			keyFile, _, inbox := operatorKey(t)
			id := c.arrange(t, keyFile, inbox, dir)
			before := files(t, inbox)
			code, stdout, stderr := invoke(t, "approvals", "approve", "--key", keyFile, "--inbox", inbox, dir, id)
			if line := lastLine(stderr); code != exitFail || stdout != "" || !strings.Contains(line, c.want) {
				t.Errorf("exit %d, stdout %q, stderr %q; want a refusal naming %q", code, stdout, line, c.want)
			}
			if after := files(t, inbox); !maps.Equal(before, after) {
				t.Error("a refused answer changed the inbox")
			}
		})
	}
	t.Run("a hold under the directory authority", func(t *testing.T) {
		dir, plane := newStore(t)
		hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
		keyFile, _, inbox := operatorKey(t)
		code, _, stderr := invoke(t, "approvals", "approve", "--key", keyFile, "--inbox", inbox, dir, waitingID)
		if line := oneStderrLine(t, stderr); code != exitFail || !strings.Contains(line, "--approver-id") {
			t.Errorf("exit %d, stderr %q; want a refusal naming the claim form", code, line)
		}
		if names := files(t, inbox); len(names) != 0 {
			t.Errorf("the inbox holds %v", slicesOf(names))
		}
	})
}

// TestARejectionAfterAnApprovalIsItsOwnFile: one operator's rejection of an
// approval it approved is filed beside the approval, not over it.
func TestARejectionAfterAnApprovalIsItsOwnFile(t *testing.T) {
	dir, plane := signedStore(t)
	hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
	keyFile, pub, inbox := operatorKey(t)
	for _, verb := range []string{"approve", "reject"} {
		if code, _, stderr := invoke(t, "approvals", verb, "--key", keyFile, "--inbox", inbox, dir, waitingID); code != exitOK {
			t.Fatalf("%s: exit %d, %q", verb, code, stderr)
		}
	}
	got := files(t, inbox)
	for _, verb := range []string{"approve", "reject"} {
		if _, ok := got[waitingID+"."+keyLabel(pub)+"-"+verb+".answer"]; !ok {
			t.Errorf("no %s file in %v", verb, slicesOf(got))
		}
	}
	if len(got) != 2 {
		t.Errorf("the inbox holds %v, want two answers", slicesOf(got))
	}
}

// TestTheSigningFormTakesItsFlagsTogether: --key without --inbox, --inbox
// without --key, and --key beside --approver-id are usage errors.
func TestTheSigningFormTakesItsFlagsTogether(t *testing.T) {
	dir, plane := signedStore(t)
	hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
	keyFile, _, inbox := operatorKey(t)
	for name, args := range map[string][]string{
		"no inbox":      {"--key", keyFile},
		"no key":        {"--inbox", inbox},
		"key and claim": {"--key", keyFile, "--inbox", inbox, "--approver-id", "duty-officer"},
	} {
		code, _, stderr := invoke(t, append(append([]string{"approvals", "approve"}, args...), dir, waitingID)...)
		if code != exitUsage {
			t.Errorf("%s: exit %d, %q; want %d", name, code, stderr, exitUsage)
		}
	}
	if names := files(t, inbox); len(names) != 0 {
		t.Errorf("the inbox holds %v", slicesOf(names))
	}
}

func slicesOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestAReadOnlyConsoleRefusesThePlanesAccount: the console's read-only form,
// for an operator under the signed authority, refuses to start as the
// account that owns the approvals directory.
func TestAReadOnlyConsoleRefusesThePlanesAccount(t *testing.T) {
	dir, plane := signedStore(t)
	hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
	_, _, inbox := operatorKey(t)
	code, stdout, stderr := invoke(t, "console", "--approvals", dir, "--inbox", inbox)
	if line := oneStderrLine(t, stderr); code != exitFail || stdout != "" || !strings.Contains(line, "plane's") {
		t.Errorf("exit %d, stdout %q, stderr %q; want the plane's account refused", code, stdout, line)
	}
}

// lastLine is the last line of s, without its newline.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	return lines[len(lines)-1]
}
