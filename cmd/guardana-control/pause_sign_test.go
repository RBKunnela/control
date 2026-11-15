package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
)

// keySigner signs as key, accepting every file a write starts from: the
// writer of a file the command under test then reads.
func keySigner(key ed25519.PrivateKey) pause.Signer {
	return pause.Signer{KeyID: policykey.KeyID(key.Public().(ed25519.PublicKey)), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key)
	}, Accept: func(pause.Signed) error { return nil }}
}

// operatorPrivate is the private half of operatorKey's key.
func operatorPrivate() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
}

// writeV3 writes at path a version 3 file, which names no plane, of t1/A at
// serial over d signed with s: the version 4 body with its plane_id cut out.
// It returns the digest a plane's floor kept of it.
func writeV3(t *testing.T, path string, s pause.Signer, serial int64, d pause.Document) string {
	t.Helper()
	const placeholder = "v3-placeholder"
	bound, err := pause.BindingOf(path)
	if err != nil {
		t.Fatal(err)
	}
	body, err := pause.MarshalSigned(pause.Header{KeyID: s.KeyID, PlaneID: placeholder, Tenant: "t1", Project: "A", File: bound, Serial: serial}, d)
	if err != nil {
		t.Fatal(err)
	}
	cut := bytes.Replace(body, []byte(`"plane_id":"`+placeholder+`",`), nil, 1)
	cut = bytes.Replace(cut, []byte(`"schema_version":"4"`), []byte(`"schema_version":"3"`), 1)
	if bytes.Contains(cut, []byte("plane_id")) || !bytes.Contains(cut, []byte(`"schema_version":"3"`)) {
		t.Fatalf("the version 4 body is not spelled as writeV3 expects: %s", body)
	}
	sig, err := s.Sign(pause.PayloadType, cut)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := policykey.MarshalEnvelope(policy.StatementEnvelope{PayloadType: pause.PayloadType, Payload: cut,
		Signatures: []policy.StatementSignature{{KeyID: s.KeyID, Signature: sig}}}, pause.MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := pause.ReadSignedV3(raw)
	if err != nil {
		t.Fatal(err)
	}
	return f.Body.Digest
}

// twoPauses is the document of two entries a version 3 file holds.
var twoPauses = pause.Document{Entries: []pause.Entry{
	{ID: "g", Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Reason: "incident"},
	{ID: "p", Scope: pause.Scope{Kind: pause.ScopeProvider, Provider: "orders"}, CreatedAt: time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC), Reason: "orders down"},
}}

// pauseSignArgs is pause sign of path for plane-a under the operator key at
// keyFile, judged by judge.
func pauseSignArgs(keyFile string, judge []string, path string) []string {
	return append(append([]string{"pause", "sign", "--key", keyFile}, judge...), "--plane-id", "plane-a", path)
}

// versionThreeFile is the operator's version 3 file of twoPauses at serial
// 5 with the roster that vouches for the operator, and the digest a plane's
// floor kept of it.
func versionThreeFile(t *testing.T) (keyFile string, pub ed25519.PublicKey, judge []string, path, digest string) {
	t.Helper()
	keyFile, pub, _ = operatorKey(t)
	path = pauseDir(t)
	return keyFile, pub, rosterOf(t, pub), path, writeV3(t, path, keySigner(operatorPrivate()), 5, twoPauses)
}

// TestPauseSignCarriesAVersion3FileToTheCurrentVersion: a version 3 file of
// two entries, which list refuses naming pause sign, is signed again as
// version 4 for plane-a at the serial after its own with the same two
// entries, and says so on standard error.
func TestPauseSignCarriesAVersion3FileToTheCurrentVersion(t *testing.T) {
	keyFile, pub, judge, path, _ := versionThreeFile(t)
	if code, _, stderr := invoke(t, "pause", "list", path); code != exitFail || !strings.Contains(stderr, "pause sign --plane-id") {
		t.Errorf("pause list of a version 3 file answered %d: %q; want a refusal naming pause sign", code, stderr)
	}
	code, stdout, stderr := invoke(t, pauseSignArgs(keyFile, judge, path)...)
	if want := "signed " + path + " again as version 4 for plane plane-a at serial 6, 2 entry(ies) kept\n"; code != exitOK || stdout != want {
		t.Fatalf("pause sign answered %d: %q %q; want %q", code, stdout, stderr, want)
	}
	if !strings.Contains(stderr, "pause sign: signed serial 6 for plane plane-a tenant t1 project A of ") || !strings.HasSuffix(stderr, "2 entry(ies): g p\n") {
		t.Errorf("pause sign said %q, not what it signed", stderr)
	}
	bound, err := pause.BindingOf(path)
	if err != nil {
		t.Fatal(err)
	}
	want := pause.Header{KeyID: policykey.KeyID(pub), PlaneID: "plane-a", Tenant: "t1", Project: "A", File: bound, Serial: 6}
	if l, err := pause.List(path); err != nil || l.Signed == nil || l.Signed.Header != want || !slices.EqualFunc(l.Entries, twoPauses.Entries, sameEntryAs) {
		t.Fatalf("the file holds %+v, %v; want %+v over the two entries", l, err, want)
	}
}

// TestPauseSignPassesTheFloorAndSignsAgainHigher: the floor a plane kept of
// the version 3 file takes the file pause sign wrote; run again, it signs
// at the serial after that.
func TestPauseSignPassesTheFloorAndSignsAgainHigher(t *testing.T) {
	keyFile, _, judge, path, digest := versionThreeFile(t)
	floor := filepath.Join(t.TempDir(), "floor")
	if err := policystate.InitPause(t.Context(), floor, "t1", "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := policystate.RaisePause(t.Context(), floor, "t1", "A", 5, digest); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := invoke(t, pauseSignArgs(keyFile, judge, path)...); code != exitOK {
		t.Fatalf("pause sign answered %d: %q", code, stderr)
	}
	l, err := pause.List(path)
	if err != nil || l.Signed == nil {
		t.Fatalf("the signed file: %+v, %v", l, err)
	}
	if _, err := policystate.RaisePause(t.Context(), floor, "t1", "A", l.Signed.Serial, l.Signed.Digest); err != nil {
		t.Errorf("the floor of the version 3 file refuses the file signed again: %v", err)
	}
	if code, stdout, stderr := invoke(t, pauseSignArgs(keyFile, judge, path)...); code != exitOK || !strings.Contains(stdout, "at serial 7, 2 entry(ies) kept") {
		t.Errorf("pause sign run again answered %d: %q %q; want serial 7", code, stdout, stderr)
	}
}

// sameEntryAs compares two entries field by field.
func sameEntryAs(a, b pause.Entry) bool {
	return a.ID == b.ID && a.Scope == b.Scope && a.CreatedAt.Equal(b.CreatedAt) && a.Reason == b.Reason
}

// TestPauseSignRefusesWhatItCannotCarry: an unsigned file, a version 3 file
// mallory signed, and a version 4 file of plane-b are each refused naming
// why, and left as they were; the flags it needs are each required.
func TestPauseSignRefusesWhatItCannotCarry(t *testing.T) {
	keyFile, pub, _ := operatorKey(t)
	judge := rosterOf(t, pub)
	mallory := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6d}, ed25519.SeedSize))
	planeB := pauseDir(t)
	if code, _, stderr := invoke(t, "pause", "init", "--key", keyFile, "--plane-id", "plane-b", "--tenant", "t1", "--project", "A", planeB); code != exitOK {
		t.Fatalf("pause init for plane-b answered %d: %q", code, stderr)
	}
	forged := pauseDir(t)
	writeV3(t, forged, keySigner(mallory), 5, twoPauses)
	for _, c := range []struct{ name, path, says string }{
		{"an unsigned file", initialized(t), "not signed"},
		{"a version 3 file mallory signed", forged, "not one the roster vouches for"},
		{"a version 4 file of plane-b", planeB, "names another plane"},
	} {
		before := fileBytes(t, c.path)
		code, stdout, stderr := invoke(t, pauseSignArgs(keyFile, judge, c.path)...)
		if code != exitFail || stdout != "" || !strings.Contains(stderr, brand.CLI+": pause sign: ") || !strings.Contains(stderr, c.says) {
			t.Errorf("%s: pause sign answered %d: %q %q; want a refusal saying %q", c.name, code, stdout, stderr, c.says)
		}
		if fileBytes(t, c.path) != before {
			t.Errorf("%s: a refused pause sign changed the file", c.name)
		}
	}
	path := pauseDir(t)
	writeV3(t, path, keySigner(operatorPrivate()), 5, twoPauses)
	for _, args := range [][]string{
		{"pause", "sign", "--key", keyFile, judge[0], judge[1], judge[2], judge[3], path},
		{"pause", "sign", "--key", keyFile, "--plane-id", "plane-a", path},
		{"pause", "sign", judge[0], judge[1], judge[2], judge[3], "--plane-id", "plane-a", path},
		{"pause", "sign", "--key", keyFile, judge[0], judge[1], judge[2], judge[3], "--plane-id", "plane-a"},
	} {
		if code, _, _ := invoke(t, args...); code != exitUsage {
			t.Errorf("%v answered %d, want the usage status", args[2:], code)
		}
	}
	if code, _, stderr := invoke(t, pauseSignArgs(keyFile, judge, path)...); code != exitOK {
		t.Errorf("the control, every flag over the operator's version 3 file, answered %d: %q", code, stderr)
	}
}
