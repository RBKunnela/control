package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/trust"
)

// rosterOf writes a roster naming pub as an operator of t1/A, signed under a
// root drawn for it, and returns the flags that judge a signed write by it.
func rosterOf(t *testing.T, pub ed25519.PublicKey) []string {
	t.Helper()
	dir := t.TempDir()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7e}, ed25519.SeedSize))
	source, err := canon.Canonicalize(map[string]any{
		"kind": trust.DocumentKind, "rosterId": "roster-a", "serial": 1,
		"keys": []any{map[string]any{
			"keyId": policykey.KeyID(pub), "alg": "ed25519", "role": "operator", "subject": "alice",
			"publicKey": policykey.FormatPublic(pub),
			"grants":    []any{map[string]any{"tenant": "t1", "project": "A", "level": "operate"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := trust.SignDocument(source, time.Now().UTC().Truncate(time.Second), time.Hour, root)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := trust.MarshalFile(env)
	if err != nil {
		t.Fatal(err)
	}
	roster, rootKey := filepath.Join(dir, "roster.json"), filepath.Join(dir, "root.pub")
	if err := os.WriteFile(roster, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootKey, []byte(policykey.FormatPublic(root.Public().(ed25519.PublicKey))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"--roster", roster, "--root-key", rootKey}
}

// invokeSigned is invoke of the pause command words, then --key keyFile and
// the roster flags judge, then rest.
func invokeSigned(t *testing.T, words []string, keyFile string, judge []string, rest ...string) (int, string, string) {
	t.Helper()
	args := append(append(append(append([]string{"pause"}, words...), "--key", keyFile), judge...), rest...)
	return invoke(t, args...)
}

// signedInitialized is a pause file signed with the operator key at keyFile
// for t1/A at serial 7.
func signedInitialized(t *testing.T, keyFile string) string {
	t.Helper()
	path := pauseDir(t)
	code, stdout, stderr := invoke(t, "pause", "init", "--key", keyFile, "--tenant", "t1", "--project", "A", "--serial", "7", path)
	if code != exitOK || !strings.Contains(stdout, "at serial 7") {
		t.Fatalf("pause init --key answered %d: %q %q", code, stdout, stderr)
	}
	return path
}

// TestSignedPauseCommandsSignEveryChangeAtTheNextSerial: init, add and
// remove with --key each leave a file signed by the key at a serial one
// above the last, for the tenant and project init named, and list names the
// signer.
func TestSignedPauseCommandsSignEveryChangeAtTheNextSerial(t *testing.T) {
	keyFile, pub, _ := operatorKey(t)
	judge := rosterOf(t, pub)
	path := signedInitialized(t, keyFile)
	code, id, stderr := invokeSigned(t, []string{"add", "--global"}, keyFile, judge, path)
	id = strings.TrimSpace(id)
	if code != exitOK || !drawnID.MatchString(id) {
		t.Fatalf("pause add --key answered %d: %q %q", code, id, stderr)
	}
	if !strings.Contains(stderr, "signed serial 8 for tenant t1 project A of ") || !strings.Contains(stderr, "1 entry(ies): "+id) {
		t.Errorf("pause add --key said %q, not what it signed", stderr)
	}
	bound, err := pause.BindingOf(path)
	if err != nil {
		t.Fatal(err)
	}
	want := pause.Header{KeyID: policykey.KeyID(pub), Tenant: "t1", Project: "A", File: bound, Serial: 8}
	holdsSigned(t, path, want, id)
	listsSigned(t, path, "signed by key "+want.KeyID+" for tenant t1 project A at serial 8;", id+" global")
	if code, _, stderr := invokeSigned(t, []string{"remove"}, keyFile, judge, path, id); code != exitOK {
		t.Fatalf("pause remove --key answered %d: %q", code, stderr)
	}
	if l, err := pause.List(path); err != nil || l.Signed == nil || l.Signed.Serial != 9 || len(l.Entries) != 0 {
		t.Errorf("after the removal the file holds %+v, %v", l, err)
	}
}

// holdsSigned fails unless the file at path is signed under want and holds
// the one entry id.
func holdsSigned(t *testing.T, path string, want pause.Header, id string) {
	t.Helper()
	l, err := pause.List(path)
	if err != nil || l.Signed == nil || l.Signed.Header != want || len(l.Entries) != 1 || l.Entries[0].ID != id {
		t.Fatalf("the file holds %+v, %v; want %+v with the entry %s", l, err, want, id)
	}
}

// listsSigned fails unless pause list of path opens with first and holds
// entry.
func listsSigned(t *testing.T, path, first, entry string) {
	t.Helper()
	code, stdout, _ := invoke(t, "pause", "list", path)
	if code != exitOK || !strings.HasPrefix(stdout, first) || !strings.Contains(stdout, entry) {
		t.Errorf("list answered %d: %q", code, stdout)
	}
}

// TestASignedPauseFileRefusesAnUnsignedWrite: an add or a removal without
// --key is refused naming the flag, and writes nothing; one with --key to an
// unsigned file is refused naming the signed init; --key needs the roster
// flags, and they need --key.
func TestASignedPauseFileRefusesAnUnsignedWrite(t *testing.T) {
	keyFile, pub, _ := operatorKey(t)
	judge := rosterOf(t, pub)
	path := signedInitialized(t, keyFile)
	before := fileBytes(t, path)
	expectRefusal(t, "pause add", "sign the change with --key <operator key file>", "pause", "add", "--global", path)
	expectRefusal(t, "pause remove", "sign the change with --key <operator key file>", "pause", "remove", path, "P1")
	if fileBytes(t, path) != before {
		t.Error("a refused unsigned write changed the signed file")
	}
	unsigned := initialized(t)
	code, _, stderr := invokeSigned(t, []string{"add", "--global"}, keyFile, judge, unsigned)
	if code != exitFail || !strings.Contains(stderr, "a signed pause file starts with pause init --key") {
		t.Errorf("a signed add to an unsigned file answered %d: %q", code, stderr)
	}
	for _, args := range [][]string{
		{"add", "--global", "--key", keyFile, path},
		{"add", "--global", "--key", keyFile, "--roster", judge[1], path},
		{"remove", "--key", keyFile, path, "P1"},
		{"add", "--global", "--roster", judge[1], "--root-key", judge[3], path},
	} {
		if code, _, _ := invoke(t, append([]string{"pause"}, args...)...); code != exitUsage {
			t.Errorf("pause %v answered %d, want the usage status", args, code)
		}
	}
	if fileBytes(t, path) != before {
		t.Error("a refused write changed the signed file")
	}
}

// TestASignedWriteSignsNoEntriesAKeylessWriterPutThere: a file a writer
// signed with a key the roster does not name is refused by add and remove
// with --key, naming what they found, and left as it was.
func TestASignedWriteSignsNoEntriesAKeylessWriterPutThere(t *testing.T) {
	keyFile, pub, _ := operatorKey(t)
	judge := rosterOf(t, pub)
	path := signedInitialized(t, keyFile)
	bound, err := pause.BindingOf(path)
	if err != nil {
		t.Fatal(err)
	}
	mallory := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6d}, ed25519.SeedSize))
	forged := pause.Signer{KeyID: policykey.KeyID(mallory.Public().(ed25519.PublicKey)), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, mallory)
	}, Accept: func(pause.Signed) error { return nil }}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := pause.InitSigned(t.Context(), path, pause.Header{KeyID: forged.KeyID, Tenant: "t1", Project: "A", File: bound, Serial: 9}, forged); err != nil {
		t.Fatal(err)
	}
	before := fileBytes(t, path)
	for _, words := range [][]string{{"add", "--global"}, {"remove"}} {
		rest := []string{path}
		if words[0] == "remove" {
			rest = append(rest, "P1")
		}
		code, stdout, stderr := invokeSigned(t, words, keyFile, judge, rest...)
		if code != exitFail || stdout != "" || !strings.Contains(stderr, "not one the roster vouches for") || !strings.Contains(stderr, "serial 9 signed by key "+forged.KeyID) {
			t.Errorf("pause %s over mallory's file answered %d: %q %q", words[0], code, stdout, stderr)
		}
	}
	if fileBytes(t, path) != before {
		t.Error("a refused write changed mallory's file")
	}
}

// TestPauseInitTakesTheSignedFlagsTogether: --tenant, --project and
// --serial make a signed file only with --key, and --key needs the tenant
// and the project.
func TestPauseInitTakesTheSignedFlagsTogether(t *testing.T) {
	keyFile, _, _ := operatorKey(t)
	for _, args := range [][]string{
		{"--tenant", "t1", "--project", "A"},
		{"--serial", "2"},
		{"--key", keyFile, "--tenant", "t1"},
		{"--key", keyFile, "--project", "A"},
	} {
		code, stdout, stderr := invoke(t, append(append([]string{"pause", "init"}, args...), pauseDir(t))...)
		if code != exitUsage || stdout != "" || stderr == "" {
			t.Errorf("init %v answered %d with %q and %q; want the usage status", args, code, stdout, stderr)
		}
	}
	expectRefusal(t, "pause init", "serial", "pause", "init", "--key", keyFile, "--tenant", "t1", "--project", "A", "--serial", "0", pauseDir(t))
}

func TestPauseFloorInitMakesThePlanesFloorOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "floor")
	code, stdout, stderr := invoke(t, "pause", "floor", "init", "--tenant", "t1", "--project", "A", dir)
	if code != exitOK || stdout != "tenant: t1\nproject: A\nfloor: no serial\n" {
		t.Fatalf("pause floor init answered %d: %q %q", code, stdout, stderr)
	}
	if f, err := policystate.ReadPause(dir, "t1", "A"); err != nil || f.HasSerial() {
		t.Errorf("the floor = %+v, %v", f, err)
	}
	expectRefusal(t, "pause floor init", "floor file already", "pause", "floor", "init", "--tenant", "t1", "--project", "A", dir)
	if code, _, _ := invoke(t, "pause", "floor", "init", "--tenant", "t1", dir); code != exitUsage {
		t.Errorf("floor init with no project answered %d", code)
	}
}
