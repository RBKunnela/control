//go:build unix

package main

import (
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policystate"
)

// planeWritableKeys are the file keys of the signed authority whose entries
// the plane's own account writes by design, each with the reason.
var planeWritableKeys = map[string]string{
	"trust.floor_dir":            "the plane raises the roster's floor itself",
	"pause.floor_dir":            "the plane raises the pause file's floor itself",
	"reaction.floor_dir":         "the plane raises the route's floor itself",
	"reaction.stops_floor_dir":   "the plane raises the stop list's floor itself",
	"approvals.dir":              "the plane writes its records of held calls; an answer counts only from the inbox",
	"approvals.hold_journal_dir": "the plane writes its own hold journal",
	"approvals.inbox_dir":        "operators file answers there and the plane prunes them; an answer counts only as the roster vouches for its signer",
}

// outsideSignedKeys are the file keys the signed authority does not read,
// each with the reason.
var outsideSignedKeys = map[string]string{
	"listener.socket":       "the socket the plane serves agents on",
	"health.socket":         "the socket the plane answers health on",
	"policy.bundle_file":    "verified under policy.public_key, which no roster may name",
	"policy.statement_file": "verified under policy.freshness_public_key, which no roster may name",
	"policy.state_dir":      "the plane's own policy floor",
	"evidence.dir":          "the plane's own spool",
	"reaction.public_key":   "refused under signed, where an operator signs the route",
	"upstreams.N.command":   "a program the plane starts, which grants no authority",
}

// fullSignedTree is signedStopsTree with a signed pause file and its floor,
// so every file key of the signed authority is set.
func fullSignedTree(t *testing.T) tree {
	t.Helper()
	tr := signedStopsTree(t)
	if err := os.Mkdir(filepath.Join(tr.dir, "pause"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := policystate.InitPause(t.Context(), filepath.Join(tr.dir, "pausefloor"), "acme", "orders"); err != nil {
		t.Fatal(err)
	}
	s := aliceSigner()
	if err := pause.InitSigned(t.Context(), filepath.Join(tr.dir, "pause", "pause.json"),
		pause.Header{KeyID: s.KeyID, Tenant: "acme", Project: "orders", Serial: 1}, s); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, tr.config, append(raw, []byte("\npause:\n  file: pause/pause.json\n  floor_dir: pausefloor\n")...))
	return tr
}

// inEntry reports whether path is entry or lies under it.
func inEntry(path, entry string) bool {
	return path == entry || strings.HasPrefix(path, entry+string(filepath.Separator))
}

// judgedWith replaces the plane's writability check for the test: judge
// answers for every path within entry, and every other path passes.
func judgedWith(t *testing.T, entry string, judge func(string) error) {
	t.Helper()
	saved := notPlaneWritable
	notPlaneWritable = func(path string) (fs.FileInfo, error) {
		if inEntry(path, entry) {
			return judgedEntry(path), judge(path)
		}
		return judgedEntry(path), nil
	}
	t.Cleanup(func() { notPlaneWritable = saved })
}

func startRefusedNaming(err error, key string) bool {
	return err != nil && strings.Contains(err.Error(), key+": under the signed authority the plane's own account may not be able to change it")
}

// TestEveryFileKeyIsCheckedAtASignedStartOrNamedWithItsReason: each file key
// of the configuration, made plane-writable on its own in a tree that sets
// them all, either refuses the signed start naming itself or is named above
// with the reason the plane may write it or never reads it under signed. A
// key in neither fails, so a file key added later cannot go unjudged.
func TestEveryFileKeyIsCheckedAtASignedStartOrNamedWithItsReason(t *testing.T) {
	cfg := fullSignedTree(t).load(t)
	values := settingsOf(cfg)
	files := map[string]bool{}
	for _, f := range gatewayconfig.Fields() {
		if !f.File {
			continue
		}
		files[f.Path] = true
		judgeFileKey(t, cfg, f.Path, values[f.Path])
	}
	for key := range planeWritableKeys {
		if _, both := outsideSignedKeys[key]; both {
			t.Errorf("%s is named both plane-writable and outside the signed authority", key)
		}
	}
	for _, named := range []map[string]string{planeWritableKeys, outsideSignedKeys} {
		for key := range named {
			if !files[key] {
				t.Errorf("%s is named here and is no file key of the configuration", key)
			}
		}
	}
}

// TestEveryFileKeyOfAMinimalSignedTreeIsChecked: the same classification
// over a tree that sets only what a signed start needs, so a check that
// holds only while another key is set fails here.
func TestEveryFileKeyOfAMinimalSignedTreeIsChecked(t *testing.T) {
	cfg := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a").load(t)
	values := settingsOf(cfg)
	judged := 0
	for _, f := range gatewayconfig.Fields() {
		if f.File && values[f.Path] != "" {
			judged++
			judgeFileKey(t, cfg, f.Path, values[f.Path])
		}
	}
	if values["trust.roster"] == "" || values["pause.file"] != "" || values["reaction.route"] != "" || values["runs.dir"] != "" {
		t.Errorf("the minimal tree sets roster %q, pause %q, route %q, runs %q; want the roster alone of them",
			values["trust.roster"], values["pause.file"], values["reaction.route"], values["runs.dir"])
	}
	if judged == 0 {
		t.Error("the minimal tree sets no file key")
	}
}

func settingsOf(cfg *gatewayconfig.Config) map[string]string {
	values := map[string]string{}
	for _, s := range cfg.Settings() {
		values[s.Path] = s.Value
	}
	return values
}

// judgeFileKey makes the entry of key, whose value the configuration holds,
// plane-writable alone and holds what the signed start answers to the
// classification above.
func judgeFileKey(t *testing.T, cfg *gatewayconfig.Config, key, value string) {
	t.Helper()
	_, writable := planeWritableKeys[key]
	_, outside := outsideSignedKeys[key]
	if value == "" {
		if !outside {
			t.Errorf("%s: the tree sets no value, so whether a signed start checks it is not known", key)
		}
		return
	}
	judgedWith(t, cfg.Resolve(value), func(string) error { return errPlaneWritesForTest })
	err := checkSignedStart(cfg)
	checked := startRefusedNaming(err, key)
	switch {
	case err != nil && !checked:
		t.Errorf("%s made plane-writable: the start refused naming another entry: %v", key, err)
	case checked && (writable || outside):
		t.Errorf("%s is checked at a signed start and also named as one it need not check", key)
	case !checked && !writable && !outside:
		t.Errorf("%s names a file and a signed start does not check it; check it in checkSignedStart, or name it here with the reason", key)
	}
}

var errPlaneWritesForTest = errors.New("the plane's account may write it")

// TestASignedConfigurationRefusesTheRouteKey: reaction.public_key is outside
// the signed authority because a signed configuration refuses it at load.
func TestASignedConfigurationRefusesTheRouteKey(t *testing.T) {
	tr := fullSignedTree(t)
	setEnv(t, "reaction.public_key", "route.pub")
	if _, err := gatewayconfig.Load(tr.config, os.Environ()); err == nil || !strings.Contains(err.Error(), "reaction.public_key: set, and the signed authority reads no such key") {
		t.Fatalf("Load with reaction.public_key under signed = %v", err)
	}
}

// TestASignedStartRefusesEachCheckedEntryAndADirectoryOnItsWay: each entry a
// signed start checks, the roster among them, made plane-writable alone
// refuses the start naming its key; judged by the real check alone, which
// walks the directories on its way and meets this test's own temporary
// directory, it refuses naming that directory; with none writable the start
// passes.
func TestASignedStartRefusesEachCheckedEntryAndADirectoryOnItsWay(t *testing.T) {
	tr := fullSignedTree(t)
	cfg := tr.load(t)
	for key, entry := range map[string]string{
		"trust.root_public_key": "trust/root.pub",
		"trust.roster":          "trust/roster.json",
		"pause.file":            "pause/pause.json",
		"reaction.route":        "route.json",
		"reaction.stops":        "stops",
		"runs.dir":              "runs/records",
	} {
		path := filepath.Join(tr.dir, filepath.FromSlash(entry))
		judgedWith(t, path, func(string) error { return errPlaneWritesForTest })
		if err := checkSignedStart(cfg); !startRefusedNaming(err, key) {
			t.Errorf("%s plane-writable: the start = %v", entry, err)
		}
		judgedWith(t, path, gatewayconfig.CheckNotPlaneWritable)
		err := checkSignedStart(cfg)
		if !startRefusedNaming(err, key) || (os.Geteuid() != 0 && !strings.Contains(err.Error(), "the directory ")) {
			t.Errorf("%s judged by the real check on this test's account: the start = %v, want %s refused at a directory on its way", entry, err, key)
		}
	}
	judgedWith(t, tr.dir, func(string) error { return nil })
	if err := checkSignedStart(cfg); err != nil {
		t.Fatalf("a tree whose entries are all placed apart: the start = %v", err)
	}
}
