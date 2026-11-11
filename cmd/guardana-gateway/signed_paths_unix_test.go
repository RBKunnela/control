//go:build unix

package main

import (
	"crypto/ed25519"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
)

// writableByIdentity stands in for a machine where the plane's account may
// write the one file at writable and nothing else. A path is judged by the
// file the kernel reaches through it, as the real check's walk follows each
// link, and every path judged is recorded.
func writableByIdentity(t *testing.T, writable string) *[]string {
	t.Helper()
	marked, err := os.Stat(writable)
	if err != nil {
		t.Fatal(err)
	}
	judged := &[]string{}
	saved := notPlaneWritable
	notPlaneWritable = func(path string) (fs.FileInfo, error) {
		*judged = append(*judged, path)
		info, err := os.Stat(path)
		switch {
		case err != nil:
			return nil, err
		case os.SameFile(info, marked):
			return nil, errPlaneWritesForTest
		}
		return info, nil
	}
	t.Cleanup(func() { notPlaneWritable = saved })
	return judged
}

// dotDotPast makes, under dir, the directory near holding a link l to
// far/sub, and returns near/l/.. spelled out: the kernel follows l before the
// ".." and reaches far, while the path cleaned names near.
func dotDotPast(t *testing.T, near, far string) string {
	t.Helper()
	for _, d := range []string{near, filepath.Join(far, "sub")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(far, "sub"), filepath.Join(near, "l")); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(near, "l") + string(filepath.Separator) + ".."
}

// rosterThroughLink points the tree's trust.roster at near/l/../roster.json,
// where near/roster.json is a roster of nearID and trust/roster.json, which
// the link reaches, one of farID.
func rosterThroughLink(t *testing.T, tr tree, nearID, farID string) (near, far string) {
	t.Helper()
	alice := []ed25519.PublicKey{signedTestPublic("alice")}
	near, far = filepath.Join(tr.dir, "plane", "roster.json"), filepath.Join(tr.dir, "trust", "roster.json")
	spelled := dotDotPast(t, filepath.Dir(near), filepath.Dir(far)) + string(filepath.Separator) + "roster.json"
	writeSignedRoster(t, near, nearID, alice)
	writeSignedRoster(t, far, farID, alice)
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	moved := strings.Replace(string(raw), "  roster: trust/roster.json\n", "  roster: "+spelled+"\n", 1)
	if moved == string(raw) {
		t.Fatal("the fixture configuration names no trust.roster to move")
	}
	writeTestFile(t, tr.config, []byte(moved))
	return near, far
}

// TestASignedStartChecksTheRosterItReads: a trust.roster spelled through a
// link and ".." is judged where the plane reads it. With the plane-writable
// roster where the cleaned path names and a protected one where the link
// leads, the start and doctor's trust check both refuse it; with the two
// swapped, the start passes and takes the roster the cleaned path names.
func TestASignedStartChecksTheRosterItReads(t *testing.T) {
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	near, _ := rosterThroughLink(t, tr, "roster-a", "roster-a")
	writableByIdentity(t, near)
	if _, err := buildSigned(t, tr); !startRefusedNaming(err, "trust.roster") {
		t.Errorf("a start over a plane-writable roster behind a link and \"..\" = %v; want trust.roster refused", err)
	}
	d := &examination{cfg: tr.load(t)}
	if verdict, _, found := d.trust(t.Context()); verdict != verdictFail || !strings.HasPrefix(found, "trust.roster: under the signed authority") {
		t.Errorf("doctor's trust check over the same roster = %s, %q; want trust.roster refused", verdict, found)
	}

	tr = signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	_, far := rosterThroughLink(t, tr, "roster-a", "roster-b")
	writableByIdentity(t, far)
	p, err := buildSigned(t, tr)
	if err != nil {
		t.Fatalf("a start over a protected roster behind a link and \"..\" was refused: %v", err)
	}
	if got := p.trustHealth(t.Context()); got["state"] != "usable" || got["roster_id"] != "roster-a" {
		t.Errorf("trust = %v; want the roster-a the cleaned path names, usable", got)
	}
}

// TestASignedStartJudgesTheConfigurationItRuns: --config spelled through a
// link and ".." loads the file the cleaned path names, and the start check
// judges that same file. With a plane-writable configuration where the link
// leads, the plane runs the protected one, not the one the link reaches.
func TestASignedStartJudgesTheConfigurationItRuns(t *testing.T) {
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	spelled := dotDotPast(t, tr.dir, filepath.Join(tr.dir, "far")) + string(filepath.Separator) + filepath.Base(tr.config)
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	reached := filepath.Join(tr.dir, "far", filepath.Base(tr.config))
	turned := strings.Replace(string(raw), "framework: example", "framework: turned", 1)
	if turned == string(raw) {
		t.Fatal("the fixture configuration names no agent framework to turn")
	}
	writeTestFile(t, reached, []byte(turned))
	judged := writableByIdentity(t, reached)

	cfg, err := gatewayconfig.Load(spelled, os.Environ())
	if err != nil {
		t.Fatalf("Load(%s): %v", spelled, err)
	}
	p, err := build(cfg, slog.New(slog.DiscardHandler), time.Now(), roleServe, "")
	if err != nil {
		t.Fatalf("a start over a protected configuration named through a link and \"..\" was refused: %v", err)
	}
	t.Cleanup(func() { _ = p.close() })
	if cfg.Listener.AgentFramework != "example" {
		t.Errorf("the plane runs agent framework %q, the configuration the link reaches; want the judged file's", cfg.Listener.AgentFramework)
	}
	if len(*judged) == 0 || (*judged)[0] != cfg.File() {
		t.Fatalf("the start check judged %q first; want the configuration file %s", *judged, cfg.File())
	}
	read, err := os.Stat(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(cfg.File()); err != nil || !os.SameFile(info, read) {
		t.Errorf("the configuration judged, %s, is not the file the plane read (%v)", cfg.File(), err)
	}
}

// TestASignedStartJudgesTheFileLoadRead: the start check holds the
// configuration it judges to the file Load read. A protected file renamed
// over the path after the read, while the file read is the plane's to write,
// is refused as not the file the plane read; the file left in place passes.
func TestASignedStartJudgesTheFileLoadRead(t *testing.T) {
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	cfg := tr.load(t)
	placedApart(t)
	if err := checkSignedStart(cfg); err != nil {
		t.Fatalf("the file Load read, still at its path: the start check = %v", err)
	}

	aside := filepath.Join(t.TempDir(), "read.yaml")
	if err := os.Link(tr.config, aside); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(tr.config), "other.yaml")
	writeTestFile(t, other, raw)
	if err := os.Rename(other, tr.config); err != nil {
		t.Fatal(err)
	}
	writableByIdentity(t, aside)
	err = checkSignedStart(cfg)
	if err == nil || !strings.Contains(err.Error(), "the configuration file: "+cfg.File()+" is not the file the plane read") {
		t.Errorf("the file Load read is plane-writable and a protected one was renamed over its path: the start check = %v; want it refused as not the file read", err)
	}
}
