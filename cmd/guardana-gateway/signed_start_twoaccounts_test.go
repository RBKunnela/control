//go:build twoaccounts && unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/runs"
)

// TestASignedStartAsThePlanesAccountJudgesRealOwnership: a signed layout
// whose every file root owns, 0644 in 0755 directories,
// passes the start check run as the plane's account; each file the check
// reads, handed to the plane's account, refuses the start naming its key,
// and so do a roster the plane's account may write by its mode and the
// directory of the trust files it may write.
func TestASignedStartAsThePlanesAccountJudgesRealOwnership(t *testing.T) {
	plane, _ := twoAccounts(t)
	// The configuration's directories have to be the plane's or root's, so
	// root is the operator here, as an /etc layout makes it.
	operator := account{}
	tr := fullSignedTree(t)
	cfg := tr.load(t)
	openToEveryAccount(t, tr.dir)
	giveTree(t, tr.dir, operator)

	if out := startCheckAs(t, plane, tr.config); out != "ok" {
		t.Fatalf("the operator's layout, judged as the plane's account: %q; want ok", out)
	}
	for key, path := range map[string]string{
		"the configuration file": tr.config,
		"trust.root_public_key":  cfg.Resolve(cfg.Trust.RootPublicKey),
		"trust.roster":           cfg.Resolve(cfg.Trust.Roster),
		"pause.file":             cfg.Resolve(cfg.Pause.File),
		"reaction.route":         cfg.Resolve(cfg.Reaction.Route),
		"reaction.stops":         cfg.Resolve(cfg.Reaction.Stops),
		"runs.dir":               filepath.Join(cfg.Resolve(cfg.Runs.Dir), runs.RecordsDir),
	} {
		t.Run(key, func(t *testing.T) {
			chownTo(t, path, plane)
			defer chownTo(t, path, operator)
			out := startCheckAs(t, plane, tr.config)
			if !strings.HasPrefix(out, key+": under the signed authority the plane's own account may not be able to change it") ||
				!strings.Contains(out, "owned by the plane's account") {
				t.Errorf("%s owned by the plane's account: %q; want the start refused naming it", key, out)
			}
		})
	}

	roster := cfg.Resolve(cfg.Trust.Roster)
	setMode(t, roster, 0o666)
	out := startCheckAs(t, plane, tr.config)
	if !strings.HasPrefix(out, "trust.roster: under the signed authority") || !strings.Contains(out, "the plane's account may write it") {
		t.Errorf("a roster of mode 0666: %q; want the start refused naming trust.roster", out)
	}
	setMode(t, roster, 0o644)

	rosterDir := filepath.Dir(roster)
	setMode(t, rosterDir, 0o777)
	out = startCheckAs(t, plane, tr.config)
	if !strings.HasPrefix(out, "trust.") || !strings.Contains(out, "under the signed authority") ||
		!strings.Contains(out, "the directory "+rosterDir+": the plane's account may write it") {
		t.Errorf("the trust files' directory of mode 0777: %q; want the start refused naming the directory", out)
	}
	setMode(t, rosterDir, 0o755)
	if out := startCheckAs(t, plane, tr.config); out != "ok" {
		t.Errorf("the layout put back: %q; want ok", out)
	}
}

// startCheckAs runs checkSignedStart over the configuration at path as a
// and returns what it printed.
func startCheckAs(t *testing.T, a account, path string) string {
	t.Helper()
	out, stderr, code := a.as(t, "signed-start", path)
	if code != 0 {
		t.Fatalf("the start check as uid %d exited %d: %q %q", a.uid, code, out, stderr)
	}
	return strings.TrimSpace(out)
}

func chownTo(t *testing.T, path string, a account) {
	t.Helper()
	if err := os.Lchown(path, int(a.uid), int(a.gid)); err != nil {
		t.Fatal(err)
	}
}

func setMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
