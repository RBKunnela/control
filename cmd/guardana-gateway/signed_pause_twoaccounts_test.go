//go:build twoaccounts && unix

package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/pause/signedpause"
)

// TestAPauseTheOperatorRewritesIsReadByThePlaneInItsGroup lays the pause
// out as the operators' guide does: the directory the operator's, the
// plane's group, mode 2750, and alice's signed file 0640. The plane, as its
// own account, reads it clear; the operator, as its own, adds a pause; the
// plane then reads it paused, and the file is still the operator's, in the
// plane's group, 0640. The same file once the plane's group may write it
// refuses the plane's start.
func TestAPauseTheOperatorRewritesIsReadByThePlaneInItsGroup(t *testing.T) {
	plane, operator := twoAccounts(t)
	tr := signedPauseTree(t)
	cfg := tr.load(t)
	file, dir := cfg.Resolve(cfg.Pause.File), filepath.Dir(cfg.Resolve(cfg.Pause.File))
	openToEveryAccount(t, tr.dir)
	giveTree(t, tr.dir, account{})
	giveFloor(t, cfg.Resolve(cfg.Trust.FloorDir), plane)
	giveFloor(t, cfg.Resolve(cfg.Pause.FloorDir), plane)
	inGroup := account{uid: operator.uid, gid: plane.gid}
	chownTo(t, dir, inGroup)
	setMode(t, dir, 0o750|os.ModeSetgid)
	chownTo(t, file, inGroup)
	setMode(t, file, 0o640)

	if got := pauseReadAs(t, plane, tr.config); got != "clear" {
		t.Fatalf("alice's pause with no entry, read as the plane's account: %q; want clear", got)
	}
	if out, stderr, code := operator.as(t, "add-pause", file); code != 0 || strings.TrimSpace(out) != "ok" {
		t.Fatalf("the operator's add as uid %d: exit %d, %q %q", operator.uid, code, out, stderr)
	}
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != operator.uid || st.Gid != plane.gid || info.Mode() != 0o640 {
		t.Errorf("the rewritten pause file: %v, %v; want the operator's, in the plane's group %d, mode 0640", info.Mode(), info.Sys(), plane.gid)
	}
	if got := pauseReadAs(t, plane, tr.config); got != "paused" {
		t.Errorf("the operator's pause, read as the plane's account: %q; want paused", got)
	}

	setMode(t, file, 0o660)
	got := pauseReadAs(t, plane, tr.config)
	if !strings.HasPrefix(got, "pause.file: under the signed authority") || !strings.Contains(got, "the plane's account may write it") {
		t.Errorf("a pause file the plane's group may write: %q; want the start refused naming pause.file", got)
	}
}

// pauseReadAs runs the plane's signed pause read over the configuration at
// path as a and returns what it printed.
func pauseReadAs(t *testing.T, a account, path string) string {
	t.Helper()
	out, stderr, code := a.as(t, "read-pause", path)
	if code != 0 {
		t.Fatalf("the pause read as uid %d exited %d: %q %q", a.uid, code, out, stderr)
	}
	return strings.TrimSpace(out)
}

// giveFloor hands the floor directory dir and every entry under it to a,
// directories 0700 and files 0600, as a floor's owner alone may use it.
func giveFloor(t *testing.T, dir string, a account) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o600)
		if d.IsDir() {
			mode = 0o700
		}
		if err := os.Lchown(path, int(a.uid), int(a.gid)); err != nil { //nolint:gosec // G122: a test's own directory, which no other account may write
			return err
		}
		return os.Chmod(path, mode) //nolint:gosec // G122: a test's own directory, which no other account may write
	})
	if err != nil {
		t.Fatalf("handing %s to uid %d: %v", dir, a.uid, err)
	}
}

// addPauseAsOperator adds a global pause, signed by alice, to the signed
// pause file at path and prints "ok".
func addPauseAsOperator(path string) int {
	e := pause.Entry{ID: "g", Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: time.Now().UTC()}
	if _, err := pause.AddSigned(context.Background(), path, e, aliceSigner()); err != nil {
		fmt.Fprintf(os.Stderr, "add: %v\n", err)
		return 2
	}
	return tellParent("ok")
}

// readPauseAsPlane loads the configuration at path, opens the trust roster
// past the plane's start check and reads the pause file as a serving plane
// judges it, printing its state, or the refusal that stopped the open.
func readPauseAsPlane(path string) int {
	cfg, err := gatewayconfig.Load(path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		return 2
	}
	ports, err := openSigned(context.Background(), cfg, nil)
	if err != nil {
		return tellParent(err.Error())
	}
	j, err := signedpause.New(ports.authn, ports.authz, cfg.PlaneID, cfg.TenantID, cfg.ProjectID,
		cfg.Resolve(cfg.Pause.File), cfg.Resolve(cfg.Pause.FloorDir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "judge: %v\n", err)
		return 2
	}
	s := pause.ReadSigned(context.Background(), cfg.Resolve(cfg.Pause.File), time.Now(), time.Second, j)
	if s.State() == pause.Unknown {
		return tellParent(fmt.Sprintf("unknown %s: %s", s.Cause(), s.Detail()))
	}
	return tellParent(s.State().String())
}
