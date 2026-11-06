//go:build unix

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// swapToLink has the next bind's path replaced, between the bind and the
// mode change, by a link to a file of mode 0600, and returns that file.
func swapToLink(t *testing.T) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketBound = func(bound string) {
		if err := os.Remove(bound); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(target, bound); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { socketBound = nil })
	return target
}

// expectMode fails unless the file at path has mode want.
func expectMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != want {
		t.Errorf("%s has mode %v, %v; want %v", path, info.Mode(), err, want)
	}
}

// TestASwappedSocketPathChangesNoFilesMode: a link put where collect's and
// the health socket were bound, before their mode is set, leaves the file
// it points to as it was, and nothing is bound.
func TestASwappedSocketPathChangesNoFilesMode(t *testing.T) {
	for name, listen := range map[string]func(string) error{
		"collect": func(path string) error { _, err := listenCollectSocket(path); return err },
		"health":  func(path string) error { _, err := listenHealthSocket(path, false); return err },
	} {
		t.Run(name, func(t *testing.T) {
			target := swapToLink(t)
			path := shortSocketPath(t)
			if err := listen(path); err == nil {
				t.Error("a swapped socket was bound")
			}
			expectMode(t, target, 0o600)
			if _, err := os.Lstat(path); err == nil {
				t.Errorf("%s exists after a refused bind", path)
			}
			if leftover, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".s*")); len(leftover) != 0 {
				t.Errorf("the private directory is left: %v", leftover)
			}
		})
	}
}

// TestCollectRefusesADirectoryOthersCanReplaceItsSocketIn: a parent the
// group or others may write and that is not sticky is refused before the
// trail is opened; a sticky one is taken.
func TestCollectRefusesADirectoryOthersCanReplaceItsSocketIn(t *testing.T) {
	path := shortSocketPath(t)
	dir := filepath.Dir(path)
	for _, mode := range []os.FileMode{0o777, 0o720, 0o702} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "trail")
		var stdout, stderr bytes.Buffer
		// A collect that took the path serves until the context ends and
		// then exits 0, which is not the refusal wanted.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		status := run(ctx, collectArgs(t, "unix://"+path, out), &stdout, &stderr)
		cancel()
		if status != exitFail ||
			!strings.Contains(stderr.String(), "not sticky") {
			t.Errorf("a directory of mode %v answered %d with %q", mode, status, stderr.String())
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("mode %v: the trail was opened", mode)
		}
	}
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	ln, err := listenCollectSocket(path)
	if err != nil {
		t.Fatalf("a sticky directory: %v", err)
	}
	expectMode(t, path, 0o666)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestTheHealthSocketsDirectoryIsThePlanesAlone: a directory others may
// write is refused, and so is one they may enter unless health.socket_uid
// names another account; then 0755 is taken and 0775 is not.
func TestTheHealthSocketsDirectoryIsThePlanesAlone(t *testing.T) {
	path := shortSocketPath(t)
	dir := filepath.Dir(path)
	for _, tc := range []struct {
		mode      os.FileMode
		reachable bool
		taken     bool
	}{
		{0o777, false, false}, {0o777, true, false}, {0o755, false, false}, {0o710, false, false},
		{0o775, true, false}, {0o757, true, false}, {0o755, true, true}, {0o700, false, true},
	} {
		if err := os.Chmod(dir, tc.mode); err != nil {
			t.Fatal(err)
		}
		ln, err := listenHealthSocket(path, tc.reachable)
		if taken := err == nil; taken != tc.taken {
			t.Errorf("mode %v, another account %v: taken %v (%v), want %v", tc.mode, tc.reachable, taken, err, tc.taken)
		}
		if err == nil {
			if err := ln.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestTheWholeAnswerListsNoStopAsEmpty: the health socket's answer keeps
// its stop members on a plane with no stop, as empty lists.
func TestTheWholeAnswerListsNoStopAsEmpty(t *testing.T) {
	p := newTree(t).plane(t)
	rec := httptest.NewRecorder()
	p.serveWholeHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	raw, _ := io.ReadAll(rec.Body)
	for _, member := range []string{`"entries":[]`, `"unheld_runs":[]`, `"unread_runs":[]`} {
		if !strings.Contains(string(raw), member) {
			t.Errorf("the whole answer lacks %s: %s", member, raw)
		}
	}
}

// TestARefusedHealthDirectoryKeepsItsStaleSocket: the directory is judged
// before anything in it is removed, so a stale socket in a directory others
// may write stays where it is.
func TestARefusedHealthDirectoryKeepsItsStaleSocket(t *testing.T) {
	path := shortSocketPath(t)
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o777); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	if _, err := listenHealthSocket(path, false); err == nil {
		t.Fatal("a directory others may write was taken")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode().Type() != os.ModeSocket {
		t.Errorf("the stale socket is gone: %v, %v", info, err)
	}
}
