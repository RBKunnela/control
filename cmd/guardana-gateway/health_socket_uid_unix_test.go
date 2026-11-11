//go:build unix

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// otherUID is an account that is not this process's.
func otherUID() string {
	if os.Geteuid() == 4242 {
		return "4243"
	}
	return "4242"
}

// TestAHealthSocketUIDOfThePlanesOwnAccountIsRefused: health.socket_uid
// naming the plane's own account refuses the start and binds nothing, and
// doctor fails on it; another account is taken, with the socket 0666.
func TestAHealthSocketUIDOfThePlanesOwnAccountIsRefused(t *testing.T) {
	own := strconv.Itoa(os.Geteuid())
	path := shortSocketPath(t)
	p, _, _ := stoppedRuns(t, path, own)
	_, err := p.bindHealthSocket(io.Discard, nil)
	if want := "health.socket_uid: " + own + " is the plane's own account"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("binding with health.socket_uid %s: %v; want %q", own, err, want)
	}
	if _, err := os.Lstat(path); err == nil {
		t.Error("a refused health.socket_uid left a socket bound")
	}
	unserved, _ := searchableSocketPath(t, 0o755)
	tr := newTree(t)
	setEnv(t, "health.socket", unserved)
	setEnv(t, "health.socket_uid", own)
	var stdout bytes.Buffer
	doctor(context.Background(), tr.config, &stdout, io.Discard)
	if line := reportLine(stdout.String(), "health.socket"); !strings.HasPrefix(line, "fail ") || !strings.Contains(line, "is the plane's own account") {
		t.Errorf("doctor's health.socket line is %q", line)
	}

	other := shortSocketPath(t)
	q, _, _ := stoppedRuns(t, other, otherUID())
	serveSocket(t, q, func(net.Conn) (uint32, error) { return 0, nil })
	expectMode(t, other, 0o666)
}

// searchableSocketPath is a socket path in a new directory under /tmp,
// whose every directory above it any account may search, so the directory
// itself is the one a test's mode decides.
func searchableSocketPath(t *testing.T, mode os.FileMode) (string, string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "s.sock"), resolved
}

// TestDoctorNamesADirectoryHealthSocketUIDCannotSearch: with
// health.socket_uid, a socket directory that account may not search is
// named in a warning, one only its group may search is named with the
// group, and a directory any account may search is not named.
func TestDoctorNamesADirectoryHealthSocketUIDCannotSearch(t *testing.T) {
	uid := otherUID()
	for _, tc := range []struct {
		mode os.FileMode
		want string
	}{
		{0o700, "warning: health.socket: health.socket_uid " + uid + " is never answered: it may not search %s (mode 0700, owner uid " + strconv.Itoa(os.Geteuid()) + ")"},
		{0o710, "warning: health.socket: health.socket_uid " + uid + " connects only as a member of gid %g, the one group that may search %s (mode 0710)"},
		{0o755, ""},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			path, resolved := searchableSocketPath(t, tc.mode)
			tr := newTree(t)
			setEnv(t, "health.socket", path)
			setEnv(t, "health.socket_uid", uid)
			var stdout bytes.Buffer
			doctor(context.Background(), tr.config, &stdout, io.Discard)
			out := stdout.String()
			if line := reportLine(out, "health.socket"); !strings.HasPrefix(line, "ok ") ||
				!strings.Contains(line, "the whole /healthz on "+path+", to uid "+strconv.Itoa(os.Geteuid())+" and uid "+uid+", socket mode 0666") {
				t.Errorf("doctor's health.socket line is %q", line)
			}
			if tc.want == "" {
				if strings.Contains(out, "warning: health.socket") {
					t.Errorf("doctor warns of a directory any account may search:\n%s", out)
				}
				return
			}
			want := strings.NewReplacer("%s", resolved, "%g", groupOf(t, resolved)).Replace(tc.want)
			if !strings.Contains(out, want+"\n") {
				t.Errorf("doctor does not say %q:\n%s", want, out)
			}
		})
	}
}

// TestDoctorSaysTheHealthSocketAnswersThePlaneAlone: without
// health.socket_uid the line names the plane's account alone and warns of
// nothing, whatever the directory's mode; a directory a start refuses fails.
func TestDoctorSaysTheHealthSocketAnswersThePlaneAlone(t *testing.T) {
	path, _ := searchableSocketPath(t, 0o700)
	tr := newTree(t)
	setEnv(t, "health.socket", path)
	var stdout bytes.Buffer
	doctor(context.Background(), tr.config, &stdout, io.Discard)
	out := stdout.String()
	if line := reportLine(out, "health.socket"); !strings.HasPrefix(line, "ok ") ||
		!strings.HasSuffix(line, "the whole /healthz on "+path+", to uid "+strconv.Itoa(os.Geteuid())+", socket mode 0600") ||
		strings.Contains(out, "warning: health.socket") {
		t.Errorf("doctor over a socket of the plane alone:\n%s", out)
	}
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // G302: a directory every account may search
		t.Fatal(err)
	}
	stdout.Reset()
	doctor(context.Background(), tr.config, &stdout, io.Discard)
	if line := reportLine(stdout.String(), "health.socket"); !strings.HasPrefix(line, "fail ") || !strings.Contains(line, "with mode 0700 or narrower") {
		t.Errorf("doctor over a directory others may enter: %q", line)
	}
}

// groupOf is the group that owns path, which the platform picks for a new
// directory: the creator's on Linux, the parent's on Darwin.
func groupOf(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s names no group", path)
	}
	return strconv.FormatUint(uint64(st.Gid), 10)
}
