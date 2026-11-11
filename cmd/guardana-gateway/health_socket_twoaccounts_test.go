//go:build twoaccounts && unix

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestTheHealthSocketAnswersTheNamedAccountAndClosesAThird: a plane run as
// root whose health.socket_uid names the other account binds the socket
// 0666 in its 0755 directory; the other account's connection, its uid read
// by the kernel, gets the whole answer, both runs named, and the third
// account's gets not a byte.
func TestTheHealthSocketAnswersTheNamedAccountAndClosesAThird(t *testing.T) {
	other, third := twoAccounts(t)
	path, _ := searchableSocketPath(t, 0o755)
	p, own, foreign := stoppedRuns(t, path, strconv.FormatUint(uint64(other.uid), 10))
	serveAsBuilt(t, p)
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Type() != os.ModeSocket || info.Mode().Perm() != 0o666 {
		t.Fatalf("the socket is %v, %v; want a socket of mode 0666", info, err)
	}
	if dir, err := os.Lstat(filepath.Dir(path)); err != nil || dir.Mode().Perm() != 0o755 {
		t.Fatalf("the socket's directory is %v, %v; want mode 0755", dir, err)
	}

	answer, stderr, code := other.as(t, "ask", path)
	if code != 0 || !strings.HasPrefix(answer, "HTTP/1.1 200 ") || !strings.Contains(answer, own) || !strings.Contains(answer, foreign) {
		t.Errorf("the named account got exit %d, %q, %q; want 200 naming %s and %s", code, answer, stderr, own, foreign)
	}
	answer, stderr, code = third.as(t, "ask", path)
	if code != 0 || answer != "" {
		t.Errorf("the third account got exit %d, %q, %q; want a connection closed with not a byte", code, answer, stderr)
	}
}

// TestTheHealthSocketOfThePlaneAloneTakesNoOtherConnection: without
// health.socket_uid the socket is 0600, and the kernel refuses the other
// account's connect before the plane sees it, even once that account may
// search the directory.
func TestTheHealthSocketOfThePlaneAloneTakesNoOtherConnection(t *testing.T) {
	other, _ := twoAccounts(t)
	path, _ := searchableSocketPath(t, 0o700)
	p, _, _ := stoppedRuns(t, path, "")
	serveAsBuilt(t, p)
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the socket is %v, %v; want mode 0600", info, err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o711); err != nil { //nolint:gosec // G302: a directory every account may search, so the socket's mode decides
		t.Fatal(err)
	}
	answer, stderr, code := other.as(t, "ask", path)
	if code != 3 || answer != "" || !strings.Contains(stderr, "permission denied") {
		t.Errorf("the other account got exit %d, %q, %q; want its connect refused", code, answer, stderr)
	}
}

// TestADirectoryTheNamedAccountCannotSearchKeepsItOutAndDoctorSaysSo: with
// health.socket_uid and the socket's directory 0700, a start succeeds and
// the named account's connect is refused by the kernel, which is what
// doctor's warning names.
func TestADirectoryTheNamedAccountCannotSearchKeepsItOutAndDoctorSaysSo(t *testing.T) {
	other, _ := twoAccounts(t)
	uid := strconv.FormatUint(uint64(other.uid), 10)
	path, resolved := searchableSocketPath(t, 0o700)
	p, _, _ := stoppedRuns(t, path, uid)
	serveAsBuilt(t, p)
	answer, stderr, code := other.as(t, "ask", path)
	if code != 3 || answer != "" || !strings.Contains(stderr, "permission denied") {
		t.Errorf("the named account got exit %d, %q, %q; want its connect refused", code, answer, stderr)
	}

	tr := newTree(t)
	setEnv(t, "health.socket", filepath.Join(filepath.Dir(path), "doctor.sock"))
	setEnv(t, "health.socket_uid", uid)
	var stdout bytes.Buffer
	doctor(context.Background(), tr.config, &stdout, io.Discard)
	want := "warning: health.socket: health.socket_uid " + uid + " is never answered: it may not search " + resolved + " (mode 0700, owner uid 0)"
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("doctor does not say %q:\n%s", want, stdout.String())
	}
}

// serveAsBuilt serves the health socket p binds with the listener exactly as
// the plane builds it, so the peer is read by the plane's own wiring and a
// test names no account through it.
func serveAsBuilt(t *testing.T, p *plane) {
	t.Helper()
	bound, err := p.bindHealthSocket(io.Discard, nil)
	if err != nil {
		t.Fatalf("binding the health socket: %v", err)
	}
	if len(bound) != 1 {
		t.Fatalf("bound %d listeners, want the socket", len(bound))
	}
	go func() { _ = bound[0].server.Serve(bound[0].listener) }()
	t.Cleanup(func() { _ = bound[0].server.Close() })
}
