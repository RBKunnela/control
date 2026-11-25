//go:build unix

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDevRefusesAnUpstreamOrDecisionPointOffTheLoopback: a demo whose
// upstream or decision point is an IP literal off the loopback, or a name,
// is refused by the key that names it before dev lays out or binds
// anything. The addresses are documentation ones, never dialled.
func TestDevRefusesAnUpstreamOrDecisionPointOffTheLoopback(t *testing.T) {
	t.Parallel()
	loopbackUpstream := newLiveUpstream(t).url
	for _, c := range []struct {
		name, upstream, extra, key string
	}{
		{"upstream", "http://192.0.2.1:9/mcp", "", "upstreams.0.endpoint"},
		{"upstream by name", "http://orders.example/mcp", "", "upstreams.0.endpoint"},
		{"decision point", loopbackUpstream, "pdp:\n  identifier: https://192.0.2.1:8443/pdp\n", "pdp.identifier"},
		{"evaluation endpoint", loopbackUpstream, "pdp:\n  identifier: https://127.0.0.1:8443/pdp\n  evaluation_endpoint: https://192.0.2.1:8443/pdp/access/v1/evaluation\n", "pdp.evaluation_endpoint"},
		{"decision point proxy", loopbackUpstream, "pdp:\n  identifier: https://127.0.0.1:8443/pdp\n  proxy: http://192.0.2.1:3128\n", "pdp.proxy"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := writeDemo(t, c.upstream, "5ms", c.extra)
			state := filepath.Join(t.TempDir(), "state")
			code, stdout, stderr := runDevToEnd(t, 30*time.Second, "--config", d.config, "--policy", d.policy, "--state", state)
			if code != exitFail || stdout != "" || !strings.Contains(stderr, "dev: "+c.key+": ") || !strings.Contains(stderr, "loopback") {
				t.Fatalf("exit %d, stdout %q, stderr %q; want 1 naming %s and the loopback, and nothing printed", code, stdout, stderr, c.key)
			}
			untouched(t, state)
		})
	}
}

// TestDevRefusesAHealthSocket: a demo naming health.socket, an owner-only
// directory outside --state, is refused by that key before dev lays out or
// binds anything, so no listener answers off the loopback and outside the
// state directory.
func TestDevRefusesAHealthSocket(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "h.sock")
	d := writeDemo(t, newLiveUpstream(t).url, "5ms", "health:\n  socket: "+socket+"\n")
	state := filepath.Join(t.TempDir(), "state")
	code, stdout, stderr := runDevToEnd(t, 30*time.Second, "--config", d.config, "--policy", d.policy, "--state", state)
	if _, err := os.Lstat(socket); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("dev bound the health socket %s: %v", socket, err)
	}
	if code != exitFail || stdout != "" || !strings.Contains(stderr, "dev: health.socket: ") {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 1 naming health.socket, and nothing printed", code, stdout, stderr)
	}
	untouched(t, state)
}
