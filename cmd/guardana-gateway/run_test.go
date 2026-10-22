package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gatewayconfig"
)

// unsignedPublicKey is a well-formed public key line that did not sign the
// fixture bundle. It is not the all-zero key, which the loader refuses as a
// weak key before any signature is checked.
func unsignedPublicKey() string {
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	return base64.StdEncoding.EncodeToString(other.Public().(ed25519.PublicKey))
}

// TestTheCommandSurface is what a shell sees: no argument answers with the
// version, an unknown command and a missing configuration are usage errors, and
// neither serves anything.
func TestTheCommandSurface(t *testing.T) {
	status, stdout := command(t)
	if status != exitOK || !strings.Contains(stdout, brand.Gateway) {
		t.Errorf("no argument answered %d: %q", status, stdout)
	}
	for _, args := range [][]string{
		{"serve"}, {"run"}, {"doctor"}, {"run", "--config"}, {"doctor", "--config", "a", "b"}, {"run", "--mode", "ENFORCE"},
	} {
		if status, _ := command(t, args...); status != exitUsage {
			t.Errorf("%q answered %d, want the usage status %d", args, status, exitUsage)
		}
	}
}

// TestRunRefusesEveryConfigurationASeamRefuses: the plane builds every seam or
// none, so each of these prints what was wrong and starts nothing. The
// refusals belong to the pipeline, the kernel and the spool, and this command's
// job is to carry them to the operator unchanged.
func TestRunRefusesEveryConfigurationASeamRefuses(t *testing.T) {
	for _, c := range []struct {
		name  string
		env   [2]string
		wants string
		// prepare lays out what the case needs beside the variable.
		prepare func(t *testing.T, tr tree)
	}{
		{name: "a mode this build does not enforce", env: [2]string{"mode", "SHADOW"}, wants: "planned"},
		{name: "a mode that records only and is planned", env: [2]string{"mode", "WARN"}, wants: "planned"},
		{name: "no bound on held requests", env: [2]string{"approvals.max_held", "0"}, wants: "held"},
		{name: "no bound on open executions", env: [2]string{"approvals.max_open", "0"}, wants: "open"},
		{name: "no bound on runs", env: [2]string{"flow.max_runs", "0"}, wants: "flow.max_runs"},
		{name: "no approval lifetime", env: [2]string{"approvals.ttl", "0s"}, wants: "lifetime"},
		{name: "no staleness budget", env: [2]string{"policy.max_stale", "0s"}, wants: "stale"},
		{name: "a spool directory that is not there", env: [2]string{"evidence.dir", "nowhere"}, wants: "evidence"},
		{name: "a bundle file that is not there", env: [2]string{"policy.bundle_file", "nowhere.bundle"}, wants: "policy.bundle_file"},
		{name: "a key that did not sign the bundle", env: [2]string{"policy.public_key", unsignedPublicKey()}, wants: "policy.bundle_file: policy: the signature does not verify"},
		{name: "a bundle of another id", env: [2]string{"policy.bundle_id", "another"}, wants: "policy.bundle_file",
			prepare: func(t *testing.T, tr tree) { tr.vouch(t, "another") }},
		{name: "an id the floor directory has no floor for", env: [2]string{"policy.bundle_id", "another"}, wants: "policy.state_dir"},
		{name: "no bound on the requests in flight", env: [2]string{"export.in_flight", "0"}, wants: "otel"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := newTree(t)
			setEnv(t, c.env[0], c.env[1])
			if c.prepare != nil {
				c.prepare(t, tr)
			}
			var stdout, stderr bytes.Buffer
			if status := serve(context.Background(), tr.config, "", &stdout, &stderr); status != exitFail {
				t.Fatalf("run answered %d for %s; it must refuse to start", status, c.name)
			}
			if stdout.Len() != 0 {
				t.Errorf("run wrote to standard output before refusing: %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), c.wants) {
				t.Errorf("the refusal is %q, which does not name %q", stderr.String(), c.wants)
			}
		})
	}
}

// TestRunRefusesABundleThatIsNotOne holds the decoder at the file: a file that
// is not a serialized bundle must not be read as an empty one, which would
// serve no policy at all.
func TestRunRefusesABundleThatIsNotOne(t *testing.T) {
	tr := newTree(t)
	junk := filepath.Join(tr.dir, "junk.bundle")
	if err := os.WriteFile(junk, []byte("this is not a bundle"), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}
	setEnv(t, "policy.bundle_file", junk)
	var stdout, stderr bytes.Buffer
	if status := serve(context.Background(), tr.config, "", &stdout, &stderr); status != exitFail {
		t.Fatalf("run started on a file that is not a bundle (status %d)", status)
	}
	if !strings.Contains(stderr.String(), "policy.bundle_file") {
		t.Errorf("the refusal does not name the key: %q", stderr.String())
	}
}

// TestBuildTakesTheSpoolDirectoryForItself is the lock again, from the side
// that matters at start: a second plane on one directory would interleave its
// records into the first one's segments (ADR-0014).
func TestBuildTakesTheSpoolDirectoryForItself(t *testing.T) {
	tr := newTree(t)
	tr.plane(t)
	var stdout, stderr bytes.Buffer
	if status := serve(context.Background(), tr.config, "", &stdout, &stderr); status != exitFail {
		t.Fatalf("a second plane started on the same spool directory (status %d)", status)
	}
	if !strings.Contains(stderr.String(), "evidence") {
		t.Errorf("the refusal does not name the evidence directory: %q", stderr.String())
	}
}

// TestAFailedBuildLeavesNothingBehind: a refusal after the spool was opened has
// to release the directory, or a second attempt with the configuration fixed
// would be refused by the first attempt's own lock.
func TestAFailedBuildLeavesNothingBehind(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "approvals.max_held", "0")
	var stdout, stderr bytes.Buffer
	if status := serve(context.Background(), tr.config, "", &stdout, &stderr); status != exitFail {
		t.Fatalf("run started with no bound on held requests (status %d)", status)
	}
	os.Unsetenv(brand.Env(gatewayconfig.EnvName("approvals.max_held"))) //nolint:errcheck // the value is restored by t.Setenv either way
	tr.plane(t)
}

// TestRunServesAndStopsWithItsContext is the whole command once: every seam
// built, the upstream connected, the listener and the health answers bound, and
// a clean stop when the process is asked to stop.
func TestRunServesAndStopsWithItsContext(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() { done <- serve(ctx, tr.config, "", &stdout, &stderr) }()

	line := waitFor(t, &stdout, "answering /healthz, /metrics and /brand on ")
	address := strings.TrimSpace(strings.TrimPrefix(line, "answering /healthz, /metrics and /brand on "))
	answer, err := http.Get("http://" + address + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	body, err := io.ReadAll(answer.Body)
	if closeErr := answer.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	if answer.StatusCode != http.StatusOK {
		t.Errorf("a plane that just started answered %d: %s", answer.StatusCode, body)
	}
	if !strings.Contains(string(body), `"mode":"OBSERVE"`) {
		t.Errorf("the answer does not name the mode: %s", body)
	}

	cancel()
	if status := <-done; status != exitOK {
		t.Errorf("run answered %d after its context ended; stderr: %s", status, stderr.String())
	}
}

// TestAPlaintextCollectorNeedsTheKey: over plaintext anyone on the path can
// forge the collector's acceptance, which releases the evidence, so a build
// with an http endpoint and export.allow_plaintext false is refused, and the
// refusal names the key the operator has to set.
func TestAPlaintextCollectorNeedsTheKey(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "export.allow_plaintext", "false")
	var stdout, stderr bytes.Buffer
	if status := serve(context.Background(), tr.config, "", &stdout, &stderr); status != exitFail {
		t.Fatalf("a plaintext collector was accepted with no key (status %d)", status)
	}
	if !strings.Contains(stderr.String(), "plaintext") {
		t.Errorf("the refusal does not name what is wrong: %q", stderr.String())
	}
	// The fixture sets the key, so the same build goes through.
	os.Unsetenv(brand.Env(gatewayconfig.EnvName("export.allow_plaintext"))) //nolint:errcheck // the value is restored by t.Setenv either way
	tr.plane(t)
}
