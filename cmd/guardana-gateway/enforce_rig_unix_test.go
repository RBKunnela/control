//go:build unix

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/runs"
)

// enforceDocument allows reads and notes and denies a transaction.
const enforceDocument = `{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"enforce-fixture","version":"2026-10-11.1","serial":1,"maxStaleSeconds":600},
  "rules":[
    {"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}},
    {"id":"allow-notes","effect":"ALLOW","when":{"action":{"effect":["WRITE"]}}},
    {"id":"deny-refunds","effect":"DENY","when":{"action":{"effect":["TRANSACT"]}}}
  ]}`

// The three tools of the enforcement API plane.
const (
	enforceRead   = "read_order"
	enforceNote   = "write_note"
	enforceRefund = "refund"
)

// enforceTree is an enforcement API plane laid out on disk: its policy, an
// empty spool, a runs directory, and a socket in a directory only this user
// may enter, short enough for every platform's socket path.
type enforceTree struct {
	dir, config, socket, runs string
}

// newEnforceTree lays out the plane in ENFORCE with the given execution
// lifetime, its trail exported to collector, and writes its configuration.
func newEnforceTree(t *testing.T, lifetime, collector string) enforceTree {
	t.Helper()
	dir := t.TempDir()
	sockDir, err := os.MkdirTemp("", "gwe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	tr := enforceTree{dir: dir, config: filepath.Join(dir, "plane.yaml"), socket: filepath.Join(sockDir, "s"), runs: filepath.Join(dir, "runs")}
	for _, sub := range []string{"spool", "runs"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := runs.InitAdmin(context.Background(), tr.runs)
	if err == nil {
		err = admin.Close()
	}
	if err != nil {
		t.Fatalf("making the runs directory: %v", err)
	}
	writeBundle(t, filepath.Join(dir, "policy.bundle"), enforceDocument)
	clearProductEnvironment(t)
	doc := fmt.Sprintf(`mode: ENFORCE
project_id: orders
tenant_id: %s
environment: dev
listener:
  kind: enforce_api
  socket: %s
  execution_lifetime: %s
  principal:
    id: %s
  agent:
    id: %s
health:
  address: 127.0.0.1:0
policy:
  bundle_id: enforce-fixture
  bundle_file: policy.bundle
  key_id: %s
  public_key: %s
%sruns:
  dir: runs
evidence:
  dir: spool
export:
  endpoint: %s
  allow_plaintext: true
  in_flight: 1
  linger: 5ms
tools:
  - name: read_order
    effect: READ
    provider: orders
    resource_type: order
    resource_from: /id
    returns:
      trust: TRUSTED_INTERNAL
      sensitivity: PUBLIC
  - name: write_note
    effect: WRITE
    provider: orders
    resource_type: note
    resource_from: /id
  - name: refund
    effect: TRANSACT
    provider: payments
    resource_type: order
    resource_from: /id
`, runsTenant, tr.socket, lifetime, runsPrincipal, runsAgent, fixtureKeyID, fixturePublicKey(),
		freshnessKeys(t, dir, "enforce-fixture"), collector)
	if err := os.WriteFile(tr.config, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return tr
}

// openRun opens a run for the listener's identity and returns its token.
func (tr enforceTree) openRun(t *testing.T) string {
	t.Helper()
	admin, err := runs.OpenAdmin(context.Background(), tr.runs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	_, token, err := admin.Open(context.Background(), runs.OpenRequest{
		Who: runs.Identity{ProjectID: runsProject, TenantID: runsTenant, PrincipalType: "service", PrincipalID: runsPrincipal, AgentID: runsAgent},
		TTL: time.Hour, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("opening a run: %v", err)
	}
	return token
}

// rawClient speaks the enforcement API with no client rule of its own: it
// sends what it is told and runs whatever it is told to run.
type rawClient struct {
	t      *testing.T
	token  string
	client *http.Client
}

func newRawClient(t *testing.T, socket, token string) *rawClient {
	t.Helper()
	dialer := &net.Dialer{}
	return &rawClient{t: t, token: token, client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
	}}}
}

// post sends one operation and returns the status and the body.
func (c *rawClient) post(path, body string) (int, []byte) {
	c.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://plane"+path, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Run-Token", c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		c.t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp.StatusCode, raw
}

// admit asks for tool with args and decodes the answer.
func (c *rawClient) admit(tool string, args []byte) *enforcev1alpha1.AdmitResponse {
	c.t.Helper()
	body, err := protojson.Marshal(&enforcev1alpha1.AdmitRequest{Tool: tool, Arguments: args})
	if err != nil {
		c.t.Fatal(err)
	}
	status, raw := c.post("/enforce/v1alpha1/admit", string(body))
	resp := &enforcev1alpha1.AdmitResponse{}
	if status != http.StatusOK || protojson.Unmarshal(raw, resp) != nil {
		c.t.Fatalf("admit %s: %d %s", tool, status, raw)
	}
	return resp
}

// complete reports sent as the bytes the execution sent, with success.
func (c *rawClient) complete(handle string, sent []byte) enforcev1alpha1.Ending {
	c.t.Helper()
	body, err := protojson.Marshal(&enforcev1alpha1.CompleteRequest{Handle: handle, SentArguments: sent,
		Status: enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS})
	if err != nil {
		c.t.Fatal(err)
	}
	status, raw := c.post("/enforce/v1alpha1/complete", string(body))
	resp := &enforcev1alpha1.CompleteResponse{}
	if status != http.StatusOK || protojson.Unmarshal(raw, resp) != nil {
		c.t.Fatalf("complete: %d %s", status, raw)
	}
	return resp.GetEnding()
}

// toolFixture is the tool both clients call: it records every argument
// document it was run with.
type toolFixture struct{ ran [][]byte }

func (f *toolFixture) run(args []byte) { f.ran = append(f.ran, bytes.Clone(args)) }
