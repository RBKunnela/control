//go:build unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/scenario"
)

// pageClient speaks to the page dev started as its script does, under the
// session its printed token was traded for. The paths and the header are
// spelled here, not taken from the page's code.
type pageClient struct {
	base, session string
}

func (c *pageClient) do(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Console-Token", token)
	req.Header.Set("Origin", c.base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(out)
}

// tradePage trades the token on the page line dev printed for a session.
func tradePage(t *testing.T, line string) *pageClient {
	t.Helper()
	base, token, ok := strings.Cut(line, "/#t=")
	if !ok {
		t.Fatalf("the page line %q holds no token", line)
	}
	c := &pageClient{base: base}
	code, out := c.do(t, http.MethodPost, "/api/session", token, `{}`)
	var traded struct {
		Session string `json:"session"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(out), &traded) != nil || traded.Session == "" {
		t.Fatalf("trading the printed token answered %d %q", code, out)
	}
	c.session = traded.Session
	return c
}

func (c *pageClient) post(t *testing.T, path string, body any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return c.do(t, http.MethodPost, path, c.session, string(raw))
}

// pageRecord is what the page lists of one record.
type pageRecord struct {
	ApprovalID   string `json:"approval_id"`
	State        string `json:"state"`
	ActionDigest string `json:"action_digest"`
}

// record is the page's listing of the record approvalID.
func (c *pageClient) record(t *testing.T, approvalID string) pageRecord {
	t.Helper()
	code, out := c.do(t, http.MethodGet, "/api/state", c.session, "")
	var state struct {
		Approvals struct {
			Records []pageRecord `json:"records"`
		} `json:"approvals"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(out), &state) != nil {
		t.Fatalf("the page's state answered %d %q", code, out)
	}
	for _, r := range state.Approvals.Records {
		if r.ApprovalID == approvalID {
			return r
		}
	}
	t.Fatalf("the page lists no record %s: %q", approvalID, out)
	return pageRecord{}
}

// approve tries to approve the held call through the page, carrying the
// digest the page lists for its record, which a dev plane's page refuses
// naming the signing command; then signs the approval with that command, the
// dev operator's key and the plane's inbox dev printed.
func (c *pageClient) approve(t *testing.T, held answered, values map[string]string) {
	t.Helper()
	rec := c.record(t, held.approvalID)
	code, out := c.post(t, "/api/approve", map[string]string{"id": held.approvalID, "reason": "", "action_digest": rec.ActionDigest})
	if code != http.StatusConflict || !strings.Contains(out, "approvals approve --key") || !strings.Contains(out, values["inbox"]) {
		t.Fatalf("approving on the page answered %d %q, want a refusal naming the signing command", code, out)
	}
	if code, _, stderr := approvalsCommand(t, "approve", "--key", values["operator_key"], "--inbox", values["inbox"],
		values["approvals"], held.approvalID); code != 0 {
		t.Fatalf("signing the approval: exit %d, %q", code, stderr)
	}
}

// pauseCommand runs the approver's pause command with args and returns its
// exit status, standard output and standard error.
func pauseCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	_, controlBin := builtBinaries(t)
	cmd := exec.Command(controlBin, append([]string{"pause"}, args...)...) //nolint:gosec // G204: the binary this test built
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exited *exec.ExitError
	if err != nil && !errors.As(err, &exited) {
		t.Fatalf("running the pause command: %v", err)
	}
	return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
}

// pauseAll pauses every call with the dev operator's key, after the page,
// which holds no key, refused to; waits for the plane at healthz to read it;
// and returns a function that lifts it the same way and waits again.
func (c *pageClient) pauseAll(t *testing.T, values map[string]string) func() {
	t.Helper()
	r := &runner{plane: planeTarget{healthURL: values["healthz"]}, timeout: 10 * time.Second, http: &http.Client{}}
	code, out := c.post(t, "/api/pause", map[string]any{
		"scope": map[string]string{"kind": "global", "provider": "", "action": "", "name": ""}, "reason": "",
	})
	if code != http.StatusConflict || !strings.Contains(out, "pause add --key") {
		t.Fatalf("the page answered a pause of a signed plane with %d %q, want 409 naming the signing command", code, out)
	}
	sign := []string{"--key", values["operator_key"], "--roster", filepath.Join(values["state"], "trust", "roster.json"),
		"--root-key", filepath.Join(values["state"], "trust", "root.pub")}
	code, id, stderr := pauseCommand(t, slices.Concat([]string{"add", "--global"}, sign, []string{"--", values["pause"]})...)
	id = strings.TrimSpace(id)
	if code != 0 || id == "" {
		t.Fatalf("pausing: exit %d, %q", code, stderr)
	}
	if err := r.pauseRead(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if code, out := c.post(t, "/api/unpause", map[string]string{"id": id}); code != http.StatusConflict {
			t.Fatalf("the page answered a lift of a signed plane with %d %q, want 409", code, out)
		}
		if code, _, stderr := pauseCommand(t, slices.Concat([]string{"remove"}, sign, []string{"--", values["pause"], id})...); code != 0 {
			t.Fatalf("lifting the pause: exit %d, %q", code, stderr)
		}
		if err := r.pauseRead(context.Background(), 0); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAHeldCallAnsweredOnThePage: a call held for an approval is shown on the
// page, which refuses to answer it, and is approved by the command the page
// names, signed with the dev operator's key; with a pause in
// force the retry is blocked and the approval stays unspent; once the pause
// is lifted the retry runs on the held trail and spends it, so the same call
// after it is refused as already used.
func TestAHeldCallAnsweredOnThePage(t *testing.T) {
	t.Parallel()
	_, values, _ := devDemo(t, "5ms")
	page := tradePage(t, values["page"])
	held := callOnce(t, values["mcp"], "update_order", "ord-10")
	if held.kind != scenario.AnswerPending || held.approvalID == "" {
		t.Fatalf("the update answered %+v, want pending", held)
	}
	page.approve(t, held, values)
	lift := page.pauseAll(t, values)
	paused := callOnce(t, values["mcp"], "update_order", "ord-10")
	if paused.kind != scenario.AnswerBlocked || !slices.Equal(paused.codes, []string{"PAUSED"}) {
		t.Fatalf("the retry under the pause answered %+v, want blocked PAUSED", paused)
	}
	if rec := page.record(t, held.approvalID); rec.State != "APPROVAL_STATE_PENDING" {
		t.Fatalf("after the paused retry the record is %+v, want the plane's own pending record", rec)
	}
	lift()
	resumed := callOnce(t, values["mcp"], "update_order", "ord-10")
	if resumed.kind != scenario.AnswerResult || resumed.output != "order updated" || resumed.requestID != held.requestID {
		t.Fatalf("the retry after the lift answered %+v, want the upstream's result on the held trail", resumed)
	}
	used := callOnce(t, values["mcp"], "update_order", "ord-10")
	if used.kind != scenario.AnswerBlocked || !slices.Equal(used.codes, []string{"APPROVAL_ALREADY_USED"}) {
		t.Fatalf("the call after the one that ran answered %+v, want blocked APPROVAL_ALREADY_USED", used)
	}
}
