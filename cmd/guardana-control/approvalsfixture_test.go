package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
)

// Fixtures for the approvals commands. Every function here builds an input; no
// expected value in any test is read back from one of them.

// fixtureBundle is the policy bundle every fixture binds under, and
// fixtureArgs the argument document the action digest is taken over.
const fixtureBundle approval.BundleDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

var fixtureArgs = []byte(`{"amount_minor":1250}`)

// fixtureIssued is the envelope's own clock. It is fixed, so two envelopes
// built in one test bind to the same digest whatever second they were built
// in; the approval's own times come from the process clock instead, because
// the commands under test compare an answer against an expiry at that clock.
var fixtureIssued = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

// The three strings a listing may never print: the envelope's two free-text
// fields and an approver's own reason. They are distinctive so that a test can
// search the output for them.
const (
	previewText    = "amount-minor-1250-card-4242"
	delegationText = "the caller asked for this on the phone"
	approverReason = "checked with the duty officer first"
)

// clockNow is the process clock at the second, which is the resolution the
// listing prints times at.
func clockNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

// fixtureEnvelope is the held call. It carries both of the contract's
// free-text fields, so a test proves the listing leaves them behind rather
// than assuming it.
func fixtureEnvelope(requestID string) *controlv1.ActionEnvelope {
	return &controlv1.ActionEnvelope{
		SchemaVersion: "1.0",
		RequestId:     requestID,
		ProjectId:     "proj-1",
		TenantId:      "tenant-1",
		Environment:   "prod",
		Principal:     &controlv1.Principal{Id: "user-1", Type: "user", TenantId: "tenant-1"},
		Agent:         &controlv1.Agent{Id: "agent-1", Framework: "cli"},
		Delegation: []*controlv1.Delegation{{
			From:      "user-1",
			To:        "agent-1",
			Scopes:    []string{"refund"},
			Reason:    delegationText,
			IssuedAt:  timestamppb.New(fixtureIssued),
			ExpiresAt: timestamppb.New(fixtureIssued.Add(time.Hour)),
		}},
		Action: &controlv1.Action{
			Kind: "tool.call", Name: "refund", Protocol: "mcp",
			Effect: controlv1.EffectClass_EFFECT_CLASS_TRANSACT, Provider: "payments",
		},
		Resource:  &controlv1.Resource{Type: "payment", Id: "pay-9", TenantId: "tenant-1", Environment: "prod"},
		Arguments: &controlv1.Arguments{RedactedPreview: previewText, RedactionProfile: "default"},
	}
}

func fixtureDecision(requestID string) *controlv1.Decision {
	return &controlv1.Decision{
		SchemaVersion: "1.0",
		DecisionId:    "dec-" + requestID,
		RequestId:     requestID,
		PolicyRuleIds: []string{"rule-a", "rule-b"},
		Verdict:       controlv1.Verdict_VERDICT_REQUIRE_APPROVAL,
	}
}

// requestOf is the request id one approval holds. The two are distinct so that
// a listing printing one in the other's place shows.
func requestOf(approvalID string) string { return "req-" + strings.ToLower(approvalID) }

// digestOf is the action digest the kernel computes for one request's
// envelope: the value the record carries and the listing has to print.
func digestOf(t testing.TB, approvalID string) approval.ActionDigest {
	t.Helper()
	digest, _, err := approval.Bind(fixtureEnvelope(requestOf(approvalID)), fixtureArgs, fixtureBundle)
	if err != nil {
		t.Fatalf("binding the fixture: %v", err)
	}
	return digest
}

// newStore opens a plane over a fresh directory, which makes it an approvals
// store, and holds the lock until the test ends.
func newStore(t *testing.T) (string, *approvals.Plane) {
	t.Helper()
	dir := t.TempDir()
	p, err := approvals.OpenPlane(dir)
	if err != nil {
		t.Fatalf("opening a plane over %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return dir, p
}

// hold records one pending request, expiring at expires.
func hold(t *testing.T, p *approvals.Plane, approvalID string, expires time.Time) {
	t.Helper()
	requestID := requestOf(approvalID)
	env := fixtureEnvelope(requestID)
	digest, binding, err := approval.Bind(env, fixtureArgs, fixtureBundle)
	if err != nil {
		t.Fatalf("binding the fixture: %v", err)
	}
	h := approvals.Hold{
		Approval: &controlv1.Approval{
			SchemaVersion:      "1.0",
			ApprovalId:         approvalID,
			RequestId:          requestID,
			ActionDigest:       string(digest),
			PolicyBundleDigest: string(fixtureBundle),
			State:              controlv1.ApprovalState_APPROVAL_STATE_PENDING,
			RequestedAt:        timestamppb.New(clockNow()),
			ExpiresAt:          timestamppb.New(expires),
		},
		Binding:  binding,
		Envelope: env,
		Decision: fixtureDecision(requestID),
	}
	if err := p.Hold(context.Background(), h, clockNow()); err != nil {
		t.Fatalf("holding %s: %v", approvalID, err)
	}
}

// files reads every file under dir, so a test can prove that a refusal left
// the directory exactly as it found it.
func files(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: the test's own temporary directory
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		out[e.Name()] = string(raw)
	}
	return out
}

// blockOf returns one entry of a listing: the lines from its approval id to
// the blank line that ends it.
func blockOf(t *testing.T, stdout, approvalID string) string {
	t.Helper()
	for _, block := range strings.Split(stdout, "\n\n") {
		if strings.HasPrefix(block, "approval "+approvalID+"\n") {
			return block
		}
	}
	t.Fatalf("the listing holds no entry for %q:\n%s", approvalID, stdout)
	return ""
}

// fieldOf returns the value one entry prints under a label, and fails when
// the label is not there: an absent field is not an empty one.
func fieldOf(t *testing.T, block, label string) string {
	t.Helper()
	for _, line := range strings.Split(block, "\n") {
		if name, value, ok := strings.Cut(strings.TrimSpace(line), "  "); ok && name == label {
			return strings.TrimSpace(value)
		}
	}
	t.Fatalf("no %q in:\n%s", label, block)
	return ""
}

// mustApprove approves one record through the command itself and fails unless
// it was filed. A test that went on to read a state the store never reached
// would examine nothing.
func mustApprove(t *testing.T, dir, approvalID, approverID string) {
	t.Helper()
	code, _, stderr := invoke(t, "approvals", "approve", "--approver-id", approverID, dir, approvalID)
	if code != exitOK {
		t.Fatalf("approvals approve %s: exit %d with %q", approvalID, code, stderr)
	}
}

// The four records everyState builds, one per state an approver can meet.
// What became of an answer after that is the plane's own ledger's, which no
// approver reads.
const (
	waitingID  = "WAITING"  // held, nobody has answered it
	answeredID = "ANSWERED" // an approver said yes
	rejectedID = "REJECTED" // an approver said no
	staleID    = "STALE"    // held, and past its expiry
)

// everyState builds one directory holding a record in each of those states,
// through the plane and the command that reach each one.
func everyState(t *testing.T) (string, *approvals.Plane) {
	t.Helper()
	dir, plane := newStore(t)
	now := clockNow()
	for _, id := range []string{waitingID, answeredID, rejectedID} {
		hold(t, plane, id, now.Add(15*time.Minute))
	}
	hold(t, plane, staleID, now.Add(-time.Minute))
	mustApprove(t, dir, answeredID, "duty-officer")
	if code, _, stderr := invoke(t, "approvals", "reject", "--approver-id", "duty-officer", dir, rejectedID); code != exitOK {
		t.Fatalf("approvals reject %s: exit %d with %q", rejectedID, code, stderr)
	}
	return dir, plane
}

// dirText is every byte under dir, so a test can prove that a value it is
// about to look for in the output did reach a file.
func dirText(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	for _, body := range files(t, dir) {
		b.WriteString(body)
		b.WriteString("\n")
	}
	return b.String()
}

// writeOver replaces one file under dir, as a writer of the directory that is
// not the store would.
func writeOver(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}
