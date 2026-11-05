//go:build unix

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/approvals/inbox"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// signedHoldingPlane is a signed plane in ENFORCE that holds every transfer,
// over a roster in which alice operates acme/orders, configured in its file
// alone.
func signedHoldingPlane(t *testing.T) (tree, *plane) {
	t.Helper()
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	writeBundle(t, filepath.Join(tr.dir, "holding.bundle"), holdingDocument)
	writeStatement(t, filepath.Join(tr.dir, "policy.statement"), filepath.Join(tr.dir, "holding.bundle"), time.Now().Truncate(time.Second))
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(strings.Replace(string(raw), "mode: OBSERVE", "mode: ENFORCE", 1), "bundle_file: policy.bundle", "bundle_file: holding.bundle", 1)
	writeTestFile(t, tr.config, []byte(doc))
	placedApart(t)
	p, err := buildSigned(t, tr)
	if err != nil {
		t.Fatal(err)
	}
	return tr, p
}

// fileAnswer writes alice's approval of the held call into the inbox under
// label, as an operator's command would.
func fileAnswer(t *testing.T, tr tree, held gateway.Disposition, label string) {
	t.Helper()
	body, err := approvals.MarshalAnswer(approvals.Answer{
		Alg: "ed25519", KeyID: policykey.KeyID(signedTestPublic("alice")), Tenant: "acme", Project: "orders",
		RequestID: "req-hold-1", ApprovalID: held.Pending.ApprovalID, ActionDigest: held.Pending.ActionDigest,
		BundleDigest: held.Decision.GetPolicyBundleDigest(), Decision: approvals.DecisionApprove, DecidedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(operators.AnswerPayloadType, body, signedTestKey("alice"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := inbox.MarshalAnswerFile(policy.StatementEnvelope{PayloadType: operators.AnswerPayloadType, Payload: body,
		Signatures: []policy.StatementSignature{{KeyID: policykey.KeyID(signedTestPublic("alice")), Signature: sig}}})
	if err != nil {
		t.Fatal(err)
	}
	name, err := inbox.AnswerFileName(held.Pending.ApprovalID, label)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(tr.dir, "inbox", name), raw)
}

// TestASignedPlaneReadsItsInbox: alice's one answer in the inbox runs the
// held call; seventeen of them for one approval are a batch past its bound
// and keep the call INDETERMINATE with the hold standing; an inbox that can
// no longer be read, and a file named for the approval that is no answer, do
// the same.
func TestASignedPlaneReadsItsInbox(t *testing.T) {
	for _, c := range []struct {
		name  string
		files int
		spoil func(tr tree)
		runs  bool
	}{
		{"one answer", 1, nil, true},
		{"seventeen answers", inbox.MaxAnswersPerApproval + 1, nil, false},
		{"an inbox others may write", 1, func(tr tree) {
			_ = os.Chmod(filepath.Join(tr.dir, "inbox"), 0o770) //nolint:gosec // G302: the mode under test is one the inbox refuses
		}, false},
		{"a file for the approval it cannot read", 1, func(tr tree) {
			entries, _ := os.ReadDir(filepath.Join(tr.dir, "inbox"))
			for _, e := range entries {
				id, _, _ := strings.Cut(e.Name(), ".")
				_ = os.WriteFile(filepath.Join(tr.dir, "inbox", id+".junk.answer"), []byte("junk"), 0o600)
			}
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr, p := signedHoldingPlane(t)
			held := admitTransfer(t, p, "req-hold-1")
			if held.Action != core.AwaitApproval {
				t.Fatalf("the first call is %v, want a hold", held.Action)
			}
			for i := range c.files {
				fileAnswer(t, tr, held, fmt.Sprintf("alice%02d", i))
			}
			if c.spoil != nil {
				c.spoil(tr)
			}
			retry := admitTransfer(t, p, "req-hold-2")
			if c.runs {
				if retry.Action != core.Execute {
					t.Fatalf("the retry is %v: %v", retry.Action, retry.Decision.GetReasonCodes())
				}
				closeExecution(t, p, retry)
				return
			}
			if retry.Action != core.Block || retry.Decision.GetVerdict().String() != "VERDICT_INDETERMINATE" {
				t.Fatalf("the retry is %v %s %v; want INDETERMINATE", retry.Action, retry.Decision.GetVerdict(), retry.Decision.GetReasonCodes())
			}
			if again := admitTransfer(t, p, "req-hold-3"); again.Action == core.Execute {
				t.Fatal("a later retry ran the call")
			}
		})
	}
}

// TestTheInboxPruneKeepsWhatAHoldStillNeeds: the prune leaves an answer to a
// hold the approvals directory still keeps, and removes one to an approval
// it no longer keeps once a lifetime has passed.
func TestTheInboxPruneKeepsWhatAHoldStillNeeds(t *testing.T) {
	tr, p := signedHoldingPlane(t)
	held := admitTransfer(t, p, "req-hold-1")
	fileAnswer(t, tr, held, "alice")
	gone := held
	gone.Pending = &gateway.Pending{ApprovalID: "GONE1", ActionDigest: held.Pending.ActionDigest}
	fileAnswer(t, tr, gone, "alice")
	got, err := p.pruneInbox(context.Background(), time.Now().Add(p.cfg.Approvals.TTL+time.Minute))
	if err != nil || got != (inbox.Pruned{Removed: 1}) {
		t.Fatalf("pruneInbox = %+v, %v; want the answer to GONE1 removed alone", got, err)
	}
	if _, err := os.Stat(filepath.Join(tr.dir, "inbox", held.Pending.ApprovalID+".alice.answer")); err != nil {
		t.Errorf("the held call's answer is gone: %v", err)
	}
}

// TestTheServingSweepPrunesTheInbox: the sweep a serving plane runs removes an
// answer to an approval it no longer holds once a lifetime has passed, and
// counts it on the health page.
func TestTheServingSweepPrunesTheInbox(t *testing.T) {
	tr, p := signedHoldingPlane(t)
	held := admitTransfer(t, p, "req-hold-1")
	gone := held
	gone.Pending = &gateway.Pending{ApprovalID: "GONE1", ActionDigest: held.Pending.ActionDigest}
	fileAnswer(t, tr, gone, "alice")
	p.sweepStores(context.Background(), time.Now().Add(p.cfg.Approvals.TTL+time.Minute))
	if _, err := os.Stat(filepath.Join(tr.dir, "inbox", "GONE1.alice.answer")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the answer to GONE1 is still there: %v", err)
	}
	got := p.sweeps.counters()
	if got["answers_forgotten"] != uint64(1) || got["answers_failed"] != uint64(0) || got["answers_refused"] != uint64(0) {
		t.Errorf("sweep counters = %v; want one answer forgotten, none failed or refused", got)
	}
}
