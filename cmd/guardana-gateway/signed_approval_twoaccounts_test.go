//go:build twoaccounts && unix

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/approvals/inbox"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// answerArg is what the file-answer role reads: the plane's approvals
// directory, the inbox and the approval to answer.
type answerArg struct {
	Dir, Inbox, ApprovalID string
}

// TestAnOperatorsAnswerFiledFromItsOwnAccountRunsThePlanesHeldCall lays the
// approvals out as the operators' guide does: the plane's approvals
// directory in the operators' group, mode 2750, and its inbox in that group,
// mode 1770. Root is the plane, holding a call, so the plane's own reads run
// past file modes. A third account outside the group fails to read the hold,
// and the retry stays held; the operator, as its own account, reads the 0640
// hold, files alice's answer, and the plane's retry runs. The operator's
// steps repeat what approvals approve does rather than run that command.
func TestAnOperatorsAnswerFiledFromItsOwnAccountRunsThePlanesHeldCall(t *testing.T) {
	operator, third := twoAccounts(t)
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	writeBundle(t, filepath.Join(tr.dir, "holding.bundle"), holdingDocument)
	writeStatement(t, filepath.Join(tr.dir, "policy.statement"), filepath.Join(tr.dir, "holding.bundle"), time.Now().Truncate(time.Second))
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(strings.Replace(string(raw), "mode: OBSERVE", "mode: ENFORCE", 1), "bundle_file: policy.bundle", "bundle_file: holding.bundle", 1)
	writeTestFile(t, tr.config, []byte(doc))
	dir, box := filepath.Join(tr.dir, recordsDir), filepath.Join(tr.dir, "inbox")
	openToEveryAccount(t, tr.dir)
	ofGroup := account{gid: operator.gid}
	chownTo(t, dir, ofGroup)
	setMode(t, dir, 0o750|os.ModeSetgid)
	chownTo(t, box, ofGroup)
	setMode(t, box, 0o770|os.ModeSticky)
	placedApart(t)
	p, err := buildSigned(t, tr)
	if err != nil {
		t.Fatal(err)
	}

	held := admitTransfer(t, p, "req-hold-1")
	if held.Action != core.AwaitApproval {
		t.Fatalf("the first call is %v, want a hold", held.Action)
	}
	arg, err := json.Marshal(answerArg{Dir: dir, Inbox: box, ApprovalID: held.Pending.ApprovalID})
	if err != nil {
		t.Fatal(err)
	}
	if out, stderr, code := third.as(t, "file-answer", string(arg)); code != 3 || !strings.Contains(stderr, "permission denied") {
		t.Errorf("an account outside the operators' group: exit %d, %q %q; want the hold's directory refused it", code, out, stderr)
	}
	if again := admitTransfer(t, p, "req-hold-2"); again.Action == core.Execute {
		t.Fatal("the retry ran though no operator answered")
	}
	if out, stderr, code := operator.as(t, "file-answer", string(arg)); code != 0 || strings.TrimSpace(out) != "filed" {
		t.Fatalf("the operator's answer as uid %d: exit %d, %q %q", operator.uid, code, out, stderr)
	}
	retry := admitTransfer(t, p, "req-hold-3")
	if retry.Action != core.Execute {
		t.Fatalf("the retry after the operator's answer is %v: %v", retry.Action, retry.Decision.GetReasonCodes())
	}
	closeExecution(t, p, retry)
}

// fileAnswerAsOperator reads the plane's hold of the approval the JSON
// answerArg raw names, signs alice's approval of it and files it in the
// inbox by the steps approvals approve takes, printing "filed".
func fileAnswerAsOperator(raw string) int {
	var a answerArg
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	r, err := approvals.OpenReader(a.Dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		return 3
	}
	rec, err := r.Held(context.Background(), a.ApprovalID)
	if err = errors.Join(err, r.Close()); err != nil {
		fmt.Fprintf(os.Stderr, "held: %v\n", err)
		return 3
	}
	key := signedTestKey("alice")
	ans, err := approvals.AnswerFor(rec, approvals.DecisionApprove, "", time.Now(), policykey.KeyID(signedTestPublic("alice")))
	if err != nil {
		fmt.Fprintf(os.Stderr, "answer: %v\n", err)
		return 2
	}
	body, err := approvals.MarshalAnswer(ans)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	sig, err := bundle.SignBytesAs(operators.AnswerPayloadType, body, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	file, err := inbox.MarshalAnswerFile(policy.StatementEnvelope{
		PayloadType: operators.AnswerPayloadType, Payload: body,
		Signatures: []policy.StatementSignature{{KeyID: ans.KeyID, Signature: sig}},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	name, err := inbox.AnswerFileName(ans.ApprovalID, approvals.AnswerLabel(ans))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	in, err := inbox.OpenInbox(a.Inbox)
	if err != nil {
		fmt.Fprintf(os.Stderr, "inbox: %v\n", err)
		return 3
	}
	if err := errors.Join(in.File(name, file), in.Close()); err != nil {
		fmt.Fprintf(os.Stderr, "file: %v\n", err)
		return 3
	}
	return tellParent("filed")
}
