package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/approvals/inbox"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// signedDecision is the signed answer's word for state.
func signedDecision(state controlv1.ApprovalState) string {
	if state == controlv1.ApprovalState_APPROVAL_STATE_APPROVED {
		return approvals.DecisionApprove
	}
	return approvals.DecisionReject
}

// signAnswer signs one answer with the operator key at ans.key and files it
// in ans.inbox. Every member of the answer but the decision, the reason and
// the time is read from the plane's record of the hold in dir, which this
// command only reads: nothing the operator types names what is signed. A key
// file another account may read or write is refused, and an answer file of
// the same name is never replaced.
func signAnswer(command, decision string, ans answer, dir, id string, stdout, stderr io.Writer) int {
	key, err := policykey.ReadPrivate(ans.key)
	if err != nil {
		return fail(stderr, command, fmt.Errorf("--key: %w", err))
	}
	defer clear(key)
	a, raw, planeAccount, err := signedFromRecord(dir, id, decision, ans.reason, key, time.Now())
	if err != nil {
		return failHinted(stderr, command, err)
	}
	if planeAccount {
		writeLine(stderr, brand.CLI+": "+command+": this account owns the approvals directory, which is the plane's account: "+
			"an answer it signs separates nothing, since the plane's account can then sign as this operator; sign from an operator's own account")
	}
	name, err := inbox.AnswerFileName(a.ApprovalID, approvals.AnswerLabel(a))
	if err != nil {
		return fail(stderr, command, err)
	}
	if err := fileInInbox(ans.inbox, name, raw); err != nil {
		return failHinted(stderr, command, fmt.Errorf("--inbox %s: %w", oneLine(ans.inbox), err))
	}
	lines := "approval " + oneLine(a.ApprovalID) + ": " + a.Decision + " signed by key " + a.KeyID + "\n" +
		"  action digest  " + a.ActionDigest + "\n" +
		"  tenant         " + oneLine(a.Tenant) + "\n" +
		"  project        " + oneLine(a.Project) + "\n" +
		"  filed          " + oneLine(filepath.Join(ans.inbox, name)) + "\n"
	if _, err := io.WriteString(stdout, lines); err != nil {
		return fail(stderr, command, fmt.Errorf("writing to standard output: %w; the answer was filed", err))
	}
	return exitOK
}

// signedFromRecord reads the plane's record of approvalID from dir and signs
// the answer to it at now. planeAccount reports whether this process owns
// dir, which makes it the plane's account.
func signedFromRecord(dir, approvalID, decision, reason string, key ed25519.PrivateKey, now time.Time) (a approvals.Answer, raw []byte, planeAccount bool, err error) {
	r, err := approvals.OpenReader(dir)
	if err != nil {
		return approvals.Answer{}, nil, false, err
	}
	planeAccount = r.PlaneAccount()
	rec, err := r.Held(context.Background(), approvalID)
	if err = errors.Join(err, r.Close()); err != nil {
		return approvals.Answer{}, nil, false, err
	}
	if a, err = approvals.AnswerFor(rec, decision, reason, now, policykey.KeyID(publicHalf(key))); err != nil {
		return approvals.Answer{}, nil, false, err
	}
	raw, err = signedAnswerFile(a, key)
	return a, raw, planeAccount, err
}

// signedAnswerFile signs a with key under the operator answer payload type
// and returns the answer file's bytes.
func signedAnswerFile(a approvals.Answer, key ed25519.PrivateKey) ([]byte, error) {
	body, err := approvals.MarshalAnswer(a)
	if err != nil {
		return nil, err
	}
	sig, err := bundle.SignBytesAs(operators.AnswerPayloadType, body, key)
	if err != nil {
		return nil, err
	}
	return inbox.MarshalAnswerFile(policy.StatementEnvelope{
		PayloadType: operators.AnswerPayloadType, Payload: body,
		Signatures: []policy.StatementSignature{{KeyID: a.KeyID, Signature: sig}},
	})
}

// fileInInbox files raw under name in the inbox at dir. A name taken already
// is refused naming the account that owns that file, which need not be this
// operator: any account that may write the inbox can take a name.
func fileInInbox(dir, name string, raw []byte) error {
	in, err := inbox.OpenInbox(dir)
	if err != nil {
		return err
	}
	err = errors.Join(in.File(name, raw), in.Close())
	if errors.Is(err, approvals.ErrAnswerFiled) {
		return fmt.Errorf("%w: %s is %s", err, name, ownerText(filepath.Join(dir, name)))
	}
	return err
}

// failHinted is fail with what an operator can do about the refusal.
func failHinted(stderr io.Writer, command string, err error) int {
	if hint := answerHint(err); hint != "" {
		return fail(stderr, command, fmt.Errorf("%w; %s", err, hint))
	}
	return fail(stderr, command, err)
}

func publicHalf(key ed25519.PrivateKey) ed25519.PublicKey {
	pub, _ := key.Public().(ed25519.PublicKey)
	return pub
}
