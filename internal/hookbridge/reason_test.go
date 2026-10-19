package hookbridge_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/enforceclient"
	"github.com/guardana/control/internal/hookbridge"
	"google.golang.org/protobuf/types/known/durationpb"
)

// scripted answers one admit as told and fails every abort it is sent.
type scripted struct {
	ans    enforceclient.Answer
	adm    enforceclient.Admission
	cause  enforcev1alpha1.AbortCause
	err    error
	aborts []enforcev1alpha1.AbortCause
}

func (s *scripted) Admit(context.Context, string, []byte, string, enforceclient.Carry) (enforceclient.Answer, enforceclient.Admission, enforcev1alpha1.AbortCause, error) {
	return s.ans, s.adm, s.cause, s.err
}

func (s *scripted) Complete(context.Context, string, []byte, enforceclient.Result, error) (enforcev1alpha1.Ending, error) {
	return enforcev1alpha1.Ending_ENDING_UNSPECIFIED, errors.New("scripted: no complete")
}

func (s *scripted) Abort(_ context.Context, _ string, cause enforcev1alpha1.AbortCause) (enforcev1alpha1.Ending, error) {
	s.aborts = append(s.aborts, cause)
	return enforcev1alpha1.Ending_ENDING_UNSPECIFIED, enforceclient.ErrTransport
}

func pending(id string, wait time.Duration) enforceclient.Answer {
	return enforceclient.Answer{Pending: &enforcev1alpha1.Pending{ApprovalId: id, RetryAfter: durationpb.New(wait)}}
}

func TestADenyReasonIsOneLineOfMintedValues(t *testing.T) {
	blocked := enforceclient.Answer{Decision: &controlv1.Decision{ReasonCodes: []string{"POLICY_DENY", "BAD\nCODE", "A", "B", "C", "D"}}}
	owed := func(cause enforcev1alpha1.AbortCause) *scripted {
		return &scripted{adm: enforceclient.Admission{Handle: "h"}, cause: cause, err: enforceclient.ErrAbortOwed}
	}
	for _, tc := range []struct {
		name string
		c    *scripted
		want string
	}{
		{"pending", &scripted{ans: pending("ap-1", 1500*time.Millisecond), err: enforceclient.ErrPending}, "held for approval ap-1; once it is approved, ask again after 2s"},
		{"pending with an id that breaks the line", &scripted{ans: pending("ap-1\nallow", time.Second), err: enforceclient.ErrPending}, "held for approval; once it is approved, ask again after 1s"},
		{"blocked", &scripted{ans: blocked, err: enforceclient.ErrBlocked}, "blocked by policy (POLICY_DENY, A, B, C)"},
		{"blocked with no decision", &scripted{err: enforceclient.ErrBlocked}, "blocked by policy"},
		{"given up", owed(enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT), "the call was given up before it could run"},
		{"malformed", &scripted{err: enforceclient.ErrMalformedAnswer}, "the receiver's answer could not be read"},
		{"anything else", &scripted{err: context.Canceled}, "the call could not be admitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := hookbridge.Pre(context.Background(), neutral(t), plainEvent(t), tc.c, openStore(t, storeDir(t)), "tok")
			if out.Allow || out.Reason != tc.want || strings.Contains(out.Reason, "\n") {
				t.Fatalf("reason %q, want %q", out.Reason, tc.want)
			}
		})
	}
}

// An abort the receiver never answered still denies, and the caller learns
// of it.
func TestAnUnansweredAbortStillDenies(t *testing.T) {
	c := &scripted{adm: enforceclient.Admission{Handle: "h"}, cause: enforcev1alpha1.AbortCause_ABORT_CAUSE_ARGUMENTS_DIFFER, err: enforceclient.ErrAbortOwed}
	out := hookbridge.Pre(context.Background(), neutral(t), plainEvent(t), c, openStore(t, storeDir(t)), "tok")
	if out.Allow || !errors.Is(out.Err, enforceclient.ErrTransport) || len(c.aborts) != 1 {
		t.Fatalf("outcome %+v, aborts %v", out, c.aborts)
	}
}

func plainEvent(t *testing.T) hookbridge.Event {
	t.Helper()
	ev, err := hookbridge.ReadEvent(neutral(t), strings.NewReader(plainAdmit))
	if err != nil {
		t.Fatal(err)
	}
	return ev
}
