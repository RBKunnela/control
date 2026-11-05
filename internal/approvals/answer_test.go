package approvals_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
)

const (
	answerAction = "sha256:abababababababababababababababababababababababababababababababab"
	answerBundle = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

func sampleAnswer() approvals.Answer {
	return approvals.Answer{
		Alg: "ed25519", KeyID: "key-1", Tenant: "acme", Project: "orders", RequestID: "req-1",
		ApprovalID: "APPROVAL1", ActionDigest: answerAction, BundleDigest: answerBundle,
		Decision: approvals.DecisionApprove, DecidedAt: time.Date(2026, 3, 1, 12, 1, 0, 500, time.UTC), Reason: "checked",
	}
}

// sampleBody is the canonical body of sampleAnswer, spelled out so the reader
// is held to the bytes and not to what MarshalAnswer writes.
const sampleBody = `{"actionDigest":"` + answerAction + `","alg":"ed25519","approvalId":"APPROVAL1",` +
	`"bundleDigest":"` + answerBundle + `","decidedAt":"2026-03-01T12:01:00.0000005Z","decision":"approve",` +
	`"keyId":"key-1","kind":"approval-answer/v1alpha1","project":"orders","reason":"checked","requestId":"req-1","tenant":"acme"}`

func TestAnAnswerReadsBackAsItWasWritten(t *testing.T) {
	body, err := approvals.MarshalAnswer(sampleAnswer())
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != sampleBody {
		t.Fatalf("the body is\n%s\nwant\n%s", body, sampleBody)
	}
	got, err := approvals.ReadAnswer([]byte(sampleBody))
	if err != nil {
		t.Fatal(err)
	}
	if got != sampleAnswer() {
		t.Fatalf("read %+v, want %+v", got, sampleAnswer())
	}
}

// TestTheAnswerReaderIsStrict: each body differs from the sample in one way,
// and each is refused.
func TestTheAnswerReaderIsStrict(t *testing.T) {
	swap := func(old, repl string) string {
		if !strings.Contains(sampleBody, old) {
			t.Fatalf("the sample holds no %q", old)
		}
		return strings.Replace(sampleBody, old, repl, 1)
	}
	for name, body := range map[string]string{
		"not canonical":                " " + sampleBody,
		"an unknown member":            swap(`"tenant":"acme"}`, `"tenant":"acme","tenants":"x"}`),
		"a member missing":             swap(`"reason":"checked",`, ``),
		"a member not a string":        swap(`"reason":"checked"`, `"reason":1`),
		"another kind":                 swap(`approval-answer/v1alpha1`, `approval-answer/v1alpha2`),
		"another decision":             swap(`"decision":"approve"`, `"decision":"allow"`),
		"a time out of UTC":            swap(`2026-03-01T12:01:00.0000005Z`, `2026-03-01T13:01:00.0000005+01:00`),
		"a time spelled longer":        swap(`2026-03-01T12:01:00.0000005Z`, `2026-03-01T12:01:00.00000050Z`),
		"a digest in upper case":       swap(answerAction, strings.ToUpper(answerAction)),
		"an empty alg":                 swap(`"alg":"ed25519"`, `"alg":""`),
		"an approval id no file takes": swap(`"approvalId":"APPROVAL1"`, `"approvalId":"../x"`),
		"a reason with a line feed":    swap(`"reason":"checked"`, `"reason":"a\nb"`),
		"a body that is no object":     `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := approvals.ReadAnswer([]byte(body)); !errors.Is(err, approvals.ErrAnswerFormat) && !errors.Is(err, approvals.ErrAnswerKind) {
				t.Fatalf("read with %v, want a refusal", err)
			}
		})
	}
}

// TestTheAnswerBoundsBiteOneByteOver: each bound admits its limit and refuses
// one more byte.
func TestTheAnswerBoundsBiteOneByteOver(t *testing.T) {
	for name, set := range map[string]func(*approvals.Answer, int){
		"reason":     func(a *approvals.Answer, n int) { a.Reason = strings.Repeat("r", n) },
		"request id": func(a *approvals.Answer, n int) { a.RequestID = strings.Repeat("q", n) },
		"tenant":     func(a *approvals.Answer, n int) { a.Tenant = strings.Repeat("t", n) },
		"project":    func(a *approvals.Answer, n int) { a.Project = strings.Repeat("p", n) },
	} {
		limit := approvals.MaxAnswerIDBytes
		if name == "reason" {
			limit = approvals.MaxReasonBytes
		}
		t.Run(name, func(t *testing.T) {
			at := sampleAnswer()
			set(&at, limit)
			if _, err := approvals.MarshalAnswer(at); err != nil {
				t.Fatalf("%d bytes refused: %v", limit, err)
			}
			over := sampleAnswer()
			set(&over, limit+1)
			if _, err := approvals.MarshalAnswer(over); !errors.Is(err, approvals.ErrAnswerFormat) {
				t.Fatalf("%d bytes: %v, want ErrAnswerFormat", limit+1, err)
			}
		})
	}
	big := sampleBody[:len(sampleBody)-1] + `,"x":"` + strings.Repeat("x", approvals.MaxAnswerBodyBytes) + `"}`
	if _, err := approvals.ReadAnswer([]byte(big)); !errors.Is(err, approvals.ErrAnswerFormat) || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("a body over the bound: %v", err)
	}
}

func TestAnAnswerWithoutATimeIsNotWritten(t *testing.T) {
	a := sampleAnswer()
	a.DecidedAt = time.Time{}
	if _, err := approvals.MarshalAnswer(a); !errors.Is(err, approvals.ErrAnswerFormat) {
		t.Fatalf("marshalled with %v", err)
	}
}

// FuzzReadAnswer: whatever the reader takes is the one body MarshalAnswer
// writes for it, so no two bodies read as one answer.
func FuzzReadAnswer(f *testing.F) {
	f.Add([]byte(sampleBody))
	f.Add([]byte(`{}`))
	f.Add([]byte(strings.Replace(sampleBody, "approve", "reject", 1)))
	f.Fuzz(func(t *testing.T, body []byte) {
		a, err := approvals.ReadAnswer(body)
		if err != nil {
			return
		}
		again, err := approvals.MarshalAnswer(a)
		if err != nil {
			t.Fatalf("read %q and could not write it back: %v", body, err)
		}
		if string(again) != string(body) {
			t.Fatalf("read %q, wrote %q", body, again)
		}
	})
}
