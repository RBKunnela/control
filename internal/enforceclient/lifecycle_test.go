package enforceclient_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/enforceclient"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	argumentsDiffer = enforcev1alpha1.AbortCause_ABORT_CAUSE_ARGUMENTS_DIFFER
	noCause         = enforcev1alpha1.AbortCause_ABORT_CAUSE_UNSPECIFIED
)

func TestExactOnlyRefusesARewrittenExecute(t *testing.T) {
	for _, tc := range []struct {
		name     string
		proposed string
		carry    enforceclient.Carry
	}{
		{"another value", `{"a":2}`, enforceclient.CarryExactOnly},
		{"the same value spelled with a space", `{"a": 1}`, enforceclient.CarryExactOnly},
		{"bytes authorized for a call that proposed none", ``, enforceclient.CarryExactOnly},
		{"a carry this client does not declare", `{"a":2}`, enforceclient.Carry(7)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r := scriptedClient(t, answer(enforceclient.PathAdmit, 200, execute))
			ans, adm, cause, err := c.Admit(context.Background(), "t", []byte(tc.proposed), "", tc.carry)
			if !errors.Is(err, enforceclient.ErrAbortOwed) || cause != argumentsDiffer {
				t.Fatalf("Admit = %v, cause %s; want ErrAbortOwed with ARGUMENTS_DIFFER", err, cause)
			}
			if adm.Authorized != nil || adm.Handle != "h-1" || ans.Outcome != enforcev1alpha1.Outcome_OUTCOME_EXECUTE {
				t.Fatalf("admission %+v, outcome %s; want only the handle h-1 to abort", adm, ans.Outcome)
			}
			if got := r.requests(); len(got) != 1 {
				t.Fatalf("%d requests, want the admit alone", len(got))
			}
		})
	}
}

func TestCarryAuthorizedTakesTheRewrite(t *testing.T) {
	c, _ := scriptedClient(t, answer(enforceclient.PathAdmit, 200, execute))
	_, adm, cause, err := c.Admit(context.Background(), "t", []byte(`{"a":2}`), "", enforceclient.CarryAuthorized)
	if err != nil || cause != noCause || string(adm.Authorized) != `{"a":1}` {
		t.Fatalf("Admit = %+v, cause %s, %v; want the authorized bytes", adm, cause, err)
	}
}

func TestExactOnlyHandsOutAnUnchangedExecute(t *testing.T) {
	c, _ := scriptedClient(t, answer(enforceclient.PathAdmit, 200,
		`{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-2","expiresAt":"2026-10-18T12:00:00Z","authorizedArguments":"eyJhIjoxfQ=="}}`))
	ans, adm, cause, err := c.Admit(context.Background(), "t", []byte(`{"a":1}`), "", enforceclient.CarryExactOnly)
	if err != nil || cause != noCause || ans.Outcome != enforcev1alpha1.Outcome_OUTCOME_EXECUTE {
		t.Fatalf("Admit = %v, cause %s, outcome %s; want a runnable EXECUTE", err, cause, ans.Outcome)
	}
	want := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	if adm.Handle != "h-2" || string(adm.Authorized) != `{"a":1}` || !adm.ExpiresAt.Equal(want) {
		t.Fatalf("admission %+v", adm)
	}

	c, _ = scriptedClient(t, answer(enforceclient.PathAdmit, 200, `{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-3"}}`))
	if _, adm, _, err := c.Admit(context.Background(), "t", nil, "", enforceclient.CarryExactOnly); err != nil || adm.Handle != "h-3" || !adm.ExpiresAt.IsZero() {
		t.Fatalf("no bytes proposed, none authorized: %+v, %v", adm, err)
	}
}

// An owed abort hands back the handle and its expiry, the two things a
// caller needs to abort it, and never the authorized bytes.
func TestAnOwedAbortKeepsTheHandleAndItsExpiry(t *testing.T) {
	c, _ := scriptedClient(t, answer(enforceclient.PathAdmit, 200,
		`{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-4","expiresAt":"2026-10-18T12:00:00Z","authorizedArguments":"eyJhIjoxfQ=="}}`))
	_, adm, cause, err := c.Admit(context.Background(), "t", []byte(`{"a":2}`), "", enforceclient.CarryExactOnly)
	want := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	if !errors.Is(err, enforceclient.ErrAbortOwed) || cause != argumentsDiffer || adm.Handle != "h-4" || !adm.ExpiresAt.Equal(want) || adm.Authorized != nil {
		t.Fatalf("Admit = %+v, cause %s, %v", adm, cause, err)
	}
}

func TestAdmitSendsNoAbortOnAnyPath(t *testing.T) {
	const obligated = `{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-1","authorizedArguments":"eyJhIjoxfQ==","obligations":[{"type":"x"}]}}`
	for _, tc := range []struct {
		name  string
		first scripted
		carry enforceclient.Carry
		want  error
		cause enforcev1alpha1.AbortCause
	}{
		{"execute", answer(enforceclient.PathAdmit, 200, execute), enforceclient.CarryAuthorized, nil, noCause},
		{"rewrite", answer(enforceclient.PathAdmit, 200, execute), enforceclient.CarryExactOnly, enforceclient.ErrAbortOwed, argumentsDiffer},
		{"obligation", answer(enforceclient.PathAdmit, 200, obligated), enforceclient.CarryAuthorized, enforceclient.ErrAbortOwed, enforcev1alpha1.AbortCause_ABORT_CAUSE_OBLIGATION},
		{"no bytes", answer(enforceclient.PathAdmit, 200, `{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-1"}}`), enforceclient.CarryAuthorized, enforceclient.ErrAbortOwed, argumentsDiffer},
		{"caller gone", scripted{For: enforceclient.PathAdmit, Status: 200, Raw: ptr(execute), Then: "cancel_caller"}, enforceclient.CarryAuthorized, enforceclient.ErrAbortOwed, enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT},
		{"block", answer(enforceclient.PathAdmit, 200, `{"outcome":"OUTCOME_BLOCK","execution":{"handle":"h-1"}}`), enforceclient.CarryAuthorized, enforceclient.ErrBlocked, noCause},
		{"pending", answer(enforceclient.PathAdmit, 200, `{"outcome":"OUTCOME_PENDING"}`), enforceclient.CarryAuthorized, enforceclient.ErrPending, noCause},
		{"refused", answer(enforceclient.PathAdmit, 401, `{"code":"ERROR_CODE_UNAUTHENTICATED"}`), enforceclient.CarryAuthorized, enforceclient.ErrRefused, noCause},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := &receiver{answers: []scripted{tc.first}, cancel: cancel}
			c := client(t, serve(t, r), 5*time.Second)
			_, _, cause, err := c.Admit(ctx, "t", []byte(`{"a":2}`), "", tc.carry)
			if !isOnly(err, tc.want) || cause != tc.cause {
				t.Fatalf("Admit = %v, cause %s; want %v, %s", err, cause, tc.want, tc.cause)
			}
			if got := r.requests(); len(got) != 1 || got[0].path != enforceclient.PathAdmit {
				t.Fatalf("requests %q, want the admit alone", got)
			}
		})
	}
}

func TestAdmitPutsTheKeyInRequestKey(t *testing.T) {
	c, r := scriptedClient(t, answer(enforceclient.PathAdmit, 200, execute), answer(enforceclient.PathAdmit, 200, execute))
	if _, _, _, err := c.Admit(context.Background(), "refund", []byte(`{"a":1}`), "call-7", enforceclient.CarryExactOnly); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.Admit(context.Background(), "refund", []byte(`{"a":1}`), "", enforceclient.CarryExactOnly); err != nil {
		t.Fatal(err)
	}
	got := r.requests()
	var keyed enforcev1alpha1.AdmitRequest
	decodeRequest(t, got[0].body, &keyed)
	if keyed.GetRequestKey() != "call-7" || keyed.GetTool() != "refund" || string(keyed.GetArguments()) != `{"a":1}` {
		t.Fatalf("admit %s, want request_key call-7", got[0].body)
	}
	if strings.Contains(string(got[1].body), "equestKey") || strings.Contains(string(got[1].body), "request_key") {
		t.Fatalf("admit %s carries a request key for no key", got[1].body)
	}
}

func TestCompleteSendsOneCompleteAndReportsTheEnding(t *testing.T) {
	clock := time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		reply   scripted
		toolErr error
		ending  enforcev1alpha1.Ending
		want    error
		status  enforcev1alpha1.CompletionStatus
	}{
		{"recorded", answer(enforceclient.PathComplete, 200, recorded), nil, enforcev1alpha1.Ending_ENDING_RECORDED, nil, enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS},
		{"recorded after a tool error", answer(enforceclient.PathComplete, 200, recorded), errors.New("lost"), enforcev1alpha1.Ending_ENDING_RECORDED, nil, enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_UNKNOWN},
		{"not recorded", answer(enforceclient.PathComplete, 200, `{"ending":"ENDING_UNRECORDED"}`), nil, enforcev1alpha1.Ending_ENDING_UNRECORDED, enforceclient.ErrNotRecorded, enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS},
		{"spent", answer(enforceclient.PathComplete, 409, `{"code":"ERROR_CODE_HANDLE_SPENT","ending":"ENDING_ABANDONED"}`), nil, enforcev1alpha1.Ending_ENDING_ABANDONED, enforceclient.ErrRefused, enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &receiver{answers: []scripted{tc.reply}, cancel: func() {}}
			c, err := enforceclient.New(enforceclient.Config{Socket: serve(t, r), Token: "tok", Timeout: 5 * time.Second, Now: func() time.Time { return clock }})
			if err != nil {
				t.Fatal(err)
			}
			res := enforceclient.Result{Status: enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS, EndedAt: clock.Add(time.Second), ResultHash: "rh"}
			ending, err := c.Complete(context.Background(), "h-9", []byte(`{"b":2}`), res, tc.toolErr)
			if ending != tc.ending || !isOnly(err, tc.want) || tc.toolErr != nil && errors.Is(err, tc.toolErr) {
				t.Fatalf("Complete = %s, %v; want %s, %v", ending, err, tc.ending, tc.want)
			}
			var req enforcev1alpha1.CompleteRequest
			body := onlyRequest(t, r, enforceclient.PathComplete, &req)
			want := &enforcev1alpha1.CompleteRequest{
				Handle: "h-9", SentArguments: []byte(`{"b":2}`), Status: tc.status,
				StartedAt: timestamppb.New(clock), EndedAt: timestamppb.New(clock.Add(time.Second)), ResultHash: "rh",
			}
			if !proto.Equal(&req, want) {
				t.Fatalf("complete %s", body)
			}
		})
	}
}

func TestAbortSendsOneAbortAndReportsTheEnding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reply  scripted
		ending enforcev1alpha1.Ending
		want   error
	}{
		{"recorded", answer(enforceclient.PathAbort, 200, recorded), enforcev1alpha1.Ending_ENDING_RECORDED, nil},
		{"record failed", answer(enforceclient.PathAbort, 200, `{"ending":"ENDING_RECORD_FAILED"}`), enforcev1alpha1.Ending_ENDING_RECORD_FAILED, nil},
		{"unknown handle", answer(enforceclient.PathAbort, 404, `{"code":"ERROR_CODE_HANDLE_UNKNOWN"}`), enforcev1alpha1.Ending_ENDING_UNSPECIFIED, enforceclient.ErrRefused},
		{"spent", answer(enforceclient.PathAbort, 409, `{"code":"ERROR_CODE_HANDLE_SPENT","ending":"ENDING_ABANDONED"}`), enforcev1alpha1.Ending_ENDING_ABANDONED, enforceclient.ErrRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r := scriptedClient(t, tc.reply)
			ending, err := c.Abort(context.Background(), "h-4", enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT)
			if ending != tc.ending || !isOnly(err, tc.want) {
				t.Fatalf("Abort = %s, %v; want %s, %v", ending, err, tc.ending, tc.want)
			}
			var req enforcev1alpha1.AbortRequest
			body := onlyRequest(t, r, enforceclient.PathAbort, &req)
			if req.GetHandle() != "h-4" || req.GetCause() != enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT {
				t.Fatalf("abort %s", body)
			}
		})
	}
}

// isOnly reports whether err is want, and nil only when want is.
func isOnly(err, want error) bool {
	return errors.Is(err, want) && (err == nil) == (want == nil)
}

// onlyRequest decodes into m the one request r received, which must have
// gone to path, and returns its body.
func onlyRequest(t *testing.T, r *receiver, path string, m proto.Message) []byte {
	t.Helper()
	got := r.requests()
	if len(got) != 1 || got[0].path != path {
		t.Fatalf("requests %q, want one to %s", got, path)
	}
	decodeRequest(t, got[0].body, m)
	return got[0].body
}

func decodeRequest(t *testing.T, body []byte, m proto.Message) {
	t.Helper()
	if err := protojson.Unmarshal(body, m); err != nil {
		t.Fatalf("request %s: %v", body, err)
	}
}

func ptr(s string) *string { return &s }
