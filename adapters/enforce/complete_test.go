package enforce_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/guardana/control/adapters/enforce"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

const (
	recorded     = enforcev1alpha1.Ending_ENDING_RECORDED
	recordFailed = enforcev1alpha1.Ending_ENDING_RECORD_FAILED
	unrecorded   = enforcev1alpha1.Ending_ENDING_UNRECORDED
)

func completeBody(handle, sent, status, extra string) string {
	return `{"handle":"` + handle + `","sentArguments":"` + b64(sent) + `","status":"` + status + `"` + extra + `}`
}

// complete posts a complete and returns its ending, failing on anything but a
// 200 answer.
func (r *rig) complete(t *testing.T, token, handle, sent, status string) enforcev1alpha1.Ending {
	t.Helper()
	code, body := r.post(t, token, enforce.PathComplete, completeBody(handle, sent, status, ""))
	if code != http.StatusOK {
		t.Fatalf("complete answered %d: %s", code, body)
	}
	var resp enforcev1alpha1.CompleteResponse
	if err := protojson.Unmarshal(body, &resp); err != nil {
		t.Fatalf("complete answer %q: %v", body, err)
	}
	return resp.GetEnding()
}

func (r *rig) abortWith(t *testing.T, token, handle, cause string) enforcev1alpha1.Ending {
	t.Helper()
	code, body := r.post(t, token, enforce.PathAbort, `{"handle":"`+handle+`","cause":"`+cause+`"}`)
	if code != http.StatusOK {
		t.Fatalf("abort answered %d: %s", code, body)
	}
	var resp enforcev1alpha1.AbortResponse
	if err := protojson.Unmarshal(body, &resp); err != nil {
		t.Fatalf("abort answer %q: %v", body, err)
	}
	return resp.GetEnding()
}

// executed admits tool with args under token and returns the handle, failing
// unless the answer is EXECUTE.
func (r *rig) executed(t *testing.T, token, tool, args string) string {
	t.Helper()
	resp := r.admit(t, token, tool, args, "")
	if resp.GetOutcome() != outcomeExecute {
		t.Fatalf("admit of %s answered %v", tool, resp)
	}
	return resp.GetExecution().GetHandle()
}

// closing is the last closing event the sink kept.
func (r *rig) closing(t *testing.T) *controlv1.Event {
	t.Helper()
	events := r.sink.Events()
	for i := len(events) - 1; i >= 0; i-- {
		if k := events[i].GetKind(); k == kindDone || k == kindFailed {
			return events[i]
		}
	}
	t.Fatalf("no closing in %v", r.kinds())
	return nil
}

const refund = `{"account":"acc-1","amount":5}`

func TestACompleteIsRecordedAsTheClientReportedIt(t *testing.T) {
	r := newRig(t, defaults())
	resp := r.admit(t, runA, "refund", refund, "")
	handle := resp.GetExecution().GetHandle()
	started, ended := base().Add(time.Second), base().Add(3*time.Second)
	code, body := r.post(t, runA, enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS",
		`,"startedAt":"`+started.Format(time.RFC3339)+`","endedAt":"`+ended.Format(time.RFC3339)+
			`","resultHash":"sha256:abc","sideEffectConfirmation":"rcpt-1"`))
	if code != http.StatusOK || !strings.Contains(string(body), "ENDING_RECORDED") {
		t.Fatalf("complete answered %d: %s", code, body)
	}
	e := r.closing(t)
	res := e.GetResult()
	for _, c := range []struct {
		field     string
		got, want any
	}{
		{"kind", e.GetKind(), kindDone},
		{"status", res.GetStatus(), controlv1.ResultStatus_RESULT_STATUS_SUCCESS},
		{"started_at", res.GetStartedAt().AsTime(), started},
		{"ended_at", res.GetEndedAt().AsTime(), ended},
		{"result_hash", res.GetResultHash(), "sha256:abc"},
		{"side_effect_confirmation", res.GetSideEffectConfirmation(), "rcpt-1"},
		{"retryable", res.GetRetryable(), false},
		{"result_schema_valid", res.GetResultSchemaValid(), false},
		{"executed_action_digest", res.GetExecutedActionDigest(), resp.GetDecision().GetActionDigest()},
		{"request_id", res.GetRequestId(), resp.GetDecision().GetRequestId()},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if s := r.a.Stats(); s.Completed != 1 || s.Open != 0 {
		t.Fatalf("stats %+v", s)
	}
}

func TestAnUncertainEffectStaysUncertainAndIsNeverRetryable(t *testing.T) {
	r := newRig(t, defaults())
	for _, tc := range []struct {
		status string
		want   controlv1.ResultStatus
	}{
		{"COMPLETION_STATUS_TIMEOUT", controlv1.ResultStatus_RESULT_STATUS_TIMEOUT},
		{"COMPLETION_STATUS_UNKNOWN", controlv1.ResultStatus_RESULT_STATUS_UNKNOWN},
		{"COMPLETION_STATUS_CANCELLED", controlv1.ResultStatus_RESULT_STATUS_CANCELLED},
		{"COMPLETION_STATUS_FAILURE", controlv1.ResultStatus_RESULT_STATUS_FAILURE},
	} {
		handle := r.executed(t, runA, "refund", refund)
		if ending := r.complete(t, runA, handle, refund, tc.status); ending != recorded {
			t.Fatalf("%s: ending %s", tc.status, ending)
		}
		e := r.closing(t)
		if e.GetKind() != kindFailed || e.GetResult().GetStatus() != tc.want || e.GetResult().GetRetryable() {
			t.Fatalf("%s recorded as %s %s retryable=%v", tc.status, e.GetKind(), e.GetResult().GetStatus(), e.GetResult().GetRetryable())
		}
	}
}

func TestAReportedMismatchHaltsOnlyTheRunThatReportedIt(t *testing.T) {
	r := newRig(t, defaults())
	ha := r.executed(t, runA, "refund", refund)
	hb := r.executed(t, runB, "refund", refund)
	if ending := r.complete(t, runA, ha, `{"account":"acc-1","amount":5000}`, "COMPLETION_STATUS_SUCCESS"); ending != recorded {
		t.Fatalf("the mismatch's record landed and was answered %s", ending)
	}
	e := r.closing(t)
	if e.GetKind() != kindFailed || e.GetResult().GetToolProtocolStatus() != "EXECUTED_ARGS_MISMATCH" {
		t.Fatalf("mismatch recorded as %s %q", e.GetKind(), e.GetResult().GetToolProtocolStatus())
	}
	if resp := r.admit(t, runA, "refund", refund, ""); resp.GetOutcome() != outcomeBlock {
		t.Fatalf("run A's next material call answered %s", resp.GetOutcome())
	}
	if resp := r.admit(t, runA, "read_file", `{"path":"a"}`, ""); resp.GetOutcome() != outcomeExecute {
		t.Fatalf("run A's read answered %s", resp.GetOutcome())
	}
	if ending := r.complete(t, runB, hb, refund, "COMPLETION_STATUS_SUCCESS"); ending != recorded {
		t.Fatalf("run B's complete answered %s", ending)
	}
	if resp := r.admit(t, runB, "refund", refund, ""); resp.GetOutcome() != outcomeExecute {
		t.Fatalf("run B's next material call answered %s", resp.GetOutcome())
	}
}

func TestAnAbortRecordsThatNothingWasSent(t *testing.T) {
	r := newRig(t, defaults())
	for _, tc := range []struct{ cause, code string }{
		{"ABORT_CAUSE_ARGUMENTS_DIFFER", "EXECUTED_ARGS_MISMATCH"},
		{"ABORT_CAUSE_OBLIGATION", "OBLIGATION_NOT_UNDERSTOOD"},
		{"ABORT_CAUSE_NOT_SENT", "EVIDENCE_UNAVAILABLE"},
	} {
		handle := r.executed(t, runA, "refund", refund)
		if ending := r.abortWith(t, runA, handle, tc.cause); ending != recorded {
			t.Fatalf("%s: ending %s", tc.cause, ending)
		}
		res := r.closing(t).GetResult()
		if res.GetStatus() != controlv1.ResultStatus_RESULT_STATUS_BLOCKED || res.GetToolProtocolStatus() != tc.code || res.GetExecutedActionDigest() != "" {
			t.Fatalf("%s recorded as %v", tc.cause, res)
		}
	}
	if resp := r.admit(t, runA, "refund", refund, ""); resp.GetOutcome() != outcomeExecute {
		t.Fatalf("an abort halted the run: %s", resp.GetOutcome())
	}
	if s := r.a.Stats(); s.Aborted != 3 {
		t.Fatalf("stats %+v", s)
	}
}

// Every malformed complete and abort is refused before anything is written,
// so the handle is still open afterwards.
func TestACompleteOrAbortBodyIsDecodedStrictly(t *testing.T) {
	r := newRig(t, defaults())
	handle := r.executed(t, runA, "refund", refund)
	for _, tc := range []struct{ name, path, body string }{
		{"no status", enforce.PathComplete, `{"handle":"` + handle + `","sentArguments":"` + b64(refund) + `"}`},
		{"an undeclared status", enforce.PathComplete, `{"handle":"` + handle + `","sentArguments":"` + b64(refund) + `","status":9}`},
		{"no sent arguments", enforce.PathComplete, `{"handle":"` + handle + `","status":"COMPLETION_STATUS_SUCCESS"}`},
		{"sent arguments past the bound", enforce.PathComplete, completeBody(handle, `{"p":"`+strings.Repeat("x", 65536-8+1)+`"}`, "COMPLETION_STATUS_SUCCESS", "")},
		{"a result hash past the bound", enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", `,"resultHash":"`+strings.Repeat("h", 1025)+`"`)},
		{"a confirmation past the bound", enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", `,"sideEffectConfirmation":"`+strings.Repeat("c", 1025)+`"`)},
		{"no handle", enforce.PathComplete, completeBody("", refund, "COMPLETION_STATUS_SUCCESS", "")},
		{"an unknown member", enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", `,"retryable":true`)},
		{"a schema verdict", enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", `,"resultSchemaValid":true`)},
		{"no cause", enforce.PathAbort, `{"handle":"` + handle + `"}`},
		{"an undeclared cause", enforce.PathAbort, `{"handle":"` + handle + `","cause":9}`},
		{"an abort with no handle", enforce.PathAbort, `{"cause":"ABORT_CAUSE_NOT_SENT"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := r.post(t, runA, tc.path, tc.body)
			refusal(t, status, body, http.StatusBadRequest, enforcev1alpha1.ErrorCode_ERROR_CODE_MALFORMED)
		})
	}
	if r.count(kindDone)+r.count(kindFailed) != 0 {
		t.Fatalf("a malformed request closed the execution: %v", r.kinds())
	}
	if ending := r.complete(t, runA, handle, refund, "COMPLETION_STATUS_SUCCESS"); ending != recorded {
		t.Fatalf("ending %s", ending)
	}
}

func TestTheCompleteBoundsAreWhereTheyAreDocumented(t *testing.T) {
	r := newRig(t, defaults())
	handle := r.executed(t, runA, "refund", refund)
	sent := `{"p":"` + strings.Repeat("x", 65536-8) + `"}`
	extra := `,"resultHash":"` + strings.Repeat("h", 1024) + `","sideEffectConfirmation":"` + strings.Repeat("c", 1024) + `"`
	code, body := r.post(t, runA, enforce.PathComplete, completeBody(handle, sent, "COMPLETION_STATUS_SUCCESS", extra))
	if code != http.StatusOK {
		t.Fatalf("a complete at every bound answered %d: %s", code, body)
	}
}

// The plane alone knows which read it handed out unrecorded: that read's
// ending is UNRECORDED, closed or aborted, and a read whose trail landed
// under the same risk setting is RECORDED.
func TestAReadThePlaneLeftUnrecordedIsAnsweredUnrecorded(t *testing.T) {
	sink := &switchSink{}
	o := defaults()
	o.plane = func(c *gateway.Config) { c.Sink = sink; c.AllowReadsUnrecorded = true }
	r := newRig(t, o)
	landed := r.executed(t, runA, "read_file", `{"path":"a"}`)
	sink.failing.Store(true)
	closed := r.executed(t, runA, "read_file", `{"path":"a"}`)
	aborted := r.executed(t, runA, "read_file", `{"path":"a"}`)
	sink.failing.Store(false)
	if ending := r.complete(t, runA, closed, `{"path":"a"}`, "COMPLETION_STATUS_SUCCESS"); ending != unrecorded {
		t.Errorf("a read the plane left unrecorded was answered %s", ending)
	}
	if ending := r.abortWith(t, runA, aborted, "ABORT_CAUSE_NOT_SENT"); ending != unrecorded {
		t.Errorf("an aborted read the plane left unrecorded was answered %s", ending)
	}
	if ending := r.complete(t, runA, landed, `{"path":"a"}`, "COMPLETION_STATUS_SUCCESS"); ending != recorded {
		t.Errorf("a read whose trail landed was answered %s", ending)
	}
}

// switchSink refuses every append once failing is set.
type switchSink struct {
	kept    evidence.MemorySink
	failing atomic.Bool
}

func (s *switchSink) Append(ctx context.Context, e *controlv1.Event) error {
	if s.failing.Load() {
		return errors.New("sink: refused")
	}
	return s.kept.Append(ctx, e)
}

func TestAClosingTheSinkRefusesIsRecordFailed(t *testing.T) {
	sink := &switchSink{}
	o := defaults()
	o.plane = func(c *gateway.Config) { c.Sink = sink }
	r := newRig(t, o)
	matched := r.executed(t, runA, "refund", refund)
	mismatched := r.executed(t, runA, "refund", refund)
	aborted := r.executed(t, runA, "refund", refund)
	sink.failing.Store(true)
	if ending := r.complete(t, runA, matched, refund, "COMPLETION_STATUS_SUCCESS"); ending != recordFailed {
		t.Fatalf("complete answered %s", ending)
	}
	if ending := r.complete(t, runA, mismatched, `{"amount":1}`, "COMPLETION_STATUS_SUCCESS"); ending != recordFailed {
		t.Fatalf("a mismatch the sink refused answered %s", ending)
	}
	if ending := r.abortWith(t, runA, aborted, "ABORT_CAUSE_NOT_SENT"); ending != recordFailed {
		t.Fatalf("abort answered %s", ending)
	}
}

// The pipeline counts a client's abort it could not record as a failure
// before any effect, which the plane's lost count does not read: the adapter
// counts it, once, and a completion the pipeline counts itself it does not.
func TestAClientAbortTheSinkRefusedCountsAsAFailedRecord(t *testing.T) {
	sink := &switchSink{}
	o := defaults()
	o.plane = func(c *gateway.Config) { c.Sink = sink }
	r := newRig(t, o)
	aborted := r.executed(t, runA, "refund", refund)
	completed := r.executed(t, runA, "refund", refund)
	landed := r.executed(t, runB, "refund", refund)
	if ending := r.abortWith(t, runB, landed, "ABORT_CAUSE_NOT_SENT"); ending != recorded {
		t.Fatalf("an abort whose record landed answered %s", ending)
	}
	sink.failing.Store(true)
	if ending := r.abortWith(t, runA, aborted, "ABORT_CAUSE_NOT_SENT"); ending != recordFailed {
		t.Fatalf("abort answered %s", ending)
	}
	if got := r.a.Stats().RecordsFailed; got != 1 {
		t.Fatalf("records failed after a refused abort = %d, want 1", got)
	}
	if ending := r.complete(t, runA, completed, refund, "COMPLETION_STATUS_SUCCESS"); ending != recordFailed {
		t.Fatalf("complete answered %s", ending)
	}
	if got := r.a.Stats().RecordsFailed; got != 1 {
		t.Fatalf("records failed after a refused completion = %d, want 1", got)
	}
}

func TestAMismatchOfBytesThatAreNotJSONIsNeverAnsweredRecordedWhenItsRecordFailed(t *testing.T) {
	sink := &switchSink{}
	o := defaults()
	o.plane = func(c *gateway.Config) { c.Sink = sink }
	r := newRig(t, o)
	handle := r.executed(t, runA, "refund", refund)
	sink.failing.Store(true)
	if ending := r.complete(t, runA, handle, `not json`, "COMPLETION_STATUS_SUCCESS"); ending == recorded {
		t.Fatal("a refused record was answered RECORDED")
	}
}

// A mismatch of bytes that are not JSON is recorded like any other: once its
// record lands it is RECORDED, and the record names the mismatch.
func TestAMismatchOfBytesThatAreNotJSONIsRecordedWhenItsRecordLands(t *testing.T) {
	r := newRig(t, defaults())
	handle := r.executed(t, runA, "refund", refund)
	if ending := r.complete(t, runA, handle, `not json`, "COMPLETION_STATUS_SUCCESS"); ending != recorded {
		t.Fatalf("a landed mismatch was answered %s", ending)
	}
	if res := r.closing(t).GetResult(); res.GetToolProtocolStatus() != "EXECUTED_ARGS_MISMATCH" {
		t.Fatalf("recorded as %v", res)
	}
}
