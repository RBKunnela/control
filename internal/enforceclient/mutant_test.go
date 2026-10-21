package enforceclient_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/enforceclient"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// defects are the rules a mutant can break, one per case's negative control.
var defects = []string{
	"block-executes-with-handle",
	"unspecified-executes",
	"unknown-executes",
	"skips-complete",
	"sends-proposed",
	"sends-proposed-when-empty",
	"ignores-obligations",
	"resumes-itself",
	"ignores-context",
	"aborts-on-tool-error",
	"completes-under-caller-context",
	"completes-when-not-sent",
	"reports-success",
	"retries-unauthenticated",
	"lenient-decoding",
	"retries-complete",
}

// mutant is a second client written apart from the reference one, which
// breaks exactly one rule when given a defect. Without one it must pass
// every case, so a case it fails is failed by the defect alone.
type mutant struct {
	defect string
	token  string
	http   *http.Client
}

func newMutant(defect string) newCaller {
	return func(_ *testing.T, socket, token string) caller {
		m := &mutant{defect: defect, token: token, http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}
		return m.call
	}
}

func (m *mutant) is(defect string) bool { return m.defect == defect }

func (m *mutant) post(ctx context.Context, path string, req, resp proto.Message) error {
	body, err := protojson.Marshal(req)
	if err != nil {
		return err
	}
	if path != enforceclient.PathComplete || !m.is("completes-under-caller-context") {
		ctx = context.WithoutCancel(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://enforce"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hreq.Header.Set(enforceclient.RunTokenHeader, m.token)
	hresp, err := m.http.Do(hreq)
	if err != nil {
		return fmt.Errorf("%w: %w", enforceclient.ErrTransport, err)
	}
	defer func() { _ = hresp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(hresp.Body, enforceclient.MaxAnswerBytes+1))
	if err != nil {
		return fmt.Errorf("%w: %w", enforceclient.ErrTransport, err)
	}
	if len(data) > enforceclient.MaxAnswerBytes {
		return fmt.Errorf("%w: past the bound", enforceclient.ErrMalformedAnswer)
	}
	opts := protojson.UnmarshalOptions{DiscardUnknown: m.is("lenient-decoding")}
	if hresp.StatusCode != http.StatusOK {
		var e enforcev1alpha1.Error
		if err := opts.Unmarshal(data, &e); err != nil {
			return fmt.Errorf("%w: %w", enforceclient.ErrMalformedAnswer, err)
		}
		return &enforceclient.RefusalError{Status: hresp.StatusCode, Code: e.GetCode(), Message: e.GetMessage(), Ending: e.GetEnding()}
	}
	if err := opts.Unmarshal(data, resp); err != nil {
		return fmt.Errorf("%w: %w", enforceclient.ErrMalformedAnswer, err)
	}
	return m.readVersion(resp)
}

// readVersion refuses an admit answer whose decision names no version the
// mutant reads, unless its defect is to read any.
func (m *mutant) readVersion(resp proto.Message) error {
	a, ok := resp.(*enforcev1alpha1.AdmitResponse)
	if !ok || a.GetDecision() == nil || m.is("reads-any-decision-version") || versionRead(a.GetDecision().GetSchemaVersion()) {
		return nil
	}
	return fmt.Errorf("%w: the decision's schema version", enforceclient.ErrMalformedAnswer)
}

// versionRead is the mutant's own reading of a decision's version: major 1
// and a minor of decimal digits that fits 32 bits.
func versionRead(v string) bool {
	minor, ok := strings.CutPrefix(v, "1.")
	if !ok || minor == "" || strings.Trim(minor, "0123456789") != "" {
		return false
	}
	_, err := strconv.ParseUint(minor, 10, 32)
	return err == nil
}

func (m *mutant) admit(ctx context.Context, tool string, args []byte) (*enforcev1alpha1.AdmitResponse, error) {
	retried := false
	for {
		resp := &enforcev1alpha1.AdmitResponse{}
		err := m.post(ctx, enforceclient.PathAdmit, &enforcev1alpha1.AdmitRequest{Tool: tool, Arguments: args}, resp)
		var refusal *enforceclient.RefusalError
		again := !retried && (errors.As(err, &refusal) && m.is("retries-unauthenticated") ||
			err == nil && resp.GetOutcome() == enforcev1alpha1.Outcome_OUTCOME_PENDING && m.is("resumes-itself"))
		if !again {
			return resp, err
		}
		retried = true
	}
}

func (m *mutant) executes(resp *enforcev1alpha1.AdmitResponse) bool {
	o, withHandle := resp.GetOutcome(), resp.GetExecution() != nil
	switch o {
	case enforcev1alpha1.Outcome_OUTCOME_EXECUTE:
		return true
	case enforcev1alpha1.Outcome_OUTCOME_BLOCK:
		return withHandle && m.is("block-executes-with-handle")
	case enforcev1alpha1.Outcome_OUTCOME_UNSPECIFIED:
		return withHandle && m.is("unspecified-executes")
	case enforcev1alpha1.Outcome_OUTCOME_PENDING:
		return false
	}
	return m.is("unknown-executes")
}

func (m *mutant) call(ctx context.Context, tool string, args []byte, exec enforceclient.Exec) (enforceclient.Answer, error) {
	if err := ctx.Err(); err != nil {
		return enforceclient.Answer{}, err
	}
	resp, err := m.admit(ctx, tool, args)
	ans := enforceclient.Answer{Outcome: enforcev1alpha1.Outcome_OUTCOME_BLOCK, Decision: resp.GetDecision()}
	switch {
	case err != nil:
		return ans, err
	case resp.GetOutcome() == enforcev1alpha1.Outcome_OUTCOME_PENDING:
		ans.Outcome, ans.Pending = enforcev1alpha1.Outcome_OUTCOME_PENDING, resp.GetPending()
		return ans, enforceclient.ErrPending
	case !m.executes(resp):
		return ans, enforceclient.ErrBlocked
	case resp.GetExecution().GetHandle() == "":
		return ans, fmt.Errorf("%w: nothing to execute under", enforceclient.ErrMalformedAnswer)
	}
	ans.Outcome = enforcev1alpha1.Outcome_OUTCOME_EXECUTE
	return m.execute(ctx, ans, resp.GetExecution(), args, exec)
}

func (m *mutant) execute(ctx context.Context, ans enforceclient.Answer, ex *enforcev1alpha1.Execution, args []byte, exec enforceclient.Exec) (enforceclient.Answer, error) {
	if cause, ok := m.refusal(ctx, ex, args); ok {
		return m.abort(ctx, ans, ex.GetHandle(), cause)
	}
	authorized := ex.GetAuthorizedArguments()
	if m.is("sends-proposed") || len(authorized) == 0 {
		authorized = args
	}
	res, err := exec(ctx, slices.Clone(authorized))
	notSent := errors.Is(err, enforceclient.ErrNotSent)
	if notSent && !m.is("completes-when-not-sent") || err != nil && m.is("aborts-on-tool-error") {
		return m.abort(ctx, ans, ex.GetHandle(), enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT)
	}
	ans.Ran, ans.Result = true, res
	if m.is("skips-complete") {
		return ans, err
	}
	return m.complete(ctx, ans, ex.GetHandle(), authorized, m.status(res, err, notSent), err)
}

// refusal is the abort cause of an execution the client must not run.
func (m *mutant) refusal(ctx context.Context, ex *enforcev1alpha1.Execution, args []byte) (enforcev1alpha1.AbortCause, bool) {
	switch {
	case len(ex.GetObligations()) > 0 && !m.is("ignores-obligations"):
		return enforcev1alpha1.AbortCause_ABORT_CAUSE_OBLIGATION, true
	case len(ex.GetAuthorizedArguments()) == 0 && len(args) > 0 && !m.is("sends-proposed-when-empty"):
		return enforcev1alpha1.AbortCause_ABORT_CAUSE_ARGUMENTS_DIFFER, true
	case ctx.Err() != nil && !m.is("ignores-context"):
		return enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT, true
	}
	return enforcev1alpha1.AbortCause_ABORT_CAUSE_UNSPECIFIED, false
}

func (m *mutant) status(res enforceclient.Result, err error, notSent bool) enforcev1alpha1.CompletionStatus {
	switch {
	case notSent:
		return enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_FAILURE
	case err != nil:
		return enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_UNKNOWN
	case m.is("reports-success"):
		return enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS
	case res.Status == enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_UNSPECIFIED:
		return enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_UNKNOWN
	}
	return res.Status
}

func (m *mutant) complete(ctx context.Context, ans enforceclient.Answer, handle string, sent []byte, status enforcev1alpha1.CompletionStatus, toolErr error) (enforceclient.Answer, error) {
	now := time.Now()
	started, ended := ans.Result.StartedAt, ans.Result.EndedAt
	if started.IsZero() {
		started = now
	}
	if ended.IsZero() {
		ended = now
	}
	req := &enforcev1alpha1.CompleteRequest{
		Handle: handle, SentArguments: sent, Status: status,
		StartedAt: timestamppb.New(started), EndedAt: timestamppb.New(ended),
		ResultHash: ans.Result.ResultHash, SideEffectConfirmation: ans.Result.SideEffectConfirmation,
	}
	for attempt := 0; ; attempt++ {
		resp := &enforcev1alpha1.CompleteResponse{}
		err := m.post(ctx, enforceclient.PathComplete, req, resp)
		var refusal *enforceclient.RefusalError
		if errors.As(err, &refusal) && attempt == 0 && m.is("retries-complete") {
			continue
		}
		if errors.As(err, &refusal) {
			ans.Ending = refusal.Ending
		}
		if err != nil {
			return ans, errors.Join(toolErr, err)
		}
		ans.Ending = resp.GetEnding()
		if ans.Ending != enforcev1alpha1.Ending_ENDING_RECORDED {
			return ans, errors.Join(toolErr, enforceclient.ErrNotRecorded)
		}
		return ans, toolErr
	}
}

func (m *mutant) abort(ctx context.Context, ans enforceclient.Answer, handle string, cause enforcev1alpha1.AbortCause) (enforceclient.Answer, error) {
	resp := &enforcev1alpha1.AbortResponse{}
	if err := m.post(ctx, enforceclient.PathAbort, &enforcev1alpha1.AbortRequest{Handle: handle, Cause: cause}, resp); err != nil {
		var refusal *enforceclient.RefusalError
		if errors.As(err, &refusal) {
			ans.Ending = refusal.Ending
		}
		return ans, errors.Join(enforceclient.ErrAborted, err)
	}
	ans.Ending = resp.GetEnding()
	return ans, enforceclient.ErrAborted
}

func TestTheMutantWithoutADefectPassesEveryCase(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			for _, m := range runCase(t, newMutant(""), c.ID) {
				t.Error(m)
			}
		})
	}
}

func TestEveryNegativeControlFailsItsCase(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			miss := runCase(t, newMutant(c.NegativeControl.Defect), c.ID)
			if len(miss) == 0 {
				t.Fatalf("a client that %s passed", c.NegativeControl.Breaks)
			}
			t.Logf("a client that %s fails: %v", c.NegativeControl.Breaks, miss)
		})
	}
}
