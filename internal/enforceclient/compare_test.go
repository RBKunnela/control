package enforceclient_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/enforceclient"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func requestMessage(path string) (proto.Message, bool) {
	switch path {
	case enforceclient.PathAdmit:
		return &enforcev1alpha1.AdmitRequest{}, true
	case enforceclient.PathComplete:
		return &enforcev1alpha1.CompleteRequest{}, true
	case enforceclient.PathAbort:
		return &enforcev1alpha1.AbortRequest{}, true
	}
	return nil, false
}

// canonical decodes a request body strictly as its path's message and
// returns it as protojson writes it, so that member order and spacing do
// not matter.
func canonical(path string, body []byte) (map[string]any, error) {
	m, ok := requestMessage(path)
	if !ok {
		return nil, fmt.Errorf("no operation at %s", path)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(body, m); err != nil {
		return nil, err
	}
	out, err := protojson.Marshal(m)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func compareRequests(got []gotRequest, token string, want expectFile) []string {
	var miss []string
	if len(got) != len(want.Requests) {
		miss = append(miss, fmt.Sprintf("%d requests, want %d", len(got), len(want.Requests)))
	}
	var aborts, completes []map[string]any
	for i, g := range got {
		if g.token != token {
			miss = append(miss, fmt.Sprintf("request %d presented another run token", i+1))
		}
		body, err := canonical(g.path, g.body)
		if err != nil {
			miss = append(miss, fmt.Sprintf("request %d to %s: %v", i+1, g.path, err))
			continue
		}
		switch g.path {
		case enforceclient.PathAbort:
			aborts = append(aborts, body)
		case enforceclient.PathComplete:
			completes = append(completes, body)
		}
		if i >= len(want.Requests) {
			miss = append(miss, fmt.Sprintf("request %d to %s not expected", i+1, g.path))
			continue
		}
		w := want.Requests[i]
		if g.path != w.Path {
			miss = append(miss, fmt.Sprintf("request %d to %s, want %s", i+1, g.path, w.Path))
			continue
		}
		miss = append(miss, matchJSON(fmt.Sprintf("request %d", i+1), w.Body, body)...)
	}
	miss = append(miss, lastField("abort cause", aborts, "cause", want.AbortCause)...)
	miss = append(miss, lastField("completion status", completes, "status", want.CompletionStatus)...)
	return miss
}

// lastField holds the expectation's abort cause or completion status to
// the requests themselves: none sent when it is empty, else exactly one
// carrying it.
func lastField(what string, bodies []map[string]any, key, want string) []string {
	switch {
	case want == "" && len(bodies) == 0:
		return nil
	case want == "":
		return []string{fmt.Sprintf("%s sent, want none", what)}
	case len(bodies) != 1:
		return []string{fmt.Sprintf("%d requests carrying the %s, want 1", len(bodies), what)}
	case bodies[0][key] != want:
		return []string{fmt.Sprintf("%s %v, want %s", what, bodies[0][key], want)}
	}
	return nil
}

// matchJSON compares a decoded request with its expectation, where the
// string "*" matches any value that is present.
func matchJSON(at string, want, got any) []string {
	if s, ok := want.(string); ok && s == "*" {
		if got == nil {
			return []string{at + ": absent, want a value"}
		}
		return nil
	}
	wm, wok := want.(map[string]any)
	gm, gok := got.(map[string]any)
	if !wok || !gok {
		if !reflect.DeepEqual(want, got) {
			return []string{fmt.Sprintf("%s: %v, want %v", at, got, want)}
		}
		return nil
	}
	var miss []string
	for k, wv := range wm {
		miss = append(miss, matchJSON(at+"."+k, wv, gm[k])...)
	}
	for k := range gm {
		if _, ok := wm[k]; !ok {
			miss = append(miss, fmt.Sprintf("%s.%s: present, want absent", at, k))
		}
	}
	return miss
}

func errorKind(err error) (string, string) {
	var refusal *enforceclient.RefusalError
	switch {
	case err == nil:
		return "none", ""
	case errors.Is(err, enforceclient.ErrMalformedAnswer):
		return "malformed_answer", ""
	case errors.As(err, &refusal):
		return "refused", refusal.Code.String()
	case errors.Is(err, enforceclient.ErrPending):
		return "pending", ""
	case errors.Is(err, enforceclient.ErrBlocked):
		return "blocked", ""
	case errors.Is(err, enforceclient.ErrAborted):
		return "aborted", ""
	case errors.Is(err, enforceclient.ErrNotRecorded):
		return "not_recorded", ""
	case errors.Is(err, enforceclient.ErrTransport):
		return "transport", ""
	}
	return "tool_error", ""
}

func compareReturns(a enforceclient.Answer, err error, want returns) []string {
	var miss []string
	kind, code := errorKind(err)
	if kind != want.Error || code != want.Code {
		miss = append(miss, fmt.Sprintf("returned %s %s (%v), want %s %s", kind, code, err, want.Error, want.Code))
	}
	ending := ""
	if a.Ending != enforcev1alpha1.Ending_ENDING_UNSPECIFIED {
		ending = a.Ending.String()
	}
	if ending != want.Ending {
		miss = append(miss, fmt.Sprintf("ending %q, want %q", ending, want.Ending))
	}
	approval, retry := "", ""
	if p := a.Pending; p != nil {
		approval = p.GetApprovalId()
		if p.GetRetryAfter() != nil {
			retry = fmt.Sprintf("%gs", p.GetRetryAfter().AsDuration().Seconds())
		}
	}
	if approval != want.ApprovalID || retry != want.RetryAfter {
		miss = append(miss, fmt.Sprintf("pending %q after %q, want %q after %q", approval, retry, want.ApprovalID, want.RetryAfter))
	}
	return miss
}
