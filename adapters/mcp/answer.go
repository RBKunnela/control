package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

// The JSON-RPC error codes a blocked or pending resources/read or
// prompts/get carries, because those results have no isError of their own,
// and the one any message carries whose run token was refused. They sit
// outside the range the protocol reserves and away from the code the library
// uses privately (ADR-0013).
const (
	CodeBlocked int64 = -31100
	CodePending int64 = -31101
	// CodeRunRefused answers every refused run token alike, with one fixed
	// message: the agent learns nothing about which runs exist or why.
	CodeRunRefused int64 = -31102
	// CodeWithheld answers a resources/read, a prompts/get or a forwarded
	// list whose answer quoted a credential the gateway holds (ADR-0042).
	CodeWithheld int64 = -31103
)

// The keys of a block's and a pending state's structured content.
const (
	keyReasonCode   = "reason_code"
	keyReasonCodes  = "reason_codes"
	keyDecisionID   = "decision_id"
	keyApprovalID   = "approval_id"
	keyActionDigest = "action_digest"
	keyExpiresAt    = "expires_at"
	keyRetryAfter   = "retry_after"
	keyRefused      = "refused"

	codeUnclassified    = "ACTION_UNCLASSIFIED"
	codeApprovalPending = "APPROVAL_PENDING"
)

// metaKeyAnswer marks an answer the gateway made itself, under its own
// namespace, so an agent can tell a block or a pending state of the
// gateway's from an upstream result shaped to look like one. The key is
// stripped from everything an upstream sends.
var metaKeyAnswer = brandMeta + "answer"

const (
	answerBlocked = "blocked"
	answerPending = "pending"
)

// The keys that name the trail a tools/call answer belongs to: the request
// and decision ids of the decision the pipeline answered with, which on a
// retry of a held request are the held request's and not this call's. They
// are stripped from what an upstream sends like every key under the
// namespace, and do not mark an answer as the gateway's.
var (
	metaKeyRequestID  = brandMeta + "request_id"
	metaKeyDecisionID = brandMeta + "decision_id"
)

// trailIDs are the keys naming d's trail; none without a decision.
func trailIDs(d *controlv1.Decision) map[string]string {
	out := map[string]string{}
	if id := d.GetRequestId(); id != "" {
		out[metaKeyRequestID] = id
	}
	if id := d.GetDecisionId(); id != "" {
		out[metaKeyDecisionID] = id
	}
	return out
}

// named adds the keys naming d's trail to a tools/call result's _meta. It
// runs after Close hashed the result, so the recorded hash stays the
// upstream's, and writes a new map rather than one the result was handed.
func named(res mcp.Result, d *controlv1.Decision) mcp.Result {
	r, ok := res.(*mcp.CallToolResult)
	ids := trailIDs(d)
	if !ok || r == nil || len(ids) == 0 {
		return res
	}
	meta := make(mcp.Meta, len(r.Meta)+len(ids))
	for k, v := range r.Meta {
		meta[k] = v
	}
	for k, v := range ids {
		meta[k] = v
	}
	r.Meta = meta
	return r
}

// namedError is an upstream wire error answering a tools/call: its own code,
// message and data, the data without the keys under the namespace and with
// the keys naming d's trail when it is an object or absent. Data of any
// other shape has no place for them and arrives as it was sent. Any other
// failure is upstreamFailed.
func namedError(err error, d *controlv1.Decision) error {
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) {
		return upstreamFailed(err)
	}
	out := &jsonrpc.Error{Code: werr.Code, Message: werr.Message, Data: werr.Data}
	var data map[string]json.RawMessage
	if len(werr.Data) > 0 && json.Unmarshal(werr.Data, &data) != nil {
		return out
	}
	ids := trailIDs(d)
	merged := make(map[string]any, len(data)+len(ids))
	stripped := false
	for k, v := range data {
		if underBrand(k) {
			stripped = true
			continue
		}
		merged[k] = v
	}
	if !stripped && len(ids) == 0 {
		return out
	}
	for k, v := range ids {
		merged[k] = v
	}
	// Values that decoded as JSON re-encode, so a failure here cannot come
	// from the upstream; the data goes rather than a key it forged.
	out.Data = nil
	if raw, merr := json.Marshal(merged); merr == nil {
		out.Data = raw
	}
	return out
}

// blocked is what a blocked tools/call answers: a tool result the model can
// read, carrying the decision's reason codes and id. It is never a JSON-RPC
// error.
func blocked(d *controlv1.Decision, extra map[string]any) *mcp.CallToolResult {
	codes := d.GetReasonCodes()
	if len(codes) == 0 {
		codes = []string{"POLICY_UNAVAILABLE"}
	}
	sc := map[string]any{keyReasonCodes: codes, keyDecisionID: d.GetDecisionId()}
	for k, v := range extra {
		sc[k] = v
	}
	out := &mcp.CallToolResult{
		IsError:           true,
		Content:           []mcp.Content{&mcp.TextContent{Text: strings.Join(codes, ",")}},
		StructuredContent: sc,
	}
	out.Meta = mcp.Meta{metaKeyAnswer: answerBlocked}
	return out
}

// pending is the state an agent is told about a held request (ADR-0013).
func pending(p *gateway.Pending) *mcp.CallToolResult {
	if p == nil {
		return blocked(nil, nil)
	}
	out := &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: codeApprovalPending}},
		StructuredContent: map[string]any{
			keyReasonCode:   codeApprovalPending,
			keyApprovalID:   p.ApprovalID,
			keyActionDigest: p.ActionDigest,
			keyExpiresAt:    p.ExpiresAt.UTC().Format(time.RFC3339),
			keyRetryAfter:   int64((p.RetryAfter + time.Second - 1) / time.Second),
		},
	}
	out.Meta = mcp.Meta{metaKeyAnswer: answerPending}
	return out
}

// inMeta moves a block's or a pending state's fields from structured content
// into _meta under the namespace, the decision id excepted, which named
// writes. A client checks structured content against the output schema the
// tool listed, which the plane's fields never meet, and the schema an agent
// holds may be one an earlier listing gave, so no answer of the plane's
// carries structured content at all.
func inMeta(r *mcp.CallToolResult) *mcp.CallToolResult {
	sc, _ := r.StructuredContent.(map[string]any)
	meta := make(mcp.Meta, len(r.Meta)+len(sc))
	for k, v := range r.Meta {
		meta[k] = v
	}
	for k, v := range sc {
		if k != keyDecisionID {
			meta[brandMeta+k] = v
		}
	}
	r.Meta, r.StructuredContent = meta, nil
	return r
}

// blockedError is the block for a method whose result cannot say isError.
func blockedError(d *controlv1.Decision, extra map[string]any) error {
	return &jsonrpc.Error{Code: CodeBlocked, Message: "blocked by policy", Data: dataOf(blocked(d, extra), answerBlocked)}
}

// pendingError is the pending state for a method whose result cannot say
// isError.
func pendingError(p *gateway.Pending) error {
	return &jsonrpc.Error{Code: CodePending, Message: codeApprovalPending, Data: dataOf(pending(p), answerPending)}
}

// dataOf is a result's structured content, with the marker that says the
// gateway made this answer, as the error's data; a map of strings and
// integers always marshals, so a failure leaves the data out rather than
// the code.
func dataOf(r *mcp.CallToolResult, answer string) json.RawMessage {
	sc, ok := r.StructuredContent.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(sc)+1)
	for k, v := range sc {
		out[k] = v
	}
	out[metaKeyAnswer] = answer
	data, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return data
}

// upstreamError is an upstream wire error as the agent sees it: its own
// code and message, and data without the gateway's marker, so an upstream
// cannot answer as the gateway. Members stay raw, so a number keeps every
// digit the upstream wrote. Any other failure is upstreamFailed.
func upstreamError(err error) error {
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) {
		return upstreamFailed(err)
	}
	out := &jsonrpc.Error{Code: werr.Code, Message: werr.Message, Data: werr.Data}
	var data map[string]json.RawMessage
	if len(werr.Data) == 0 || json.Unmarshal(werr.Data, &data) != nil {
		return out
	}
	stripped := false
	for k := range data {
		if underBrand(k) {
			delete(data, k)
			stripped = true
		}
	}
	if !stripped {
		return out
	}
	out.Data = nil
	if raw, merr := json.Marshal(data); merr == nil {
		out.Data = raw
	}
	return out
}

// upstreamFailed answers a call that ended in no wire error of the
// upstream's, a timeout, a broken connection or an input request: a fixed
// code and message, because the error's own text can quote the endpoint,
// credential and all.
func upstreamFailed(err error) error {
	if errors.Is(err, errInputRequired) {
		return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: errInputRequired.Error()}
	}
	return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "the upstream did not answer"}
}

// codeRejectedByTransport is the code the SDK's HTTP client wraps around a
// call it could not complete: a send that failed, or a 429 or 5xx status.
const codeRejectedByTransport = -32005

// raisedByTheClient reports whether code is one the SDK's client puts on an
// error it raises itself: an answer it could not parse, or a call over HTTP
// it could not complete. An upstream may send these codes too; either way,
// whether the call took effect is unknown.
func raisedByTheClient(code int64) bool {
	switch code {
	case jsonrpc.CodeParseError, jsonrpc.CodeInvalidRequest, codeRejectedByTransport:
		return true
	}
	return false
}

// resultOf records what an upstream answered, or failed to, for Close: the
// status, the protocol's own status and a hash of the result's encoding,
// prefixed when the agent was shown a fixed answer instead. The identifiers
// are the pipeline's, which named the request and minted the execution; the
// adapter mints none. No content is captured (ADR-0004).
func resultOf(d gateway.Disposition, started, ended time.Time, ans answer) *controlv1.ActionResult {
	out := &controlv1.ActionResult{
		SchemaVersion: schemaVersion,
		RequestId:     d.Decision.GetRequestId(),
		ExecutionId:   d.ExecutionID,
		StartedAt:     timestamppb.New(started),
		EndedAt:       timestamppb.New(ended),
	}
	err := ans.err
	switch {
	case err == nil:
		out.Status = controlv1.ResultStatus_RESULT_STATUS_SUCCESS
		out.ToolProtocolStatus = "ok"
		if r, ok := ans.res.(*mcp.CallToolResult); ok && r != nil && r.IsError {
			out.Status = controlv1.ResultStatus_RESULT_STATUS_FAILURE
			out.ToolProtocolStatus = "isError"
		}
		if !ans.encoded {
			out.Status = controlv1.ResultStatus_RESULT_STATUS_UNKNOWN
			out.ToolProtocolStatus = "unhashable"
			break
		}
		sum := sha256.Sum256(ans.encoding)
		out.ResultHash = "sha256:" + hex.EncodeToString(sum[:])
	case errors.Is(err, errInputRequired):
		out.Status = controlv1.ResultStatus_RESULT_STATUS_FAILURE
		out.ToolProtocolStatus = "input_required"
	case errors.Is(err, context.DeadlineExceeded):
		out.Status = controlv1.ResultStatus_RESULT_STATUS_TIMEOUT
		out.ToolProtocolStatus = "timeout"
	default:
		out.Status = controlv1.ResultStatus_RESULT_STATUS_UNKNOWN
		out.ToolProtocolStatus = "error"
		var werr *jsonrpc.Error
		if errors.As(err, &werr) && !raisedByTheClient(werr.Code) {
			out.Status = controlv1.ResultStatus_RESULT_STATUS_FAILURE
			out.ToolProtocolStatus = "jsonrpc:" + strconv.FormatInt(werr.Code, 10)
		}
	}
	if ans.withheld {
		out.ToolProtocolStatus = statusWithheld + out.ToolProtocolStatus
	}
	return out
}
