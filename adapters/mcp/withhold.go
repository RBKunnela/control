package mcp

import (
	"encoding/json"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/secretscan"
)

// What the agent is shown in place of an answer that quoted a credential the
// gateway holds (ADR-0042). The effect happened or not as the record says;
// the text says so, since a model that reads a failure may call again.
const (
	answerWithheld = "withheld"

	textRanWithheld      = "The call ran, and its answer was withheld because it quoted a credential the gateway holds. Calling again repeats its effect."
	textErroredWithheld  = "The tool answered with an error, which was withheld because it quoted a credential the gateway holds."
	messageErrorWithheld = "the upstream's error was withheld because it quoted a credential the gateway holds"
	messageWithheld      = "the upstream's answer was withheld because it quoted a credential the gateway holds"

	statusWithheld = "withheld:"
)

// answer is what one upstream call came to, encoded once for the record's
// hash and for the scan.
type answer struct {
	res any
	err error
	// encoding is json.Marshal of res, set when err is nil and res encoded.
	encoding []byte
	encoded  bool
	verdict  secretscan.Verdict
	withheld bool
}

// inspect encodes and scans what an upstream answered. A result that does not
// encode is not scanned, and is withheld. A wire error is scanned by its
// message and data; any other failure reaches the agent as upstreamFailed,
// which carries nothing of the upstream's, so it is not scanned.
func inspect(secrets *secretscan.Set, res any, err error) answer {
	out := answer{res: res, err: err}
	if err == nil {
		raw, merr := json.Marshal(res)
		if merr == nil {
			out.encoding, out.encoded = raw, true
			out.verdict = secrets.ScanJSON(raw)
		}
		out.withheld = out.verdict.Withhold()
		return out
	}
	var werr *jsonrpc.Error
	if errors.As(err, &werr) {
		out.verdict = scanWireError(secrets, werr)
		out.withheld = out.verdict.Withhold()
	}
	return out
}

// scanWireError reads an error's message and, when it has any, its data,
// and returns a found verdict before one that could not scan.
func scanWireError(secrets *secretscan.Set, werr *jsonrpc.Error) secretscan.Verdict {
	msg := secrets.ScanText(werr.Message)
	if msg.State == secretscan.Found || len(werr.Data) == 0 {
		return msg
	}
	data := secrets.ScanJSON(werr.Data)
	if data.State == secretscan.Clean {
		return msg
	}
	return data
}

// scanned is v's encoding scanned; a value that does not encode is not
// scanned.
func scanned(secrets *secretscan.Set, v any) secretscan.Verdict {
	raw, err := json.Marshal(v)
	if err != nil {
		return secretscan.Verdict{}
	}
	return secrets.ScanJSON(raw)
}

// scan inspects what the upstream answered a call, and counts and logs the
// answer when it is withheld.
func (a *Adapter) scan(d gateway.Disposition, c *call, res mcp.Result, err error) answer {
	ans := inspect(a.cfg.Secrets, res, err)
	if ans.withheld {
		a.withheldAnswer(d.Decision.GetRequestId(), methodOf(c.admission.Envelope.GetAction().GetKind()), c.upstream, ans.verdict)
	}
	return ans
}

// withheldAnswer counts and logs one answer withheld from the agent by the
// matched secret's key and spelling, never by its value or the text.
func (a *Adapter) withheldAnswer(requestID, method, upstream string, v secretscan.Verdict) {
	a.withheld.Add(1)
	var attrs []any
	if requestID != "" {
		attrs = append(attrs, "request_id", requestID)
	}
	attrs = append(attrs, "method", method, "upstream", upstream, "secret", v.Key, "spelling", v.Spelling)
	if v.State != secretscan.Found {
		attrs = append(attrs, "scan", "not scanned")
	}
	a.logger.Warn("upstream answer withheld", attrs...)
}

// logWithheldDefinitions logs each of upstream's tool definitions the scan
// kept out of the manifest. A tool's name is logged only when it alone holds
// no secret.
func (a *Adapter) logWithheldDefinitions(upstream string) {
	for _, e := range a.manifest.withheldOf(upstream) {
		attrs := []any{"upstream", upstream}
		if a.cfg.Secrets.ScanText(e.Tool.Name).State == secretscan.Clean {
			attrs = append(attrs, "tool", e.Tool.Name)
		}
		attrs = append(attrs, "secret", e.verdict.Key, "spelling", e.verdict.Spelling)
		if e.verdict.State != secretscan.Found {
			attrs = append(attrs, "scan", "not scanned")
		}
		a.logger.Warn("tool definition withheld", attrs...)
	}
}

// definitionWithheld is why a withheld definition is unclassified, naming
// the secret by its key.
func definitionWithheld(v secretscan.Verdict) string {
	if v.State == secretscan.Found {
		return "its definition quotes the secret " + v.Key
	}
	return "its definition could not be scanned for secrets"
}

// methodOf is the method a call of kind was received as.
func methodOf(kind string) string {
	switch kind {
	case channel.KindResource:
		return methodReadResource
	case channel.KindPrompt:
		return methodGetPrompt
	}
	return methodCallTool
}

// withheldResult is a tools/call's answer in place of the upstream's: an
// error result for an upstream isError and, since no fixed answer meets an
// output schema a client checks a success against, for a tool that declares
// one; otherwise a success that says the call ran.
func withheldResult(res mcp.Result, e *Entry) *mcp.CallToolResult {
	text, isError := textRanWithheld, false
	if r, ok := res.(*mcp.CallToolResult); ok && r != nil && r.IsError {
		text, isError = textErroredWithheld, true
	} else if e != nil && e.Tool != nil && e.Tool.OutputSchema != nil {
		isError = true
	}
	out := &mcp.CallToolResult{IsError: isError, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
	out.Meta = mcp.Meta{metaKeyAnswer: answerWithheld}
	return out
}

// withheldError is an upstream wire error in place of the upstream's: its
// code, a fixed message, and as data the marker and the keys naming d's
// trail, none without a decision. Any other failure is upstreamFailed.
func withheldError(err error, d *controlv1.Decision) error {
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) {
		return upstreamFailed(err)
	}
	return &jsonrpc.Error{Code: werr.Code, Message: messageErrorWithheld, Data: withheldData(d)}
}

// withheldAnswerError answers a resources/read, a prompts/get or a forwarded
// list whose answer was withheld: those results cannot say isError.
func withheldAnswerError() error {
	return &jsonrpc.Error{Code: CodeWithheld, Message: messageWithheld, Data: withheldData(nil)}
}

// withheldData is the marker and d's trail ids; a map of strings always
// marshals, so a failure leaves the data out rather than the code.
func withheldData(d *controlv1.Decision) json.RawMessage {
	data := map[string]string{metaKeyAnswer: answerWithheld}
	for k, v := range trailIDs(d) {
		data[k] = v
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	return raw
}

// withheldOf returns upstream's entries the scan withheld, as they stand.
func (m *manifest) withheldOf(upstream string) []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Entry
	for _, e := range m.perUp[upstream] {
		if e.withheld {
			out = append(out, *e)
		}
	}
	return out
}

// Withheld reports whether the scan kept this definition out of the manifest,
// and why, by the secret's configuration key and never by its value.
func (e Entry) Withheld() (string, bool) { return e.why, e.withheld }
