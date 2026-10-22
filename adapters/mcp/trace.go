package mcp

import "github.com/guardana/control/internal/adapterkit"

// metaKeyTraceparent is the _meta key W3C trace context travels under,
// unprefixed as SEP-414 and OpenTelemetry's MCP conventions write it.
const metaKeyTraceparent = "traceparent"

// traceContext reads the traceparent a call's _meta carries through
// adapterkit.TraceContext; a value that is not a string names no trace.
func traceContext(meta map[string]any) (traceID, spanID string) {
	v, ok := meta[metaKeyTraceparent].(string)
	if !ok {
		return "", ""
	}
	return adapterkit.TraceContext(v)
}
