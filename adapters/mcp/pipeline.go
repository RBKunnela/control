package mcp

import (
	"context"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

// Pipeline is what the adapter asks about every call and every listed tool:
// the enforcement pipeline of internal/gateway, or a fake of the same shape
// in a test. Admit answers and never fails. Close takes the bytes that were
// sent and the result; Abort closes an execution the adapter did not send;
// an error from either means the record is not durable. Preview decides
// without recording, holding or executing, which is what list shaping asks.
type Pipeline interface {
	Admit(ctx context.Context, a gateway.Admission) gateway.Disposition
	Close(ctx context.Context, d gateway.Disposition, sent []byte, result *controlv1.ActionResult) error
	Abort(ctx context.Context, d gateway.Disposition, cause gateway.AbortCause) error
	Preview(ctx context.Context, a gateway.Admission) gateway.Previewed
}

var _ Pipeline = (*gateway.Pipeline)(nil)

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so nothing can reassign one into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// New's refusals.
const (
	// ErrListener is a listener kind this build does not know, an
	// authenticator on a listener that has no HTTP request to authenticate,
	// or a cap on sessions that is negative or on a listener that keeps none.
	ErrListener Error = "mcp: the listener is not one this build serves"
	// ErrIdentity is a listener with no principal or no agent configured, or
	// an authenticated listener whose configured principal carries more than
	// a tenant and a type: the user and what is known about them come from
	// the token, never from configuration.
	ErrIdentity Error = "mcp: the listener's configured identity is missing or claims what only a token may say"
	// ErrUpstream is no upstream, an upstream without a transport or with a
	// name no envelope can carry as its action.provider, or two upstreams
	// with one name.
	ErrUpstream Error = "mcp: an upstream lacks a transport or a name an envelope carries, or shares its name"
	// ErrOverride is an override that names no known upstream, no tool or no
	// fingerprint, classifies a tool another override does, carries a
	// classification classify.Check refuses, whose *classify.Error it wraps,
	// or is of a class that needs an environment the listener or its upstream
	// leaves empty.
	ErrOverride Error = "mcp: a manifest override is incomplete or out of bounds"
	// ErrShaping is a list shaping this build does not know.
	ErrShaping Error = "mcp: the list shaping is not one this build knows"
	// ErrNoClock is a nil clock.
	ErrNoClock Error = "mcp: no clock"
	// ErrNoIDSource is a nil id source.
	ErrNoIDSource Error = "mcp: no id source"
	// ErrListTimeout is a negative bound on reading an upstream's list.
	ErrListTimeout Error = "mcp: the list timeout cannot be negative"
	// ErrRunsSource is a run token source that does not fit the listener: a
	// token without a resolver, a token on HTTP, where the header is the only
	// source, or a stdio resolver with no token to resolve.
	ErrRunsSource Error = "mcp: the run token source does not fit the listener"
)

// Start's refusals.
const (
	// ErrNoPipeline is a nil pipeline.
	ErrNoPipeline Error = "mcp: no pipeline"
	// ErrStarted is a second Start.
	ErrStarted Error = "mcp: the adapter is started already"
	// ErrNotStarted is a listener served before Start connected the upstreams.
	ErrNotStarted Error = "mcp: the adapter is not started"
)

// Refusals of what an upstream serves.
const (
	// ErrListBound is an upstream list longer than the adapter reads: more
	// pages or more entries than the bound. A tools/list past it leaves that
	// upstream's tools unclassified.
	ErrListBound Error = "mcp: an upstream list exceeds the bound on pages or entries"
)

// Refusals of an execution the adapter was handed and does not send. Each is
// aborted, never closed, and the agent is told the block.
const (
	// ErrArguments is an authorized document the method cannot carry: a
	// resources/read takes no arguments, and a prompts/get takes an object of
	// strings.
	ErrArguments Error = "mcp: the authorized arguments are not what this method sends"
	// ErrUnroutable is an execution no configured upstream is known to serve.
	ErrUnroutable Error = "mcp: no upstream serves this operation"
)

// ErrNoEndUser is a request on an authenticated listener that carries no
// user identity: nothing to bind, so nothing is decided about.
const ErrNoEndUser Error = "mcp: the listener authenticated nobody for this request"
