package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/pkg/contract"
)

const (
	schemaVersion = "1.0"
	// noArguments is what a call with no arguments is decided and sent as:
	// the empty document, never null and never nothing.
	noArguments = "{}"
	// tagClient carries what the client said about itself: a run-context
	// tag, which the digest leaves out, never a field it covers.
	tagClient   = "mcp.client="
	tagRevision = "mcp.protocol_version="
)

// call is one operation the middleware translated: what the pipeline is
// asked, and what the adapter needs afterwards to send and to close.
type call struct {
	admission gateway.Admission
	entry     *Entry // nil for a resource read, a prompt get and a tool no upstream lists
	upstream  string
	requestID string
}

// arguments are the bytes the digest covers for a tools/call: what the agent
// sent, or the empty document when it sent nothing or null.
func arguments(raw json.RawMessage) []byte {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		return raw
	}
	return []byte(noArguments)
}

// promptArguments are a prompts/get's arguments as the bytes the digest
// covers: the canonical form of the map, the empty document for none.
func promptArguments(args map[string]string) ([]byte, error) {
	if len(args) == 0 {
		return []byte(noArguments), nil
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("mcp: prompt arguments: %w", err)
	}
	out, err := canon.CanonicalizeJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("mcp: prompt arguments: %w", err)
	}
	return out, nil
}

// identity resolves who is calling from the listener: the token the
// authenticator put on the request, or the operator's configured identity.
// A client's own claim in _meta.clientInfo never reaches it (ADR-0013).
func (a *Adapter) identity(req mcp.Request) (*controlv1.Principal, *controlv1.Agent, error) {
	principal := proto.CloneOf(a.cfg.Listener.Identity.Principal)
	agent := proto.CloneOf(a.cfg.Listener.Identity.Agent)
	if a.cfg.Listener.Authenticator == nil {
		return principal, agent, nil
	}
	extra := req.GetExtra()
	if extra == nil || extra.TokenInfo == nil || extra.TokenInfo.UserID == "" {
		return nil, nil, &contract.ValidationError{Field: "principal.id", Err: fmt.Errorf("%w: %w", contract.ErrMissingField, ErrNoEndUser)}
	}
	principal.Id = extra.TokenInfo.UserID
	principal.AuthnStrength = a.cfg.Listener.AuthnStrength
	return principal, agent, nil
}

// base builds what every envelope carries before the action: identifiers,
// the trace meta says the call belongs to, the clock, where the request was
// received, who calls and the run context with the client's claim as a tag.
// meta is the params' _meta, which each caller takes from params it already
// read: for a method whose params may be absent, the SDK's Params interface
// can hold a nil pointer that GetMeta dereferences.
func (a *Adapter) base(req mcp.Request, meta map[string]any, principal *controlv1.Principal, agent *controlv1.Agent, requestID string) *controlv1.ActionEnvelope {
	env := &controlv1.ActionEnvelope{
		SchemaVersion: schemaVersion,
		RequestId:     requestID,
		OccurredAt:    timestamppb.New(a.cfg.Clock()),
		ProjectId:     a.cfg.ProjectID,
		TenantId:      a.cfg.TenantID,
		Environment:   a.cfg.Environment,
		Principal:     principal,
		Agent:         agent,
		Context:       &controlv1.RunContext{},
	}
	env.TraceId, env.SpanId = traceContext(meta)
	if sr, ok := req.(interface {
		ClientInfo() *mcp.Implementation
		ProtocolVersion() string
	}); ok {
		if ci := sr.ClientInfo(); ci != nil {
			env.Context.Tags = append(env.Context.Tags, tagClient+ci.Name+"/"+ci.Version)
		}
		if v := sr.ProtocolVersion(); v != "" {
			env.Context.Tags = append(env.Context.Tags, tagRevision+v)
		}
	}
	return env
}

// toolCall translates a tools/call. The effect, the resource and the
// destination come from the manifest entry; a tool no entry classifies
// reaches the pipeline as the envelope that could be built beside a refusal
// wrapping gateway.ErrUnclassified, and the pipeline decides what happens to
// it.
func (a *Adapter) toolCall(req *mcp.CallToolRequest) call {
	c := call{requestID: a.cfg.NewID()}
	args := arguments(req.Params.Arguments)
	c.admission.Arguments = args
	principal, agent, err := a.identity(req)
	if err != nil {
		c.admission.Refusal = err
		return c
	}
	env := a.base(req, req.Params.Meta, principal, agent, c.requestID)
	env.Action = &controlv1.Action{Kind: channel.KindTool, Name: req.Params.Name, Protocol: channel.ProtocolMCP}
	c.admission.Envelope = env
	entry, err := a.manifest.route(req.Params.Name)
	c.entry = entry
	c.upstream = a.route(entry)
	if err != nil {
		c.admission.Refusal = adapterkit.Unclassified(a.finish(env, args), err)
		return c
	}
	c.admission.Classification = entry.Classification
	up := a.upstreamConfig(entry.Upstream)
	env.Action.Effect = entry.Effect
	env.Action.Provider = entry.Upstream
	env.Resource = &controlv1.Resource{
		Type:        entry.ResourceType,
		Id:          adapterkit.ResourceID(args, entry.ResourceFrom),
		TenantId:    up.TenantID,
		Environment: up.Environment,
	}
	if entry.TrustZone != controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED {
		env.Destination = &controlv1.Destination{TrustZone: entry.TrustZone}
	}
	c.admission.ResultTrust, c.admission.ResultSensitivity = entry.ReturnsTrust, entry.ReturnsSensitivity
	c.admission.Refusal = a.finish(env, args)
	return c
}

// route is the upstream a call goes to: the one whose entry classifies the
// tool, or, for a tool no entry names, the one upstream configured. With
// several, nothing says which would serve it and the call is unroutable.
func (a *Adapter) route(entry *Entry) string {
	switch {
	case entry != nil:
		return entry.Upstream
	case len(a.names) == 1:
		return a.names[0]
	}
	return ""
}

// read translates a resources/read or a prompts/get: a READ of the named
// resource on the upstream that serves it, with the arguments the agent
// asked with. The manifest lists tools only, so a read routes only where one
// upstream is configured; with several, nothing says which holds the URI or
// the prompt, and the read reaches the pipeline as unclassified.
func (a *Adapter) read(req mcp.Request, meta map[string]any, kind, name string, args []byte, argErr error) call {
	c := call{requestID: a.cfg.NewID(), upstream: a.route(nil)}
	c.admission.Arguments = args
	principal, agent, err := a.identity(req)
	if err != nil {
		c.admission.Refusal = err
		return c
	}
	env := a.base(req, meta, principal, agent, c.requestID)
	c.admission.Envelope = env
	env.Action = &controlv1.Action{Kind: kind, Name: name, Protocol: channel.ProtocolMCP}
	if argErr != nil {
		c.admission.Refusal = argErr
		return c
	}
	if len(a.names) != 1 {
		c.admission.Refusal = adapterkit.Unclassified(a.finish(env, args),
			fmt.Errorf("%w: %d upstreams serve %ss", gateway.ErrUnclassified, len(a.names), kind))
		return c
	}
	up := a.upstreamConfig(c.upstream)
	env.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_READ
	env.Action.Provider = c.upstream
	env.Resource = &controlv1.Resource{Type: channel.ProtocolMCP + "." + kind, Id: name, TenantId: up.TenantID, Environment: up.Environment}
	c.admission.Refusal = a.finish(env, args)
	return c
}

// finish hashes the arguments into the envelope and validates it, so the
// pipeline receives either an envelope Validate accepts or the refusal.
func (a *Adapter) finish(env *controlv1.ActionEnvelope, args []byte) error {
	if err := adapterkit.HashInto(env, args); err != nil {
		return err
	}
	return recordable(env, contract.Validate(env))
}

// recordable takes the strings an agent chose off an envelope Validate
// refused as too large, so the trail can record the refused call: the field
// the refusal names, and every other one of the action's name, the run
// context's tags and the resource's id past the bound, since Validate names
// only the first. An envelope refused whole loses its tags; a name and a
// resource within their bound cannot make it too large, and stay. A name or
// a resource taken off is recorded as its placeholder, which the contract
// requires in their place; the refusal names what was over the bound.
func recordable(env *controlv1.ActionEnvelope, err error) error {
	var ve *contract.ValidationError
	if !errors.As(err, &ve) || !errors.Is(err, contract.ErrTooLarge) {
		return err
	}
	if ve.Field == "action.name" && env.Action != nil {
		env.Action.Name = adapterkit.Placeholder(env.Action.Name)
	}
	if ve.Field == "" || strings.HasPrefix(ve.Field, "context.tags") {
		env.Context.Tags = nil
	}
	if ve.Field == "resource.id" && env.Resource != nil {
		env.Resource.Id = adapterkit.Placeholder(env.Resource.Id)
	}
	dropOverlong(env)
	return err
}

// dropOverlong replaces the action's name and the resource's id with their
// placeholders when either is past the contract's bound, and drops each such
// tag.
func dropOverlong(env *controlv1.ActionEnvelope) {
	if len(env.GetAction().GetName()) > contract.MaxStringBytes {
		env.Action.Name = adapterkit.Placeholder(env.Action.Name)
	}
	if len(env.GetResource().GetId()) > contract.MaxStringBytes {
		env.Resource.Id = adapterkit.Placeholder(env.Resource.Id)
	}
	if env.Context != nil {
		env.Context.Tags = slices.DeleteFunc(env.Context.Tags, func(tag string) bool { return len(tag) > contract.MaxStringBytes })
	}
}

func (a *Adapter) upstreamConfig(name string) Upstream {
	for _, up := range a.cfg.Upstreams {
		if up.Name == name {
			return up
		}
	}
	return Upstream{}
}
