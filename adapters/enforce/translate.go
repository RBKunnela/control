package enforce

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/pkg/contract"
)

const (
	schemaVersion = "1.0"
	// noArguments is what an admit with no arguments is decided as: the empty
	// document, never nothing.
	noArguments = "{}"
)

// translate builds the admission for req under run: the envelope from the
// listener's identity, the run and the tool table, never from the request
// beyond the tool's name, its arguments and the trace it claims. A tool the
// table does not name reaches the pipeline beside a refusal wrapping
// gateway.ErrUnclassified.
func (a *Adapter) translate(req *enforcev1alpha1.AdmitRequest, run gateway.OpenedRun) gateway.Admission {
	args := req.GetArguments()
	if len(args) == 0 {
		args = []byte(noArguments)
	}
	env := &controlv1.ActionEnvelope{
		SchemaVersion: schemaVersion,
		RequestId:     a.cfg.NewID(),
		OccurredAt:    timestamppb.New(a.cfg.Clock()),
		ProjectId:     a.cfg.ProjectID,
		TenantId:      a.cfg.TenantID,
		Environment:   a.cfg.Environment,
		Principal:     proto.CloneOf(a.cfg.Identity.Principal),
		Agent:         proto.CloneOf(a.cfg.Identity.Agent),
		Context:       &controlv1.RunContext{},
		Action:        &controlv1.Action{Kind: channel.KindTool, Name: req.GetTool(), Protocol: channel.ProtocolEnforce},
	}
	env.TraceId, env.SpanId = adapterkit.TraceContext(req.GetTraceparent())
	adm := gateway.Admission{Envelope: env, Arguments: args, Run: &run}
	tool, ok := a.tools[req.GetTool()]
	if !ok {
		adm.Refusal = adapterkit.Unclassified(finish(env, args), fmt.Errorf("%w: the tool table does not name the tool", gateway.ErrUnclassified))
		return adm
	}
	env.Action.Effect = tool.Effect
	env.Action.Provider = tool.Provider
	env.Resource = &controlv1.Resource{
		Type:        tool.ResourceType,
		Id:          adapterkit.ResourceID(args, tool.ResourceFrom),
		TenantId:    a.cfg.TenantID,
		Environment: a.cfg.Environment,
	}
	if tool.TrustZone != controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED {
		env.Destination = &controlv1.Destination{TrustZone: tool.TrustZone}
	}
	adm.ResultTrust, adm.ResultSensitivity = tool.ReturnsTrust, tool.ReturnsSensitivity
	adm.Classification = tool.Classification
	adm.Refusal = finish(env, args)
	return adm
}

// finish hashes the arguments into the envelope and validates it, so the
// pipeline receives either an envelope Validate accepts or the refusal. A
// resource id past the contract's bound is recorded as its placeholder.
func finish(env *controlv1.ActionEnvelope, args []byte) error {
	if err := adapterkit.HashInto(env, args); err != nil {
		return err
	}
	if id := env.GetResource().GetId(); len(id) > contract.MaxStringBytes {
		env.Resource.Id = adapterkit.Placeholder(id)
		return &contract.ValidationError{Field: "resource.id", Err: contract.ErrTooLarge}
	}
	return contract.Validate(env)
}
