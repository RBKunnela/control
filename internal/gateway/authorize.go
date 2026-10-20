package gateway

import (
	"bytes"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
)

// authorize produces the bytes execution may send: the proposed bytes as
// they are, or the rewritten document when a rewriting obligation applies,
// and the obligations left for the adapter. OBSERVE executes the proposed
// bytes and enforces nothing.
//
// A rewrite that changed the arguments makes the call another action, so the
// kernel decides the authorized envelope with the rewritten bytes against
// the same snapshot, and that decision is the one recorded, bound and
// compared at Close. No rule reads argument values, so it is the first one
// again unless the clock moved between the two; either way it is enforced as
// it is, and when it would let the call proceed its own rewriting
// obligations have to give exactly the bytes it was asked about.
func (c *call) authorize(snap *policy.Snapshot) {
	c.args, c.rest = c.in.Arguments, nil
	if c.p.cfg.Mode != modeObserve {
		args, rest, err := rewrite(c.in.Arguments, c.kernel.GetObligations())
		if err != nil {
			c.decide(verdictDeny, codeObligationNotApplied)
			return
		}
		c.args, c.rest = args, rest
	}
	digest, err := canon.ArgumentsHashV1(c.args)
	if err != nil {
		c.decide(verdictIndeterminate, codeInvalidFieldValue)
		return
	}
	c.digest = digest
	c.env = authorizedEnvelope(c.in.Envelope, digest)
	if !bytes.Equal(c.args, c.in.Arguments) {
		proposed, err := canon.ArgumentsHashV1(c.in.Arguments)
		if err != nil || proposed != digest {
			if !c.decideAuthorized(snap) {
				return
			}
		}
	}
	actionDigest, err := canon.DigestV1(c.env, c.args)
	if err != nil {
		c.decide(verdictIndeterminate, codeInvalidFieldValue)
		return
	}
	c.actionDigest = actionDigest
	if c.action == core.Execute && len(c.rest) > 0 {
		c.action = core.ExecuteWithObligations
	}
}

// decideAuthorized asks the kernel about the authorized envelope and bytes,
// applies the mode to its answer, and reports whether the call may go on. It
// reuses the decision point's answer about the proposed call, since the
// question would carry nothing the rewrite changed.
func (c *call) decideAuthorized(snap *policy.Snapshot) bool {
	out := c.p.kernel.Decide(c.ctx, core.Request{
		Envelope: c.env, Refusal: c.in.Refusal, AuthorizedArgs: c.args, Flow: c.flow.state, External: c.external,
	}, snap)
	c.kernel, c.decision, c.action, c.basis = out.Decision, out.Decision, out.Action, out.Basis
	c.kernelAction = out.Action
	c.reliedOnDecision(out.Decision, snap)
	c.applyMode()
	if c.action == core.Block {
		return false
	}
	rest, ok := reproduces(c.in.Arguments, c.args, c.kernel.GetObligations())
	if !ok {
		c.decide(verdictDeny, codeObligationNotApplied)
		return false
	}
	c.rest = rest
	return true
}

// reproduces reports whether obligations rewrite proposed into exactly
// authorized, and returns the obligations they leave for the adapter.
func reproduces(proposed, authorized []byte, obligations []*controlv1.Obligation) ([]*controlv1.Obligation, bool) {
	args, rest, err := rewrite(proposed, obligations)
	if err != nil || !bytes.Equal(args, authorized) {
		return nil, false
	}
	return rest, true
}

// authorizedEnvelope is env as the authorized call: its arguments hash is
// the hash of the bytes that may be sent, and it carries no preview or
// redaction profile, which describe the proposed bytes.
func authorizedEnvelope(env *controlv1.ActionEnvelope, argumentsHash string) *controlv1.ActionEnvelope {
	out := proto.CloneOf(env)
	if out == nil {
		out = &controlv1.ActionEnvelope{}
	}
	if out.Arguments == nil {
		out.Arguments = &controlv1.Arguments{}
	}
	out.Arguments.CanonicalHash = argumentsHash
	out.Arguments.RedactedPreview = ""
	out.Arguments.RedactionProfile = ""
	return out
}
