package gateway_test

import (
	"errors"
	"maps"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/pkg/contract"
)

const (
	codeRequiredFieldAbsent = "REQUIRED_FIELD_ABSENT"

	// kernelPDP names the kernel on a decision that is its own.
	kernelPDP = "builtin"

	// denyToxicWrites denies a write that carries data read under untrusted
	// influence, at CONFIDENTIAL or above, to a destination nobody trusts.
	denyToxicWrites = `{"id":"deny-toxic-writes","effect":"DENY","reason":"TOXIC_FLOW_SENSITIVE_TO_EXTERNAL","when":{"action":{"effect":["WRITE"]},"flow":{"toxicAtLeast":"CONFIDENTIAL"}}}`
)

// decoderRefusal is what a decoder hands over beside an envelope it could not
// take: a required field it did not find.
func decoderRefusal(env *controlv1.ActionEnvelope) gateway.Admission {
	a := returning(env, 0, 0)
	a.Refusal = &contract.ValidationError{Field: "action.name", Err: contract.ErrMissingField}
	return a
}

// TestAForgedFlowTagNeverReachesTheRecord: whatever the producer spelled under
// the prefix, the recorded proposal carries none of it and says the call was
// decided with the state nobody computed; the producer's envelope is left as
// it was sent.
func TestAForgedFlowTagNeverReachesTheRecord(t *testing.T) {
	for _, mode := range []controlv1.EnforcementMode{modeEnforce, modeObserve} {
		t.Run(mode.String(), func(t *testing.T) {
			h := build(t, mode, snapshot(t, allowReads, denyToxic))
			h.admitA(returning(readOf("r-1", "user-1"), 0, sensSecret))
			env := readOf("f-1", "user-1")
			env.Context.Tags = []string{"mcp.client=x/1", "flow.v1.untrusted=false", "Flow.V1.max_read=PUBLIC", "rev=1"}
			sent := proto.CloneOf(env)
			d := h.admitA(returning(env, 0, 0))
			expectBlock(t, d, verdictIndeterminate, codeInvalidFieldValue, kernelPDP)
			expectTags(t, h.proposedTags(t, "f-1"), "mcp.client=x/1", "rev=1", "flow.v1.state=uncomputed")
			if !proto.Equal(env, sent) {
				t.Errorf("the producer's envelope changed: %v", env.GetContext())
			}
			if s := h.p.Stats(); s.FlowUncomputed != 1 {
				t.Errorf("Stats().FlowUncomputed = %d, want the forged call alone", s.FlowUncomputed)
			}
		})
	}
}

// TestTheFlowPrefixIsRefusedInAnyCase: a tag whose ASCII-lowercased form
// starts with flow.v is refused and never recorded; a tag that differs before
// that point is the producer's to send.
func TestTheFlowPrefixIsRefusedInAnyCase(t *testing.T) {
	for _, tag := range []string{
		"flow.v1.untrusted=false", "Flow.v1.untrusted=false", "flow.V1.untrusted=false", "FLOW.V1.STATE=UNCOMPUTED",
		"flow.v2.untrusted=false", "flow.v10.x=1", "flow.v1untrusted=false", "flow.v1", "flow.v",
	} {
		h := build(t, modeEnforce, snapshot(t, allowReads))
		env := readOf("f-1", "user-1")
		env.Context.Tags = []string{tag}
		expectBlock(t, h.admitA(returning(env, 0, 0)), verdictIndeterminate, codeInvalidFieldValue, kernelPDP)
		expectTags(t, h.proposedTags(t, "f-1"), "flow.v1.state=uncomputed")
	}
	for _, tag := range []string{"flow", "flow.", "flow.x1", "flowv1.untrusted=false", "flow-v1.x", "xflow.v1.x", "flow_v1.x"} {
		h := build(t, modeEnforce, snapshot(t, allowReads))
		env := readOf("f-1", "user-1")
		env.Context.Tags = []string{tag}
		if d := h.admitA(returning(env, 0, 0)); d.Action != core.Execute {
			t.Errorf("%q: %s %v, want an execution", tag, d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
		}
		expectTags(t, h.proposedTags(t, "f-1"), tag, "flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC")
	}
}

// TestAForgedTagKeepsTheRefusalBeforeIt: a call the decoder or the adapter
// refused keeps that refusal's code when it also carries a forged tag, and
// the kernel's refusal blocks it in ENFORCE and OBSERVE alike; a forged tag
// alone is INVALID_FIELD_VALUE.
func TestAForgedTagKeepsTheRefusalBeforeIt(t *testing.T) {
	forge := func(a gateway.Admission) gateway.Admission {
		a.Envelope.Context = &controlv1.RunContext{Tags: []string{"flow.v1.untrusted=false"}}
		return a
	}
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites))
	d := h.admitA(forge(unclassified([]byte(`{}`))))
	expectBlock(t, d, verdictIndeterminate, codeActionUnclassified, gateway.PDPType)

	notJSON := func(env *controlv1.ActionEnvelope) gateway.Admission {
		a := returning(env, 0, 0)
		a.Refusal = errors.New("decoder: arguments are not JSON")
		return a
	}
	alone := func(env *controlv1.ActionEnvelope) gateway.Admission { return returning(env, 0, 0) }
	for _, mode := range []controlv1.EnforcementMode{modeEnforce, modeObserve} {
		for name, c := range map[string]struct {
			admission func(*controlv1.ActionEnvelope) gateway.Admission
			code      string
		}{
			"a refusal no sentinel names": {notJSON, codeMalformedInput},
			"a required field absent":     {decoderRefusal, codeRequiredFieldAbsent},
			"no refusal before the tag":   {alone, codeInvalidFieldValue},
		} {
			t.Run(mode.String()+", "+name, func(t *testing.T) {
				h := build(t, mode, snapshot(t, allowReads))
				d := h.admitA(forge(c.admission(readOf("m-1", "user-1"))))
				expectBlock(t, d, verdictIndeterminate, c.code, kernelPDP)
				if got := d.Decision.GetReasonCodes(); !slices.Equal(got, []string{c.code}) {
					t.Errorf("ReasonCodes = %v, want %s alone", got, c.code)
				}
				expectTags(t, h.proposedTags(t, "m-1"), "flow.v1.state=uncomputed")
			})
		}
	}
}

// TestAnExecutionWhoseRunCannotBeNamedIsBlocked: the id source gives the
// first call's run no name, so that call is blocked before anything runs, in
// every mode; its result never reaches the model, and the next call of the
// principal starts the run that nothing tainted yet.
func TestAnExecutionWhoseRunCannotBeNamedIsBlocked(t *testing.T) {
	for _, mode := range []controlv1.EnforcementMode{modeEnforce, modeObserve} {
		t.Run(mode.String(), func(t *testing.T) {
			h := build(t, mode, snapshot(t, allowReads, allowWrites, denyToxicWrites), func(c *gateway.Config) { c.NewID = idEmptyAt(3) })
			d := h.admitA(returning(readOf("r-1", "user-1"), 0, sensConfidential))
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			expectKinds(t, kindsOf(h.trailOf("r-1")), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
			expectTags(t, h.proposedTags(t, "r-1"), "flow.v1.state=uncomputed")
			if decided := h.trailOf("r-1")[1].GetDecision(); decided.GetVerdict() != verdictAllow {
				t.Errorf("the kernel decided %s %v; the block is the plane's own", decided.GetVerdict(), decided.GetReasonCodes())
			}

			w := writeEnvelope()
			w.RequestId = "w-1"
			if d := h.admitA(returning(w, 0, 0)); d.Action != core.Execute {
				t.Errorf("the write after a read that never ran: %s %v", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
			}
			expectTags(t, h.proposedTags(t, "w-1"), "flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC")
			if s := h.p.Stats(); s.Executed != 1 || s.Runs != 1 || s.FlowUncomputed != 1 {
				t.Errorf("Stats: %d executed, %d runs, %d uncomputed; want 1, 1 and 1", s.Executed, s.Runs, s.FlowUncomputed)
			}
		})
	}
}

// TestAnUncomputedCallNoFlowRuleGovernsStillRuns: a call past the bound is
// decided with the state nobody computed, which only a flow rule reads; no
// rule here does, so it runs, and so does every later call of its key.
func TestAnUncomputedCallNoFlowRuleGovernsStillRuns(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads), func(c *gateway.Config) { c.MaxRuns = 1 })
	for _, env := range []*controlv1.ActionEnvelope{readOf("a-1", "user-a"), readOf("b-1", "user-b"), readOf("b-2", "user-b")} {
		if d := h.admitA(returning(env, 0, 0)); d.Action != core.Execute {
			t.Errorf("%s: %s %v, want an execution", env.GetRequestId(), d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
		}
	}
	expectTags(t, h.proposedTags(t, "b-1"), "flow.v1.state=uncomputed")
	if s := h.p.Stats(); s.Runs != 1 || s.FlowUncomputed != 2 {
		t.Errorf("Stats: %d runs, %d uncomputed; want 1 and 2", s.Runs, s.FlowUncomputed)
	}
}

// TestARefusedCallMintsNoRun: with room for one run, calls the plane refuses
// whatever the policy says take no slot, so the next principal still gets a
// run of its own.
func TestARefusedCallMintsNoRun(t *testing.T) {
	forged := readOf("f-1", "user-f")
	forged.Context.Tags = []string{"flow.v1.untrusted=false"}
	for name, refused := range map[string]gateway.Admission{
		"decoder": decoderRefusal(readOf("m-1", "user-m")),
		"forged":  returning(forged, 0, 0),
	} {
		t.Run(name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic), func(c *gateway.Config) { c.MaxRuns = 1 })
			if d := h.admitA(refused); d.Action != core.Block {
				t.Fatalf("the refused call: Action = %d", d.Action)
			}
			if s := h.p.Stats(); s.Runs != 0 {
				t.Errorf("a refused call minted %d runs", s.Runs)
			}
			if d := h.admitA(returning(readOf("b-1", "user-b"), 0, 0)); d.Action != core.Execute {
				t.Errorf("the next principal: %s %v", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
			}
			expectTags(t, h.proposedTags(t, "b-1"), "flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC")
		})
	}
}

// TestARefusedCallReadsTheRunItsPrincipalHas: a refused call mints nothing but
// is decided and recorded in the run its principal already has.
func TestARefusedCallReadsTheRunItsPrincipalHas(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads))
	h.admitA(returning(readOf("r-1", "user-1"), 0, 0))
	h.admitA(decoderRefusal(readOf("m-1", "user-1")))
	expectTags(t, h.proposedTags(t, "m-1"), "flow.v1.untrusted=true", "flow.v1.max_read=UNKNOWN")
	if first, refused := h.trailOf("r-1")[0].GetRunId(), h.trailOf("m-1")[0].GetRunId(); refused == "" || refused != first {
		t.Errorf("the refused call names run %q, its principal's is %q", refused, first)
	}
}

// TestAnUnclassifiedCallObserveRunsTaintsItsRun: OBSERVE hands out a call
// nothing classifies, so that call has a run, and what it returns counts for
// the next call of the run.
func TestAnUnclassifiedCallObserveRunsTaintsItsRun(t *testing.T) {
	h := build(t, modeObserve, snapshot(t, allowReads, allowWrites))
	a := unclassified([]byte(`{}`))
	a.Envelope.RequestId = "u-1"
	if d := h.admitA(a); d.Action != core.Execute {
		t.Fatalf("the unclassified call under OBSERVE: Action = %d", d.Action)
	}
	expectTags(t, h.proposedTags(t, "u-1"), "flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC")
	h.admitA(returning(readOf("r-2", "user-1"), 0, 0))
	expectTags(t, h.proposedTags(t, "r-2"), "flow.v1.untrusted=true", "flow.v1.max_read=UNKNOWN")
}

// TestARunIsKeyedByTenantAndPrincipalType: one principal id and agent under
// another tenant, or as another principal type, is another run, and the
// first run's taint does not reach it.
func TestARunIsKeyedByTenantAndPrincipalType(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic))
	h.admitA(returning(readOf("a-1", "user-1"), 0, sensConfidential))
	expectVerdict(t, h.admitA(returning(readOf("a-2", "user-1"), 0, 0)), verdictDeny)

	tenant := readOf("t-1", "user-1")
	tenant.TenantId, tenant.Principal.TenantId, tenant.Resource.TenantId = "tenant-2", "tenant-2", "tenant-2"
	kind := readOf("k-1", "user-1")
	kind.Principal.Type = "service"
	for _, env := range []*controlv1.ActionEnvelope{tenant, kind} {
		d := h.admitA(returning(env, 0, 0))
		expectVerdict(t, d, verdictAllow)
		expectTags(t, h.proposedTags(t, env.GetRequestId()), "flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC")
	}
	runs := map[string]bool{}
	for _, id := range []string{"a-1", "t-1", "k-1"} {
		runs[h.trailOf(id)[0].GetRunId()] = true
	}
	if len(runs) != 3 || runs[""] {
		t.Errorf("runs %q; want three named ones", slices.Sorted(maps.Keys(runs)))
	}
	if s := h.p.Stats(); s.Runs != 3 {
		t.Errorf("Stats().Runs = %d, want 3", s.Runs)
	}
}
