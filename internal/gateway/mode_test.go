package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// TestEveryDeclaredModeHasARow walks the contract's enum rather than a list
// written here, so a mode added to the contract without a row fails.
func TestEveryDeclaredModeHasARow(t *testing.T) {
	values := controlv1.EnforcementMode(0).Descriptor().Values()
	if values.Len() < 7 {
		t.Fatalf("the contract declares %d modes; the table was written for 7", values.Len())
	}
	for i := range values.Len() {
		mode := controlv1.EnforcementMode(values.Get(i).Number())
		need, err := gateway.Requirements(mode)
		switch {
		case mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED:
			if !errors.Is(err, gateway.ErrMode) {
				t.Errorf("Requirements(UNSPECIFIED) = %+v, %v; want ErrMode", need, err)
			}
		case errors.Is(err, gateway.ErrMode):
			t.Errorf("Requirements(%s) = ErrMode; a declared mode has a row or is planned", mode)
		case err == nil && !need.ObserveRequest:
			t.Errorf("Requirements(%s) needs no ObserveRequest; every mode records", mode)
		}
	}
}

func TestBlockingModesNeedACooperatingAdapter(t *testing.T) {
	cases := []struct {
		mode        controlv1.EnforcementMode
		enforcement gateway.Enforcement
		err         error
	}{
		{controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE, gateway.EnforcementNone, nil},
		{controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE, gateway.EnforcementCooperative, nil},
		{controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE, gateway.EnforcementCooperative, nil},
		{controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN, gateway.EnforcementCooperative, nil},
		// The planned rows are readable before they are built: SHADOW acts on
		// the enforced decision, so it needs to block; WARN lets every call
		// proceed.
		{controlv1.EnforcementMode_ENFORCEMENT_MODE_SHADOW, gateway.EnforcementCooperative, gateway.ErrModePlanned},
		{controlv1.EnforcementMode_ENFORCEMENT_MODE_WARN, gateway.EnforcementNone, gateway.ErrModePlanned},
	}
	for _, tc := range cases {
		need, err := gateway.Requirements(tc.mode)
		if !errors.Is(err, tc.err) || need.Enforcement != tc.enforcement || !need.ObserveRequest || !need.ObserveResult {
			t.Errorf("Requirements(%s) = %+v, %v; want Enforcement=%d with both observes and %v", tc.mode, need, err, tc.enforcement, tc.err)
		}
	}
}

// TestEachEnforcementIsHeldAgainstEachMode: through New, an adapter that
// cannot keep a call from its effect runs only under OBSERVE, a cooperating
// one and an inline one under every mode this build enforces, and a value
// this build does not declare under none.
func TestEachEnforcementIsHeldAgainstEachMode(t *testing.T) {
	const undeclared = gateway.EnforcementInline + 1
	accepted := map[gateway.Enforcement][]controlv1.EnforcementMode{
		gateway.EnforcementNone:        {modeObserve},
		gateway.EnforcementCooperative: {modeObserve, modeApprove, modeEnforce, modeLockdown},
		gateway.EnforcementInline:      {modeObserve, modeApprove, modeEnforce, modeLockdown},
		undeclared:                     nil,
	}
	for enforcement, modes := range accepted {
		for _, mode := range allModes {
			cfg := validConfig(t)
			cfg.Mode = mode
			cfg.Adapter = fakeAdapter{name: "fake", caps: gateway.Capabilities{ObserveRequest: true, ObserveResult: true, Enforcement: enforcement}}
			_, err := gateway.New(cfg)
			switch want := slices.Contains(modes, mode); {
			case want && err != nil:
				t.Errorf("Enforcement %d under %s: New = %v, want it built", enforcement, mode, err)
			case !want && !errors.Is(err, gateway.ErrCapability):
				t.Errorf("Enforcement %d under %s: New = %v, want ErrCapability", enforcement, mode, err)
			}
		}
	}
}

func TestPlannedAndUndeclaredModesAreRefused(t *testing.T) {
	for _, mode := range []controlv1.EnforcementMode{
		controlv1.EnforcementMode_ENFORCEMENT_MODE_SHADOW,
		controlv1.EnforcementMode_ENFORCEMENT_MODE_WARN,
	} {
		if _, err := gateway.Requirements(mode); !errors.Is(err, gateway.ErrModePlanned) {
			t.Errorf("Requirements(%s) = %v; want ErrModePlanned", mode, err)
		}
	}
	if _, err := gateway.Requirements(controlv1.EnforcementMode(99)); !errors.Is(err, gateway.ErrMode) {
		t.Errorf("Requirements(99) = %v; want ErrMode", err)
	}
}

// unclassifiedRead is a read envelope with its effect class gone, refused as
// nothing classifies it, as an adapter hands over a tool no entry names.
func unclassifiedRead(requestID string) gateway.Admission {
	env := requestNamed(readEnvelope(), requestID)
	env.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
	a := admission(env, []byte(`{}`))
	a.Refusal = fmt.Errorf("adapter: %w", gateway.ErrUnclassified)
	return a
}

// TestOBSERVEHoldsAnUnclassifiedCallMaterial: OBSERVE lets a call nothing
// classifies through, but with no effect class to call it a read it is
// material, so a halted plane blocks it and the risk setting that runs a read
// unrecorded does not run it.
func TestOBSERVEHoldsAnUnclassifiedCallMaterial(t *testing.T) {
	ctx := context.Background()
	h := build(t, modeObserve, snapshot(t, allowWrites, allowReads))
	if d := h.p.Admit(ctx, unclassifiedRead("req-0")); d.Action != core.Execute {
		t.Fatalf("an unclassified call under OBSERVE: Action = %d, want Execute", d.Action)
	}
	d := h.admit(writeEnvelope(), []byte(`{}`))
	h.sink.fail(true)
	if err := h.p.Close(ctx, d, []byte(`{}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, errSink) {
		t.Fatalf("Close under a failing sink = %v, want the sink's error", err)
	}
	h.sink.fail(false)
	expectBlock(t, h.p.Admit(ctx, unclassifiedRead("req-2")), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)

	open := build(t, modeObserve, snapshot(t, allowReads), func(c *gateway.Config) { c.AllowReadsUnrecorded = true })
	open.sink.fail(true)
	expectBlock(t, open.p.Admit(ctx, unclassifiedRead("req-1")), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	if s := open.p.Stats(); s.ReadsUnrecorded != 0 || s.Executed != 0 {
		t.Errorf("Stats = %+v; want nothing run unrecorded", s)
	}
}
