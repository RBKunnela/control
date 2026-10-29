package gateway_test

import (
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// TestAFlowTheRunCannotVouchForIsNeverAsked: a call blocked for its run
// whatever the answer, because the run's state cannot be read, the id source
// cannot name its run or the producer forged a flow tag, sends no question to
// the decision point, in every mode; a call whose run reads is asked once.
func TestAFlowTheRunCannotVouchForIsNeverAsked(t *testing.T) {
	forged := func() gateway.Admission {
		env := readOf("r-1", "user-1")
		env.Context.Tags = []string{"flow.v1.untrusted=false"}
		return returning(env, 0, 0)
	}
	plain := func() gateway.Admission { return returning(readOf("r-1", "user-1"), 0, 0) }
	cases := map[string]struct {
		admission func() gateway.Admission
		config    func(*gateway.Config)
		asks      uint64
		code      string
	}{
		"an unreadable run state": {
			func() gateway.Admission { return under(plain(), opened("run-a", "root-1")) },
			func(c *gateway.Config) {
				r := newRuns("root-1")
				r.failState = true
				withRuns(r)(c)
			}, 0, codeEvidenceUnavailable,
		},
		"no opened run":                   {plain, withRuns(newRuns("root-1")), 0, codeEvidenceUnavailable},
		"a run the id source cannot name": {plain, func(c *gateway.Config) { c.NewID = idEmptyAt(3) }, 0, codeEvidenceUnavailable},
		"a forged flow tag":               {forged, func(*gateway.Config) {}, 0, codeInvalidFieldValue},
		"a run whose state reads": {
			func() gateway.Admission { return under(plain(), opened("run-a", "root-1")) },
			withRuns(newRuns("root-1")), 1, "",
		},
	}
	for name, tc := range cases {
		for _, mode := range []controlv1.EnforcementMode{modeEnforce, modeObserve} {
			t.Run(name+"/"+mode.String(), func(t *testing.T) {
				dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
				h := build(t, mode, snapshot(t, allowReads, vetoReads), tc.config, withDecisionPoint(dp))
				d := h.admitA(tc.admission())
				var asked uint64
				for range dp.questions() {
					asked++
				}
				if asked != tc.asks {
					t.Errorf("the decision point was asked %d time(s), want %d", asked, tc.asks)
				}
				if s := h.p.Stats(); s.Asks.Made != tc.asks {
					t.Errorf("Stats().Asks.Made = %d, want %d", s.Asks.Made, tc.asks)
				}
				if tc.code == "" {
					if d.Action != core.Execute {
						t.Errorf("the call whose run reads: %s %v, want an execution", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
					}
					return
				}
				pdp := gateway.PDPType
				if tc.code == codeInvalidFieldValue {
					pdp = kernelPDP
				}
				expectBlock(t, d, verdictIndeterminate, tc.code, pdp)
			})
		}
	}
}
