package gateway_test

import (
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

const (
	pauseRunA      = `{"kind":"run","id":"run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	pauseRoot1     = `{"kind":"run","id":"run-11111111111111111111111111111111"}`
	pauseAgent1    = `{"kind":"agent","id":"agent-1"}`
	pauseAgent2    = `{"kind":"agent","id":"agent-2"}`
	pausePrincipal = `{"kind":"principal","id":"user-1"}`
	pauseOther     = `{"kind":"principal","id":"user-2"}`
)

// scopedCall is one call of the overlapping-runs cases: the opened run it is
// made under, and what its run context and tags claim.
type scopedCall struct {
	run      *gateway.OpenedRun
	claimRun string
	paused   bool
}

// claimingRun is a read whose client-sent run context and client tag name
// claim, which the plane never vouches for.
func claimingRun(requestID, claim string) *controlv1.ActionEnvelope {
	env := tool(readOf(requestID, "user-1"))
	env.Context.RunId = claim
	env.Context.Tags = append(env.Context.Tags, "mcp.client="+claim+"/1.0")
	return env
}

// TestAPauseScopeNamesTheIdentityThePlaneVouchesFor: two runs of one agent
// and principal run at once under one root, and a third under another root.
// A run entry blocks exactly the run it names, or every run of the root it
// names; an agent or a principal entry blocks every run of the identity it
// names and none of another's. What the client wrote in its run context or
// its client tag neither aims a pause nor slips past one.
func TestAPauseScopeNamesTheIdentityThePlaneVouchesFor(t *testing.T) {
	runA, runB, runC := opened("run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "run-11111111111111111111111111111111"), opened("run-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "run-11111111111111111111111111111111"), opened("run-cccccccccccccccccccccccccccccccc", "run-22222222222222222222222222222222")
	for _, c := range []struct {
		name  string
		scope string
		calls []scopedCall
	}{
		{"a run entry", pauseRunA, []scopedCall{{runA, "", true}, {runB, "", false}, {runC, "", false}}},
		{"a run entry and a context naming the paused run", pauseRunA, []scopedCall{{runB, "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false}, {runC, "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false}}},
		{"a run entry and a context naming another run", pauseRunA, []scopedCall{{runA, "run-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", true}, {runA, "", true}}},
		{"a root's entry", pauseRoot1, []scopedCall{{runA, "", true}, {runB, "", true}, {runC, "run-11111111111111111111111111111111", false}}},
		{"the listener's agent", pauseAgent1, []scopedCall{{runA, "", true}, {runB, "", true}, {runC, "", true}}},
		{"another agent", pauseAgent2, []scopedCall{{runA, "agent-2", false}, {runB, "", false}}},
		{"the listener's principal", pausePrincipal, []scopedCall{{runA, "", true}, {runB, "", true}}},
		{"another principal", pauseOther, []scopedCall{{runA, "user-2", false}, {runB, "", false}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowReads), withRuns(newRuns("run-11111111111111111111111111111111", "run-22222222222222222222222222222222")))
			h.pause.set(paused(t, c.scope))
			for i, call := range c.calls {
				requestID := c.name + "/" + string(rune('a'+i))
				d := h.admitA(under(admission(claimingRun(requestID, call.claimRun), []byte(`{}`)), call.run))
				switch {
				case call.paused:
					expectPlaneBlock(t, h, d, verdictDeny, codePaused)
				case d.Action != core.Execute:
					t.Errorf("run %s claiming %q under %s: Action = %d, codes %v; want it run",
						call.run.ID, call.claimRun, c.scope, d.Action, d.Decision.GetReasonCodes())
				}
			}
		})
	}
}

// TestARunEntryPausesACallUnderNoOpenedRun: a field the call does not carry
// matches, so a local run's call, which no opened run vouches for, is paused
// by every run entry, whatever its run context claims; an entry naming
// another agent leaves it running.
func TestARunEntryPausesACallUnderNoOpenedRun(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads))
	h.pause.set(paused(t, `{"kind":"run","id":"run-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`))
	expectPlaneBlock(t, h, h.admitA(admission(claimingRun("r-local", "run-1"), []byte(`{}`))), verdictDeny, codePaused)

	h = build(t, modeEnforce, snapshot(t, allowReads))
	h.pause.set(paused(t, pauseAgent2))
	if d := h.admitA(admission(claimingRun("r-other", "agent-2"), []byte(`{}`))); d.Action != core.Execute {
		t.Errorf("a local run's call under another agent's pause: Action = %d, codes %v", d.Action, d.Decision.GetReasonCodes())
	}
}
