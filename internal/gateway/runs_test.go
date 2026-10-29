package gateway_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

// refusingRuns is a runs directory that refuses every token and holds no
// state, so a test that reaches it by mistake cannot pass on what it said.
type refusingRuns struct{}

func (refusingRuns) Resolve(context.Context, string, gateway.RunIdentity, time.Time) (gateway.OpenedRun, error) {
	return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunUnknown}
}

func (refusingRuns) State(context.Context, string) (gateway.RunState, error) {
	return gateway.RunState{}, errors.New("no state")
}

func (refusingRuns) Raise(context.Context, string, func(gateway.RunState) gateway.RunState) error {
	return errors.New("no state")
}

func TestNewRefusesRunsOnOneSideOnly(t *testing.T) {
	presenting := enforcing
	presenting.PresentsRuns = true
	cases := map[string]func(*gateway.Config){
		"an adapter that presents runs, no runs directory": func(c *gateway.Config) {
			c.Adapter = fakeAdapter{name: testProtocol, caps: presenting}
		},
		"a runs directory, an adapter that presents none": func(c *gateway.Config) {
			c.Runs = refusingRuns{}
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			mut(&cfg)
			if p, err := gateway.New(cfg); p != nil || !errors.Is(err, gateway.ErrRunsMismatch) {
				t.Errorf("New = %v, %v; want nil, ErrRunsMismatch", p, err)
			}
		})
	}
	cfg := validConfig(t)
	cfg.Adapter = fakeAdapter{name: testProtocol, caps: presenting}
	cfg.Runs = refusingRuns{}
	if _, err := gateway.New(cfg); err != nil {
		t.Errorf("New with runs on both sides = %v, want nil", err)
	}
}

// TestARunOnAPlaneWithoutRunsIsBlocked: an admission that carries an opened
// run reaches a plane that judges none, so the run is nobody's word; the call
// is blocked before anything runs, in every mode, and mints no local run.
func TestARunOnAPlaneWithoutRunsIsBlocked(t *testing.T) {
	for _, mode := range []controlv1.EnforcementMode{modeEnforce, modeObserve} {
		t.Run(mode.String(), func(t *testing.T) {
			h := build(t, mode, snapshot(t, allowReads, allowWrites))
			a := returning(readOf("r-1", "user-1"), 0, 0)
			a.Run = &gateway.OpenedRun{ID: "run-1", Root: "run-1", Expires: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
			d := h.admitA(a)
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			if s := h.p.Stats(); s.Executed != 0 || s.Runs != 0 {
				t.Errorf("Stats: %d executed, %d runs; want 0 and 0", s.Executed, s.Runs)
			}
		})
	}
}

// TestTheRunCausesAreAClosedSet pins the refusal counter's label set: seven
// fixed values, none repeated, none empty.
func TestTheRunCausesAreAClosedSet(t *testing.T) {
	want := []gateway.RunCause{"missing", "malformed", "unknown", "identity", "closed", "expired", "unreadable"}
	got := gateway.RunCauses()
	if !slices.Equal(got, want) {
		t.Fatalf("RunCauses() = %v, want %v", got, want)
	}
	got[0] = "changed"
	if gateway.RunCauses()[0] != gateway.RunMissing {
		t.Error("RunCauses hands out its own slice")
	}
}
