package trailchain_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/trailchain"
	"github.com/guardana/control/pkg/contract"
)

const (
	proposed  = controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED
	decided   = controlv1.EventKind_EVENT_KIND_POLICY_DECIDED
	requested = controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED
	answered  = controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED
	expired   = controlv1.EventKind_EVENT_KIND_APPROVAL_EXPIRED
	started   = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
	completed = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
	blocked   = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED
	found     = controlv1.EventKind_EVENT_KIND_FINDING_RAISED
	reloaded  = controlv1.EventKind_EVENT_KIND_POLICY_RELOADED

	fromTheFuture = controlv1.EventKind(99)
)

// linked writes one trail of the given kinds by hand: ids evt-1, evt-2, ...,
// each linked to the one before, all in one scope and enforcing.
func linked(kinds ...controlv1.EventKind) []*controlv1.Event {
	events := make([]*controlv1.Event, 0, len(kinds))
	prev := ""
	for i, kind := range kinds {
		id := "evt-" + strconv.Itoa(i+1)
		event := &controlv1.Event{
			EventId: id, PrevEventId: prev, Kind: kind,
			RequestId: "req-1", ProjectId: "proj-1", TenantId: "tenant-1",
			EnforcementMode: controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		}
		if kind == started || kind == completed {
			event.ExecutionId = "exec-1"
		}
		events = append(events, event)
		prev = id
	}
	return events
}

// verdict names an answer by the one sentinel it carries, and fails on an
// answer that carries both.
func verdict(t *testing.T, err error) string {
	t.Helper()
	broken, indeterminate := errors.Is(err, trailchain.ErrBroken), errors.Is(err, trailchain.ErrIndeterminate)
	switch {
	case broken && indeterminate:
		t.Fatalf("one answer carries both sentinels: %v", err)
	case broken:
		return "broken"
	case indeterminate:
		return "indeterminate"
	case err != nil:
		t.Fatalf("an answer with neither sentinel: %v", err)
	}
	return "well formed"
}

// Sequences the evidence package's chain tests pin, with the verdicts they pin.
func TestValidateGivesThePinnedVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events []*controlv1.Event
		want   string
	}{
		{"ran to completion", linked(proposed, decided, started, completed), "well formed"},
		{"approval expired then asked again",
			linked(proposed, decided, requested, expired, requested, answered, started, completed), "well formed"},
		{"reload before anything", linked(reloaded, proposed, decided, blocked), "well formed"},
		{"in flight, awaiting an approver", linked(proposed, decided, requested), "well formed"},
		{"empty", nil, "broken"},
		{"started after an approval expired", linked(proposed, decided, requested, expired, started), "broken"},
		{"finding ahead of the proposal", linked(found, proposed, decided, blocked), "broken"},
		{"reloads alone", linked(reloaded, reloaded), "broken"},
		{"a kind it cannot place", linked(proposed, fromTheFuture, decided), "indeterminate"},
		{"a second proposal behind a kind it cannot place", linked(proposed, fromTheFuture, proposed), "broken"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := verdict(t, trailchain.Validate(tc.events)); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestValidateReadsAnUndeclaredModeAsIndeterminateAndAMissingOneAsBroken(t *testing.T) {
	for mode, want := range map[controlv1.EnforcementMode]string{
		controlv1.EnforcementMode(99):                          "indeterminate",
		controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED: "broken",
	} {
		events := linked(proposed, decided, blocked)
		events[1].EnforcementMode = mode
		if got := verdict(t, trailchain.Validate(events)); got != want {
			t.Errorf("mode %d: got %s, want %s", int32(mode), got, want)
		}
	}
}

func TestValidateBoundsAnIdentifierAtMaxStringBytes(t *testing.T) {
	for length, want := range map[int]string{
		contract.MaxStringBytes:     "well formed",
		contract.MaxStringBytes + 1: "broken",
	} {
		events := linked(proposed, decided, started, completed)
		long := strings.Repeat("x", length)
		events[2].ExecutionId, events[3].ExecutionId = long, long
		if got := verdict(t, trailchain.Validate(events)); got != want {
			t.Errorf("execution_id of %d bytes: got %s, want %s", length, got, want)
		}
	}
}

func TestARefusalQuotesAnIdentifierUpTo64Bytes(t *testing.T) {
	for length, cut := range map[int]bool{64: false, 65: true} {
		events := linked(proposed, decided)
		events[1].PrevEventId = strings.Repeat("p", length)
		message := trailchain.Validate(events).Error()
		whole := strconv.Quote(events[1].PrevEventId)
		if strings.Contains(message, whole) == cut || strings.Contains(message, "(truncated)") != cut {
			t.Errorf("a %d-byte identifier, cut %v: %q", length, cut, message)
		}
	}
}

// inRun stamps run on every event of a trail.
func inRun(run string, events []*controlv1.Event) []*controlv1.Event {
	for _, event := range events {
		event.RunId = run
	}
	return events
}

// A plane stamps one run on a whole request, so a trail whose run changes
// cannot say which run did what. A trail that names no run anywhere is an
// action taken outside a run, which evidence.IDs allows.
func TestValidateHoldsEveryEventToTheFirstEventsRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events []*controlv1.Event
		names  []string
	}{
		{"no event names a run", linked(proposed, decided, started, completed), nil},
		{"every event names one run", inRun("run-1", linked(proposed, decided, started, completed)), nil},
		{"the last event names another run",
			func() []*controlv1.Event {
				e := inRun("run-1", linked(proposed, decided, started, completed))
				e[3].RunId = "run-2"
				return e
			}(),
			[]string{"event 3", `run "run-2", not "run-1"`}},
		{"a finding after the end names another run",
			func() []*controlv1.Event {
				e := inRun("run-1", linked(proposed, decided, blocked, found))
				e[3].RunId = "run-2"
				return e
			}(),
			[]string{"event 3", `run "run-2", not "run-1"`}},
		{"only a later event names a run",
			func() []*controlv1.Event {
				e := linked(proposed, decided, started, completed)
				e[2].RunId = "run-1"
				return e
			}(),
			[]string{"event 2", `run "run-1", not ""`}},
		{"a later event names no run",
			func() []*controlv1.Event {
				e := inRun("run-1", linked(proposed, decided, started, completed))
				e[1].RunId = ""
				return e
			}(),
			[]string{"event 1", `run "", not "run-1"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := trailchain.Validate(tc.events)
			if tc.names == nil {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if got := verdict(t, err); got != "broken" {
				t.Fatalf("got %s (%v), want broken", got, err)
			}
			for _, want := range tc.names {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%q names no %s", err, want)
				}
			}
		})
	}
}

func TestValidateBoundsARunIDAtMaxStringBytes(t *testing.T) {
	for length, want := range map[int]string{
		contract.MaxStringBytes:     "well formed",
		contract.MaxStringBytes + 1: "broken",
	} {
		events := inRun(strings.Repeat("r", length), linked(proposed, decided, blocked))
		err := trailchain.Validate(events)
		if got := verdict(t, err); got != want {
			t.Errorf("run_id of %d bytes: got %s, want %s", length, got, want)
			continue
		}
		if want == "broken" && !strings.Contains(err.Error(), "run_id is") {
			t.Errorf("run_id of %d bytes: %q is not the length refusal", length, err)
		}
	}
}

func TestTheSentinelsKeepTheirText(t *testing.T) {
	if got := trailchain.ErrBroken.Error(); got != "evidence: chain broken" {
		t.Errorf("ErrBroken reads %q", got)
	}
	if got := trailchain.ErrIndeterminate.Error(); got != "evidence: chain indeterminate" {
		t.Errorf("ErrIndeterminate reads %q", got)
	}
}
