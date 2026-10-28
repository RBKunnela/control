// Scope tests: what every event of one trail shares beside its links, and the
// identifiers an event of a given kind has to carry. Like the link tests they
// damage a trail the Builder wrote, so every field under test starts out as the
// package writes it and exactly one thing changes.
package evidence_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
)

// Two requests that ran. Between them they hold every kind that has to name an
// execution. Functions rather than variables, as declaredKinds is.
func ranToCompletion() []controlv1.EventKind {
	return []controlv1.EventKind{proposed, decided, started, completed}
}

func ranAndFailed() []controlv1.EventKind {
	return []controlv1.EventKind{proposed, decided, started, failed}
}

// A trail is one request's, and request_id is unique only within a project
// (action_envelope.proto), so a request id alone does not name one request. An
// exporter that scoped a trail by its first event would otherwise export
// another tenant's events under the first one's name.
//
// Each row names the event and the field the refusal has to blame. A test that
// asked only for ErrChainBroken would pass on a refusal some other rule made,
// which is how a rule that never fires looks enforced.
func TestValidateChainRefusesAnEventFromAnotherScope(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kinds  []controlv1.EventKind
		damage func(e []*controlv1.Event)
		names  []string
	}{
		{
			name: "an event belongs to another project", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[2].ProjectId = "proj-2" },
			names:  []string{"event 2", "project"},
		},
		{
			name: "the last event belongs to another project", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[3].ProjectId = "proj-2" },
			names:  []string{"event 3", "project"},
		},
		{
			name: "an event belongs to another tenant", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[1].TenantId = "tenant-2" },
			names:  []string{"event 1", "tenant"},
		},
		{
			// The scope is read from event 0, so the event blamed is the first
			// one that disagrees with it.
			name: "event 0 is the one that differs", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[0].TenantId = "tenant-2" },
			names:  []string{"event 1", "tenant"},
		},
		// The three rows the equality rule cannot reach on its own: when no
		// event carries the value, every event equals event 0.
		{
			name: "no event carries a request id", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) {
				for _, event := range e {
					event.RequestId = ""
				}
			},
			names: []string{"event 0", "request_id"},
		},
		{
			name: "no event carries a project id", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) {
				for _, event := range e {
					event.ProjectId = ""
				}
			},
			names: []string{"event 0", "project_id"},
		},
		{
			name: "no event carries a tenant id", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) {
				for _, event := range e {
					event.TenantId = ""
				}
			},
			names: []string{"event 0", "tenant_id"},
		},
		// The mode is each event's own and not part of the scope, so event 0 has
		// no special place here.
		{
			name: "an event names no enforcement mode", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) {
				e[2].EnforcementMode = controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED
			},
			names: []string{"event 2", "enforcement mode"},
		},
		{
			name: "the first event names no enforcement mode", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) {
				e[0].EnforcementMode = controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED
			},
			names: []string{"event 0", "enforcement mode"},
		},
		{
			name: "ACTION_STARTED names no execution", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[2].ExecutionId = "" },
			names:  []string{"event 2", "execution"},
		},
		{
			name: "ACTION_COMPLETED names no execution", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[3].ExecutionId = "" },
			names:  []string{"event 3", "execution"},
		},
		{
			name: "ACTION_FAILED names no execution", kinds: ranAndFailed(),
			damage: func(e []*controlv1.Event) { e[3].ExecutionId = "" },
			names:  []string{"event 3", "execution"},
		},
		{
			name: "ACTION_COMPLETED names another execution", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[3].ExecutionId = "exec-2" },
			names:  []string{"event 3", "execution"},
		},
		{
			name: "ACTION_FAILED names another execution", kinds: ranAndFailed(),
			damage: func(e []*controlv1.Event) { e[3].ExecutionId = "exec-2" },
			names:  []string{"event 3", "execution"},
		},
		{
			// The mismatch is found where the action closes, whichever side
			// of it was changed.
			name: "ACTION_STARTED names another execution", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[2].ExecutionId = "exec-2" },
			names:  []string{"event 3", "execution"},
		},
		{
			// A finding keeps the state, so the comparison reaches across it.
			name: "another execution after a finding", kinds: []controlv1.EventKind{
				proposed, decided, started, found, completed,
			},
			damage: func(e []*controlv1.Event) { e[4].ExecutionId = "exec-2" },
			names:  []string{"event 4", "execution"},
		},
		// A later event that carries nothing is refused only because nothing
		// differs from event 0's value. A guard that skipped an empty value
		// would let an event that names no tenant join tenant-1's trail.
		{
			name: "the last event carries no tenant", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[3].TenantId = "" },
			names:  []string{"event 3", "tenant"},
		},
		{
			name: "an event in the middle carries no request id", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[2].RequestId = "" },
			names:  []string{"event 2", "request"},
		},
		// A plane stamps one run on a whole request, so the event that names
		// another run, or none where event 0 names one, is the one blamed.
		{
			name: "the last event belongs to another run", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[3].RunId = "run-2" },
			names:  []string{"event 3", `run "run-2"`, `"run-1"`},
		},
		{
			name: "an event in the middle carries no run", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[2].RunId = "" },
			names:  []string{"event 2", `run ""`, `"run-1"`},
		},
		// The comparison is byte for byte. It folds no case, normalizes nothing
		// and skips nothing a reader cannot see, so "Tenant-A" and "tenant-a"
		// are two tenants. Each value is made from the one the trail carries,
		// and the runes are built from their numbers, so this file holds none
		// raw.
		{
			name: "the last tenant differs only by case", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[3].TenantId = strings.ToUpper(e[3].GetTenantId()) },
			names:  []string{"event 3", "tenant"},
		},
		{
			name: "the last tenant differs only by a zero width space", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) { e[3].TenantId += string(rune(0x200b)) },
			names:  []string{"event 3", "tenant"},
		},
		{
			name: "the last project is the NFD spelling of the others' NFC", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) {
				for _, event := range e {
					event.ProjectId = "caf" + string(rune(0xe9))
				}
				e[3].ProjectId = "cafe" + string(rune(0x301))
			},
			names: []string{"event 3", "project"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := trail(t, tc.kinds...)
			// Control: the trail has to be valid before it is damaged, or the
			// assertion below would pass on something else.
			if err := evidence.ValidateChain(events); err != nil {
				t.Fatalf("the undamaged trail is already refused: %v", err)
			}
			tc.damage(events)

			err := evidence.ValidateChain(events)
			if !errors.Is(err, evidence.ErrChainBroken) {
				t.Fatalf("ValidateChain: got %v, want ErrChainBroken", err)
			}
			if errors.Is(err, evidence.ErrChainIndeterminate) {
				t.Errorf("ValidateChain: got %v, want a definite refusal", err)
			}
			for _, want := range tc.names {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("ValidateChain: got %v, want it to name %q", err, want)
				}
			}
		})
	}
}

// The control for the execution rows above: an execution id is asked of the
// kinds that record something running and of no other, so a request that was
// blocked carries none and is well formed.
func TestValidateChainAsksForAnExecutionOnlyWhereSomethingRan(t *testing.T) {
	events := trail(t, proposed, decided, requested, expired, blocked)
	for i, event := range events {
		if event.GetExecutionId() != "" {
			t.Fatalf("event %d carries execution_id %q, so this case no longer tests what it says",
				i, event.GetExecutionId())
		}
	}
	if err := evidence.ValidateChain(events); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
}

// Which declared mode an event names is the plane's business, not the
// trail's, so every one of them is accepted on any event.
func TestValidateChainAcceptsEveryDeclaredMode(t *testing.T) {
	for _, mode := range declaredModes() {
		t.Run(mode.String(), func(t *testing.T) {
			events := trail(t, ranToCompletion()...)
			events[1].EnforcementMode = mode
			if err := evidence.ValidateChain(events); err != nil {
				t.Errorf("ValidateChain: %v", err)
			}
		})
	}
}

// A mode number this version does not declare is what a trail from a later
// minor version may carry. common.proto makes an undeclared enum number
// INDETERMINATE for a receiver rather than an error, and event.proto does the
// same for a kind, so the answer is the undetermined one: this reader cannot
// tell what authority the plane exercised, and the producer may just be newer.
// It is never nil.
func TestValidateChainIsIndeterminateForAModeItCannotName(t *testing.T) {
	// One past the highest declared mode is the boundary: without the rule it
	// is the first number that would pass.
	past := controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN + 1
	if _, declared := controlv1.EnforcementMode_name[int32(past)]; declared {
		t.Fatalf("the contract now declares mode %d; move this boundary", int32(past))
	}

	// On the first event, on one inside the trail and on the last. A check that
	// skipped either end would read that trail as well formed, which is the
	// reading this rule exists to refuse.
	last := len(ranToCompletion()) - 1
	for _, mode := range []controlv1.EnforcementMode{past, -1} {
		for _, at := range []int{0, 1, last} {
			t.Run(fmt.Sprintf("%s on event %d", mode, at), func(t *testing.T) {
				events := trail(t, ranToCompletion()...)
				events[at].EnforcementMode = mode

				err := evidence.ValidateChain(events)
				if !errors.Is(err, evidence.ErrChainIndeterminate) {
					t.Fatalf("ValidateChain: got %v, want ErrChainIndeterminate", err)
				}
				if errors.Is(err, evidence.ErrChainBroken) {
					t.Errorf("ValidateChain: got %v, which also reads as a defect in the trail", err)
				}
				if want := fmt.Sprintf("event %d", at); !strings.Contains(err.Error(), want) {
					t.Errorf("ValidateChain: got %v, want it to name %s", err, want)
				}
			})
		}
	}
}

// The undetermined answer never hides a definite one, wherever the definite
// defect sits relative to the mode this version cannot name.
func TestValidateChainDoesNotLaunderADefectBehindAModeItCannotName(t *testing.T) {
	const undeclared = controlv1.EnforcementMode(99)
	for _, tc := range []struct {
		name   string
		kinds  []controlv1.EventKind
		damage func(e []*controlv1.Event)
		names  string
	}{
		{
			name: "a scope defect after it", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) {
				e[1].EnforcementMode = undeclared
				e[3].ProjectId = "proj-2"
			},
			names: "event 3",
		},
		{
			name: "a scope defect before it", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) {
				e[1].TenantId = "tenant-2"
				e[3].EnforcementMode = undeclared
			},
			names: "event 1",
		},
		{
			name: "an order defect", kinds: []controlv1.EventKind{proposed, decided, blocked, started},
			damage: func(e []*controlv1.Event) { e[1].EnforcementMode = undeclared },
			names:  "event 3",
		},
		{
			name: "an execution that does not match", kinds: ranToCompletion(),
			damage: func(e []*controlv1.Event) {
				e[0].EnforcementMode = undeclared
				e[3].ExecutionId = "exec-2"
			},
			names: "event 3",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := trail(t, tc.kinds...)
			tc.damage(events)

			err := evidence.ValidateChain(events)
			if !errors.Is(err, evidence.ErrChainBroken) {
				t.Fatalf("ValidateChain: got %v, want ErrChainBroken", err)
			}
			if errors.Is(err, evidence.ErrChainIndeterminate) {
				t.Errorf("ValidateChain: got %v, want the defect reported on its own", err)
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("ValidateChain: got %v, want it to name %s", err, tc.names)
			}
		})
	}
}

// Whether the execution that closed is the one that started is a step of the
// walk, so after a kind this version cannot place it is part of what stays
// undetermined: a later version may add a kind after which a new execution is
// legitimate, and refusing that trail would blame a newer producer. Whether an
// event of a running kind names an execution at all is not a step: one that
// names none says nothing about what ran, whatever came before it. Each of the
// three kinds is pinned here on its own. In a trail the walk can place, a
// closing event that names no execution is refused by the comparison as well,
// which would hide a rule that dropped one of the kinds.
func TestValidateChainExecutionRulesAroundAKindItCannotPlace(t *testing.T) {
	ranAfter := []controlv1.EventKind{proposed, decided, started, fromTheFuture, completed}
	failedAfter := []controlv1.EventKind{proposed, decided, started, fromTheFuture, failed}
	startedAfter := []controlv1.EventKind{proposed, decided, fromTheFuture, started}
	for _, tc := range []struct {
		name      string
		kinds     []controlv1.EventKind
		execution string // what the last event names
		definite  bool
		names     string
	}{
		{"ACTION_COMPLETED naming another execution stays undetermined", ranAfter, "exec-2", false, "event 3"},
		{"ACTION_FAILED naming another execution stays undetermined", failedAfter, "exec-2", false, "event 3"},
		{"ACTION_COMPLETED naming no execution is a defect", ranAfter, "", true, "event 4"},
		{"ACTION_FAILED naming no execution is a defect", failedAfter, "", true, "event 4"},
		{"ACTION_STARTED naming no execution is a defect", startedAfter, "", true, "event 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := trailOfKinds(t, tc.kinds...)
			events[len(events)-1].ExecutionId = tc.execution

			want, other := evidence.ErrChainIndeterminate, evidence.ErrChainBroken
			if tc.definite {
				want, other = other, want
			}
			err := evidence.ValidateChain(events)
			if !errors.Is(err, want) {
				t.Fatalf("ValidateChain: got %v, want %v", err, want)
			}
			if errors.Is(err, other) {
				t.Errorf("ValidateChain: got %v, which also reads as %v", err, other)
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("ValidateChain: got %v, want it to name %s", err, tc.names)
			}
		})
	}
}

// The rules that hold whatever an event's kind is hold on either side of a kind
// this version cannot place. A missing mode and a second scope are defects
// whatever that kind turns out to mean, so one added line of kind 99 must not
// turn either into "this reader cannot tell".
func TestValidateChainDoesNotLaunderAScopeOrModeDefectBehindAKindItCannotPlace(t *testing.T) {
	kinds := []controlv1.EventKind{proposed, decided, fromTheFuture, started, completed}
	unspecified := controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED
	for _, tc := range []struct {
		name   string
		damage func(e []*controlv1.Event)
		names  []string
	}{
		{"no mode after it", func(e []*controlv1.Event) { e[4].EnforcementMode = unspecified },
			[]string{"event 4", "enforcement mode"}},
		{"no mode before it", func(e []*controlv1.Event) { e[1].EnforcementMode = unspecified },
			[]string{"event 1", "enforcement mode"}},
		{"another tenant after it", func(e []*controlv1.Event) { e[4].TenantId = "tenant-2" },
			[]string{"event 4", "tenant"}},
		{"another project before it", func(e []*controlv1.Event) { e[1].ProjectId = "proj-2" },
			[]string{"event 1", "project"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := trailOfKinds(t, kinds...)
			// Control: undamaged, the trail is undetermined and not broken, so a
			// definite refusal below comes from the damage.
			if err := evidence.ValidateChain(events); !errors.Is(err, evidence.ErrChainIndeterminate) {
				t.Fatalf("the undamaged trail: got %v, want ErrChainIndeterminate", err)
			}
			tc.damage(events)

			err := evidence.ValidateChain(events)
			if !errors.Is(err, evidence.ErrChainBroken) {
				t.Fatalf("ValidateChain: got %v, want ErrChainBroken", err)
			}
			if errors.Is(err, evidence.ErrChainIndeterminate) {
				t.Errorf("ValidateChain: got %v, want the defect reported on its own", err)
			}
			for _, want := range tc.names {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("ValidateChain: got %v, want it to name %q", err, want)
				}
			}
		})
	}
}

// The read route end to end, over bytes a producer from somewhere else wrote:
// two projects, two tenants, then two events that carry neither, nor a mode,
// nor an execution. Every line decodes, so the only thing between these lines
// and a reader that scopes the trail by its first event is ValidateChain.
func TestTheReadRouteRefusesATrailThatMixesScopes(t *testing.T) {
	const (
		head    = `{"eventId":"e0","kind":"EVENT_KIND_ACTION_PROPOSED","requestId":"req-1",`
		decided = `{"eventId":"e1","prevEventId":"e0","kind":"EVENT_KIND_POLICY_DECIDED","requestId":"req-1",`
		started = `{"eventId":"e2","prevEventId":"e1","kind":"EVENT_KIND_ACTION_STARTED","requestId":"req-1"`
		closed  = `{"eventId":"e3","prevEventId":"e2","kind":"EVENT_KIND_ACTION_COMPLETED","requestId":"req-1"`
		scopeA  = `"projectId":"proj-A","tenantId":"tenant-A","enforcementMode":"ENFORCEMENT_MODE_ENFORCE"`
		scopeB  = `"projectId":"proj-B","tenantId":"tenant-B","enforcementMode":"ENFORCEMENT_MODE_OBSERVE"`
	)
	mixed := head + scopeA + "}\n" + decided + scopeB + "}\n" + started + "}\n" + closed + "}\n"
	// The control: the same four lines in one scope, each with what its kind
	// has to carry. Without it the case above passes on a read route that
	// refuses every trail.
	whole := head + scopeA + "}\n" + decided + scopeA + "}\n" +
		started + `,` + scopeA + `,"executionId":"exec-1"}` + "\n" +
		closed + `,` + scopeA + `,"executionId":"exec-1"}` + "\n"

	read := func(t *testing.T, input string) error {
		t.Helper()
		events, err := evidence.DecodeJSONL(strings.NewReader(input), 4)
		if err != nil {
			t.Fatalf("DecodeJSONL: %v", err)
		}
		return evidence.ValidateChain(events)
	}

	if err := read(t, whole); err != nil {
		t.Fatalf("the trail in one scope is refused: %v", err)
	}
	err := read(t, mixed)
	if !errors.Is(err, evidence.ErrChainBroken) {
		t.Fatalf("ValidateChain: got %v, want ErrChainBroken", err)
	}
	if !strings.Contains(err.Error(), "event 1") || !strings.Contains(err.Error(), "project") {
		t.Errorf("ValidateChain: got %v, want it to name event 1 and its project", err)
	}
}

// The trails the Builder writes when an action closes, made, written and read
// back the way a reader meets them. The Builder stamps the execution Started
// was handed on the event that closes it, so neither a closing call with
// nothing to record, the natural one for a crash or a timeout, nor a result
// that names an execution of its own makes the trail one ValidateChain
// refuses. The result's own id stays in the payload, which ValidateChain does
// not read. A Builder that lifted the result's id would make every row here
// refused when read.
func TestValidateChainAcceptsEveryWayTheBuilderClosesAnAction(t *testing.T) {
	other := &controlv1.ActionResult{ExecutionId: "exec-2"}
	for _, tc := range []struct {
		name   string
		close  func(b *evidence.Builder) *controlv1.Event
		result string // the execution the payload names, "" when there is none
	}{
		{"Completed with no result", func(b *evidence.Builder) *controlv1.Event { return b.Completed(nil) }, ""},
		{"Failed with no result", func(b *evidence.Builder) *controlv1.Event { return b.Failed(nil) }, ""},
		{"Completed, the result naming another execution",
			func(b *evidence.Builder) *controlv1.Event { return b.Completed(other) }, "exec-2"},
		{"Failed, the result naming another execution",
			func(b *evidence.Builder) *controlv1.Event { return b.Failed(other) }, "exec-2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := trailBuilder(t, "req-1", "evt")
			made := []*controlv1.Event{b.Proposed(nil), b.Decided(nil), b.Started("exec-1"), tc.close(b)}

			read, err := evidence.DecodeJSONL(bytes.NewReader(encode(t, made)), len(made))
			if err != nil {
				t.Fatalf("DecodeJSONL: %v", err)
			}
			if err := evidence.ValidateChain(read); err != nil {
				t.Fatalf("ValidateChain: %v", err)
			}
			closing := read[len(read)-1]
			if got := closing.GetExecutionId(); got != "exec-1" {
				t.Errorf("the closing event names execution %q, want %q, the one Started was handed", got, "exec-1")
			}
			if got := closing.GetResult().GetExecutionId(); got != tc.result {
				t.Errorf("the result names execution %q, want %q as its producer wrote it", got, tc.result)
			}
		})
	}
}

// The other side of the rule: a closing call before any Started has no
// execution to stamp. It stamps none rather than lifting the result's, and
// ValidateChain refuses the trail, naming the event and what it lacks.
func TestABuilderThatStartedNothingClosesNoExecution(t *testing.T) {
	b := trailBuilder(t, "req-1", "evt")
	events := []*controlv1.Event{
		b.Proposed(nil), b.Decided(nil), b.Completed(&controlv1.ActionResult{ExecutionId: "exec-2"}),
	}
	if got := events[2].GetExecutionId(); got != "" {
		t.Fatalf("the closing event names execution %q, lifted from its result; want none", got)
	}
	err := evidence.ValidateChain(events)
	if !errors.Is(err, evidence.ErrChainBroken) {
		t.Fatalf("ValidateChain: got %v, want ErrChainBroken", err)
	}
	for _, want := range []string{"event 2", "execution"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateChain: got %v, want it to name %q", err, want)
		}
	}
}
