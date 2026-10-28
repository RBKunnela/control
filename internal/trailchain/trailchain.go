// Package trailchain checks that a sequence of events is one coherent account
// of one request. It holds no writer and no reader, so a binary that judges a
// trail need not link the package that writes one; evidence.ValidateChain
// documents the order it accepts.
package trailchain

import (
	"errors"
	"fmt"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

var (
	// ErrBroken reports a definite defect: a link that does not join, an event
	// belonging to another request, project, tenant or run, an identifier or a mode
	// an event has to carry and does not, an identifier longer than the
	// contract lets a string be, or a step the order does not allow.
	ErrBroken = errors.New("evidence: chain broken")

	// ErrIndeterminate reports that the sequence carries an event kind or an
	// enforcement mode this version does not declare, so the trail could not be
	// read either way. It never hides ErrBroken: a defect that holds whatever
	// the undeclared value turns out to mean is reported as broken.
	ErrIndeterminate = errors.New("evidence: chain indeterminate")
)

// Validate reports whether events are one coherent account of one request: its
// links, its scope, its identifiers and their bounds, its modes and its order.
// A nil result says the trail is well formed and nothing about whether it is
// true.
func Validate(events []*controlv1.Event) error {
	if len(events) == 0 {
		return fmt.Errorf("%w: no events", ErrBroken)
	}
	if err := checkLinks(events); err != nil {
		return err
	}
	if err := checkOrder(events); err != nil {
		return err
	}
	return checkModes(events)
}

// checkLinks holds the rules that do not depend on an event's kind, so they
// still apply to a sequence whose order this version cannot establish: the
// length of every identifier, the scope every event shares, the mode each one
// names, and the links.
func checkLinks(events []*controlv1.Event) error {
	scope, err := scopeOf(events[0])
	if err != nil {
		return err
	}
	seen := make(map[string]int, len(events))
	prev := ""
	for i, event := range events {
		if event == nil {
			return fmt.Errorf("%w: event %d is nil", ErrBroken, i)
		}
		if err := lengthDefect(i, event); err != nil {
			return err
		}
		if err := scope.holds(i, event); err != nil {
			return err
		}
		if err := modeDefect(i, event); err != nil {
			return err
		}
		if event.GetEventId() == "" {
			// Without an id the link below cannot be read: an empty id and an
			// empty prev_event_id are the same bytes as the head of a trail.
			return fmt.Errorf("%w: event %d carries no event_id", ErrBroken, i)
		}
		if first, dup := seen[event.GetEventId()]; dup {
			// A repeating id generator makes every link join, including an
			// event to itself, so the link check alone would report nothing.
			return fmt.Errorf("%w: events %d and %d share event_id %s",
				ErrBroken, first, i, quoteID(event.GetEventId()))
		}
		seen[event.GetEventId()] = i
		if event.GetPrevEventId() != prev {
			return fmt.Errorf("%w: event %d links to %s, want %s",
				ErrBroken, i, quoteID(event.GetPrevEventId()), quoteID(prev))
		}
		prev = event.GetEventId()
	}
	return nil
}

// checkOrder walks the accepted order.
//
// A kind it cannot place makes every state after that event a guess, so it
// stops walking the order there and holds the undetermined reading. It does not
// stop reading the sequence: the defects that hold whatever that kind turns out
// to mean are still reported, and reported as definite. Returning at the first
// unplaceable kind instead would hand anyone able to add a line to an evidence
// file a way to turn "this trail is broken" into "this reader cannot tell".
func checkOrder(events []*controlv1.Event) error {
	state := chainStart
	proposals := 0
	startedAs := "" // the execution ACTION_STARTED named, once the walk has taken it
	var unplaceable error

	for i, event := range events {
		kind := event.GetKind()
		if kind == controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED {
			proposals++
		}
		if err := definiteDefect(i, event, proposals); err != nil {
			return err
		}
		if unplaceable != nil {
			continue
		}
		next, result := state.step(kind)
		switch result {
		case stepAllowed:
			ran, err := execution(i, event, startedAs)
			if err != nil {
				return err
			}
			state, startedAs = next, ran
		case stepUnplaceable:
			unplaceable = fmt.Errorf("%w: event %d has kind %d, which this version cannot place",
				ErrIndeterminate, i, int32(kind))
		case stepRefused:
			return fmt.Errorf("%w: event %d is %s, which cannot follow %s",
				ErrBroken, i, kind, state)
		}
	}

	if unplaceable != nil {
		return unplaceable
	}
	if proposals == 0 {
		// Reached only when every kind was placed, because a later version may
		// well propose an action with a kind this one has never heard of.
		return fmt.Errorf("%w: nothing proposes an action, so the sequence accounts for no request",
			ErrBroken)
	}
	return nil
}

// definiteDefect reports the defects that do not depend on where the walk has
// got to, so they are still reported after a kind this version could not place.
// All three hold under any order a later version declares: an event that names
// no kind says nothing about itself wherever it sits; one request_id is one
// proposed action, so a second proposal is two requests in one file rather than
// a step in either; and a record that something ran which does not say what ran
// cannot be joined to whatever ran it.
func definiteDefect(i int, event *controlv1.Event, proposals int) error {
	kind := event.GetKind()
	switch {
	case kind == controlv1.EventKind_EVENT_KIND_UNSPECIFIED:
		// Declared, and it says nothing about the event carrying it. That is a
		// defect in the record rather than a kind from a later version.
		return fmt.Errorf("%w: event %d has no kind", ErrBroken, i)
	case kind == controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED && proposals > 1:
		return fmt.Errorf("%w: event %d proposes an action this sequence already proposed",
			ErrBroken, i)
	case namesExecution(kind) && event.GetExecutionId() == "":
		return fmt.Errorf("%w: event %d is %s and names no execution", ErrBroken, i, kind)
	}
	return nil
}
