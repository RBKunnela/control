package main

import (
	"fmt"
	"slices"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// follower carries the state through one export.
type follower struct {
	s *followState
	// pending maps the key of each alert raised before and not saved past to
	// its offset, and matched names those this run met again.
	pending map[string]int64
	matched map[string]bool
	alerts  []alert
	// rows are the requests that ended in this export, in the order they did.
	rows                    []row
	duplicates, conflicting int
	// at is the offset of the record being read, where an alert is raised.
	at int64
}

func newFollower(s *followState, pending map[string]int64) *follower {
	return &follower{s: s, pending: pending, matched: map[string]bool{}}
}

func (f *follower) raise(a alert) {
	k := a.key()
	if _, raised := f.pending[k]; raised {
		f.matched[k] = true
		return
	}
	f.alerts = append(f.alerts, a)
}

// take reads the export's events and gaps in the file's order, then moves
// the cursor and carries forward the pending alerts it has not reached.
func (f *follower) take(x *export) {
	gaps := x.gapRecords
	tail := false
	for _, e := range x.events {
		for len(gaps) > 0 && gaps[0].offset < e.offset {
			tail = f.gap(gaps[0]) || tail
			gaps = gaps[1:]
		}
		f.event(e)
	}
	for _, g := range gaps {
		tail = f.gap(g) || tail
	}
	if !tail && x.trailer.endReached {
		f.s.tailGap = nil
	}
	if x.trailer.nextCursor != "" {
		f.s.cursor = x.trailer.nextCursor
	}
	if x.header.source != "" {
		f.s.source = x.header.source
	}
	f.carry()
}

// carry keeps the pending alerts this run did not meet again and the cursor
// has not passed, so a later run that reaches them does not raise them.
func (f *follower) carry() {
	reached := cursorOffset(f.s.cursor)
	f.s.carried = map[string]int64{}
	for k, offset := range f.pending {
		if !f.matched[k] && offset >= reached {
			f.s.carried[k] = offset
		}
	}
}

// gap raises a gap record's alert. The gap after the last newline has no
// cursor and stands in every export until a writer ends the line, so it is
// raised once while it stays where it was. It reports whether g was that gap.
func (f *follower) gap(g gapRecord) bool {
	f.at = g.offset
	if g.cursor != "" {
		f.raise(gapAlertOf(g))
		return false
	}
	if t := f.s.tailGap; t != nil && t.offset == g.offset && t.reason == g.reason {
		return true
	}
	f.raise(gapAlertOf(g))
	if slices.Contains(gapReasons, g.reason) {
		f.s.tailGap = &gapRecord{offset: g.offset, reason: g.reason}
	}
	return true
}

func noted(a alert, note string) alert {
	a.Note = note
	return a
}

// event takes one event: one holding a value over the bounds is not kept, a
// line seen before is dropped, one id with another line is a conflict, and
// anything else moves its request on and raises what it calls for.
func (f *follower) event(e *event) {
	f.at = e.offset
	ev := e.ev
	k := requestKey{ev.GetTenantId(), ev.GetProjectId(), ev.GetRequestId()}
	id := ev.GetEventId()
	switch {
	case oversize(ev):
		f.tooLong(k, e)
		return
	case e.conflicting:
		f.raise(noted(eventAlert(codeConflict, e), fmt.Sprintf("event %s is held twice with different content in this export", safe(id))))
		return
	case k.tenant == "" || k.project == "" || k.request == "":
		f.eventAlerts(nil, e)
		f.raise(noted(eventAlert(codeUnknown, e), "an event names no tenant, project or request"))
		return
	case id == "":
		f.noID(k, e)
		return
	}
	ek := eventKey{k.tenant, k.project, id}
	hash := lineHash(e.raw)
	if first, seen := f.s.seen[ek]; seen {
		if first == hash {
			f.duplicates++
			return
		}
		f.conflicting++
		f.raise(noted(eventAlert(codeConflict, e), fmt.Sprintf("event %s was read before with other content", safe(id))))
		return
	}
	f.s.addToWindow(seenEvent{key: ek, request: k.request, hash: hash})
	if o := f.s.open[k]; o != nil {
		f.next(o, e)
		return
	}
	if c := f.s.closed[k]; c != nil {
		f.eventAlerts(&decisionFacts{id: c.kernel}, e)
		f.afterEnd(c, k, e)
		return
	}
	f.start(k, e)
}

// modeDefect holds an event after the end to the request's mode, as the walk
// holds every event of a request. A mode the state does not hold cannot be
// compared, so the event is not taken.
func (c *closedRequest) modeDefect(id string, mode controlv1.EnforcementMode) string {
	if c.mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
		return fmt.Sprintf("event %s follows the end of a request whose enforcement mode the state does not hold", id)
	}
	w := walker{mode: c.mode}
	return w.modeDefect(id, mode)
}

// runDefect holds an event after the end to the request's run, as the walk
// holds every event of a request. A run the state does not hold cannot be
// compared, so the event is not taken.
func (c *closedRequest) runDefect(ev *controlv1.Event) string {
	if !c.runKnown {
		return fmt.Sprintf("event %s follows the end of a request whose run the state does not hold", safe(ev.GetEventId()))
	}
	return runDefect(ev, c.run)
}

func annotates(kind controlv1.EventKind) bool {
	s, ok := steps[kind]
	return ok && s.to == unchanged && follows(atEnded, s.from)
}

// eventAlerts raises what one event calls for, whatever its request's chain
// says: an INDETERMINATE, a block with a decision other than the kernel's,
// an approval that expired. A policy DENY is the kernel's own block, and
// raises nothing. kernel is the kernel's decision as far as it is known. A
// value over the bounds is left out, and the alert says so.
func (f *follower) eventAlerts(kernel *decisionFacts, e *event) {
	ev := e.ev
	cut := ""
	if oversize(ev) {
		cut = cutNote
	}
	d := ev.GetDecision()
	own := boundedFacts(d)
	switch ev.GetKind() {
	case controlv1.EventKind_EVENT_KIND_POLICY_DECIDED:
		if d.GetVerdict() == controlv1.Verdict_VERDICT_INDETERMINATE {
			a := noted(eventAlert(codeUndecided, e), cut)
			a.Verdict, a.Reasons = own.verdict, own.codes
			f.raise(a)
		}
	case controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED:
		cell := blockCell(kernel, own)
		if d == nil || cell == "=" {
			return
		}
		a := noted(eventAlert(codePlaneBlock, e), cut)
		if kernel != nil {
			a.Verdict, a.Reasons = kernel.verdict, kernel.codes
		}
		a.Block = cell
		f.raise(a)
		if d.GetVerdict() == controlv1.Verdict_VERDICT_INDETERMINATE {
			b := noted(eventAlert(codeUndecided, e), cut)
			b.Verdict, b.Reasons, b.Block = own.verdict, own.codes, cell
			f.raise(b)
		}
	case controlv1.EventKind_EVENT_KIND_APPROVAL_EXPIRED:
		f.raise(noted(eventAlert(codeExpired, e), cut))
	}
}

// bound drops the oldest open requests past maxOpen, with an alert where the
// request past the bound opened. A dropped request is not remembered as
// ended, so its next event reads as broken.
func (f *follower) bound() {
	for len(f.s.open) > maxOpen {
		q := f.s.queue[0]
		f.s.queue = f.s.queue[1:]
		o := f.s.open[q.key]
		if o == nil || o.firstOffset != q.firstOffset {
			continue
		}
		delete(f.s.open, q.key)
		at := f.at
		f.raise(alert{V: alertLineVersion, Alert: codeOpenBound, Tenant: o.key.tenant, Project: o.key.project, Request: o.key.request,
			Run: o.desc.run, Offset: &at,
			Note: fmt.Sprintf("more than %d requests are open: the oldest is no longer followed, and its later events read as broken", maxOpen)})
	}
}

// addToWindow keeps an event among the newest windowSize, and forgets the
// oldest past it with the ended request whose last event it was.
func (s *followState) addToWindow(e seenEvent) {
	s.seen[e.key] = e.hash
	s.window = append(s.window, e)
	for len(s.window) > windowSize {
		old := s.window[0]
		s.window = s.window[1:]
		delete(s.seen, old.key)
		k := requestKey{old.key.tenant, old.key.project, old.request}
		if c := s.closed[k]; c != nil && c.tail == old.key.id {
			delete(s.closed, k)
		}
	}
}
