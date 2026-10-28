package main

import (
	"fmt"
)

// tooLong takes an event over the bounds: it raises the alerts it calls for
// with those values left out, is neither kept nor deduplicated, and the
// request it names, when open, ends unknown.
func (f *follower) tooLong(k requestKey, e *event) {
	var kernel *decisionFacts
	switch o, c := f.s.open[k], f.s.closed[k]; {
	case o != nil:
		kernel = o.desc.kernel
	case c != nil:
		kernel = &decisionFacts{id: c.kernel}
	}
	f.eventAlerts(kernel, e)
	if o := f.s.open[k]; o != nil {
		f.close(o, endUnknown, tooLongNote, e)
		return
	}
	f.raise(noted(eventAlert(codeUnknown, e), tooLongNote))
}

// noID takes an event that names no event_id, which cannot be deduplicated
// or linked to: its request, when open, ends unknown.
func (f *follower) noID(k requestKey, e *event) {
	const note = "an event carries no event_id"
	o := f.s.open[k]
	var kernel *decisionFacts
	if o != nil {
		kernel = o.desc.kernel
	}
	f.eventAlerts(kernel, e)
	if o != nil {
		f.close(o, endUnknown, note, e)
		return
	}
	f.raise(noted(eventAlert(codeUnknown, e), note))
}

// next takes an event of an open request, which has to follow the last one
// read.
func (f *follower) next(o *openRequest, e *event) {
	ev := e.ev
	id, prev := ev.GetEventId(), ev.GetPrevEventId()
	if prev == o.tail {
		f.step(o, e)
		return
	}
	note := fmt.Sprintf("event %s follows %s, and the request's last event read is %s", safe(id), safe(prev), safe(o.tail))
	switch {
	case prev == "":
		note = fmt.Sprintf("events %s and %s both start the request", safe(o.head), safe(id))
	case f.s.seen[eventKey{o.key.tenant, o.key.project, prev}] == "":
		note = fmt.Sprintf("event %s follows %s, which this export does not hold", safe(id), safe(prev))
	}
	o.desc.add(ev)
	o.tail, o.tailOffset = id, e.offset
	f.eventAlerts(o.desc.kernel, e)
	f.close(o, endUnknown, note, e)
}

// step walks an event that follows the request's last one.
func (f *follower) step(o *openRequest, e *event) {
	ev := e.ev
	o.desc.add(ev)
	o.tail, o.tailOffset = ev.GetEventId(), e.offset
	f.eventAlerts(o.desc.kernel, e)
	if note := runDefect(ev, o.desc.run); note != "" {
		f.close(o, endUnknown, note, e)
		return
	}
	if note := o.walk.take(ev); note != "" {
		f.close(o, endUnknown, note, e)
		return
	}
	if o.walk.at == atEnded {
		f.close(o, o.walk.end, o.walk.note, e)
	}
}

// start takes the first event read of a request: one that follows nothing
// opens it, and one that follows an event not read breaks it.
func (f *follower) start(k requestKey, e *event) {
	ev := e.ev
	id := ev.GetEventId()
	o := &openRequest{key: k, firstOffset: e.offset, tailOffset: e.offset, head: id, tail: id,
		desc: description{run: ev.GetRunId()}, walk: walker{prevKind: startOfRequest, mode: ev.GetEnforcementMode(), end: endOpen}}
	if prev := ev.GetPrevEventId(); prev != "" {
		note := fmt.Sprintf("event %s follows %s, which this export does not hold", safe(id), safe(prev))
		if f.s.seen[eventKey{k.tenant, k.project, prev}] != "" {
			note = fmt.Sprintf("event %s follows %s, of a request no longer followed", safe(id), safe(prev))
		}
		o.desc.add(ev)
		f.eventAlerts(o.desc.kernel, e)
		f.close(o, endUnknown, note, e)
		return
	}
	f.s.open[k] = o
	f.s.queue = append(f.s.queue, queued{k, e.offset})
	f.step(o, e)
	f.bound()
}

// afterEnd takes an event of a request that ended: only a finding or a
// reload that follows its last event, under the request's mode, leaves it as
// it ended.
func (f *follower) afterEnd(c *closedRequest, k requestKey, e *event) {
	ev := e.ev
	id, prev := ev.GetEventId(), ev.GetPrevEventId()
	switch {
	case c.unknown:
		return
	case prev == c.tail && annotates(ev.GetKind()):
		note := c.modeDefect(safe(id), ev.GetEnforcementMode())
		if note == "" {
			note = c.runDefect(ev)
		}
		if note == "" {
			c.tail = id
			return
		}
		c.unknown = true
		f.raise(noted(eventAlert(codeUnknown, e), note))
		return
	}
	c.unknown = true
	note := fmt.Sprintf("event %s follows %s after request %s ended at %s", safe(id), safe(prev), safe(k.request), safe(c.tail))
	if prev == "" {
		note = fmt.Sprintf("event %s starts request %s again after it ended", safe(id), safe(k.request))
	}
	f.raise(noted(eventAlert(codeUnknown, e), note))
}

// close ends a request: its row is printed, it is remembered as ended while
// its last event is in the window, and an unknown or uncertain end raises an
// alert at the event that ended it.
func (f *follower) close(o *openRequest, end, note string, e *event) {
	delete(f.s.open, o.key)
	r := row{key: o.key}
	o.desc.fill(&r)
	r.end, r.note = end, note
	f.rows = append(f.rows, r)
	if f.s.seen[eventKey{o.key.tenant, o.key.project, o.tail}] != "" {
		c := &closedRequest{tail: o.tail, unknown: end == endUnknown}
		if !c.unknown {
			c.mode = o.walk.mode
			c.run, c.runKnown = o.desc.run, true
		}
		if o.desc.kernel != nil {
			c.kernel = o.desc.kernel.id
		}
		f.s.closed[o.key] = c
	}
	switch end {
	case endUnknown:
		f.raise(noted(eventAlert(codeUnknown, e), note))
	case endUncertain:
		f.raise(noted(eventAlert(codeUncertain, e), note))
	}
}
