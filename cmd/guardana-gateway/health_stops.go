package main

import (
	"context"
	"errors"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/runs"
)

// stopsAnswer is the stop state a call admitted now would be decided under
// (ADR-0046): the route and its floor as the start left them, the list's id,
// the state and why an unknown one is unknown, how old the read is, the
// active stops, at most reaction.MaxListedEntries of them, the list's use of
// its bounds, the active stops naming a run the runs directory does not hold
// for the plane's project, and what the reader counted. A plane with no route says only disabled.
type stopsAnswer struct {
	State  string       `json:"state"`
	Cause  string       `json:"cause,omitempty"`
	Route  *routeAnswer `json:"route,omitempty"`
	Floor  string       `json:"floor,omitempty"`
	ListID string       `json:"list_id,omitempty"`
	// AgeMS is left out where nothing was read.
	AgeMS *int64 `json:"age_ms,omitempty"`
	// Active is how many stops are active; Entries lists the first of them.
	Active  int               `json:"active"`
	Entries []stopEntryAnswer `json:"entries"`
	Usage   *usageAnswer      `json:"usage,omitempty"`
	// Degraded says the list is past nine tenths of a bound, past which the
	// emitter can write no more stops.
	Degraded bool `json:"degraded"`
	// UnheldRuns are the listed stops' runs the runs directory holds no
	// record of for the plane's project, and UnreadRuns those whose record
	// could not be read.
	UnheldRuns []string       `json:"unheld_runs"`
	UnreadRuns []string       `json:"unread_runs"`
	Polls      map[string]any `json:"polls,omitempty"`
}

type routeAnswer struct {
	ID     string `json:"id"`
	Serial int64  `json:"serial"`
	Digest string `json:"digest"`
}

type stopEntryAnswer struct {
	EntryID   string `json:"entry_id"`
	RunID     string `json:"run_id"`
	FindingID string `json:"finding_id"`
	RuleID    string `json:"rule_id"`
	ExpiresAt string `json:"expires_at"`
}

type usageAnswer struct {
	Bytes    int64 `json:"bytes"`
	MaxBytes int64 `json:"max_bytes"`
	Lines    int64 `json:"lines"`
	MaxLines int64 `json:"max_lines"`
}

// stopsAnswer is snap as a call admitted at now would take it.
func (p *plane) stopsAnswer(snap reaction.Snapshot, now time.Time) stopsAnswer {
	at := snap.At(now)
	out := stopsAnswer{State: at.State().String(), Entries: []stopEntryAnswer{}, UnheldRuns: []string{}, UnreadRuns: []string{}}
	if at.State() == reaction.Unknown {
		out.Cause = string(at.Cause())
	}
	if p.stops == nil {
		return out
	}
	route := p.stops.route
	out.Route = &routeAnswer{ID: route.ID(), Serial: route.Serial(), Digest: route.Digest()}
	out.Floor = routeFloorText(p.stops.floor)
	// The list the plane holds, which an unknown read leaves in place.
	held := snap.AcceptedList()
	out.ListID = held.Header().ListID
	if !snap.ReadAt().IsZero() {
		age := now.Sub(snap.ReadAt()).Milliseconds()
		out.AgeMS = &age
	}
	entries, total := at.ActiveEntries(now, now)
	if at.State() == reaction.Unknown {
		entries, total = heldActive(held, now)
	}
	out.Active = total
	for _, e := range entries {
		out.Entries = append(out.Entries, stopEntryAnswer{
			EntryID: e.EntryID, RunID: e.RunID, FindingID: e.FindingID, RuleID: e.RuleID,
			ExpiresAt: e.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	out.UnheldRuns, out.UnreadRuns = unheldRuns(p.runsDir, p.cfg.ProjectID, entries)
	if u := held.Usage(); u != (reaction.Usage{}) {
		out.Usage = &usageAnswer{Bytes: u.Bytes, MaxBytes: reaction.MaxListBytes, Lines: u.Lines, MaxLines: reaction.MaxListLines}
		out.Degraded = u.Degraded()
	}
	stats := p.stops.poller.Stats()
	failed := make(map[string]uint64, len(stats.Failed))
	for cause, n := range stats.Failed {
		failed[string(cause)] = n
	}
	out.Polls = map[string]any{"made": stats.Polls, "failed": failed}
	return out
}

// heldActive is what ActiveEntries says of the list a plane holds while its
// state is unknown: the stops of the last list it accepted that are active at
// now, at most reaction.MaxListedEntries of them, and how many in all. The
// state still blocks every call; this is what the plane would stop by.
func heldActive(held reaction.List, now time.Time) ([]reaction.Entry, int) {
	var out []reaction.Entry
	total := 0
	for _, e := range held.Entries() {
		if !e.ActiveAt(now, now) {
			continue
		}
		total++
		if len(out) < reaction.MaxListedEntries {
			out = append(out, e)
		}
	}
	return out, total
}

// unheldRuns names, in order, the runs of entries the runs directory holds no
// record of under project, and those whose record it could not read: a stop
// of a run that is not there, or is another project's, matches no call of a
// plane of project, and one that cannot be read is not known to.
func unheldRuns(dir *runs.Plane, project string, entries []reaction.Entry) (unheld, unread []string) {
	unheld, unread = []string{}, []string{}
	for _, e := range entries {
		if dir == nil {
			unread = append(unread, e.RunID)
			continue
		}
		rec, err := dir.Lookup(context.Background(), e.RunID)
		switch {
		case errors.Is(err, runs.ErrNoRun):
			unheld = append(unheld, e.RunID)
		case err != nil:
			unread = append(unread, e.RunID)
		case rec.Who.ProjectID != project:
			unheld = append(unheld, e.RunID)
		}
	}
	return unheld, unread
}
