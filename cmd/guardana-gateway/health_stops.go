package main

import (
	"context"
	"errors"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/runs"
)

// stopsAnswer is the stop state a call admitted now would be decided under
// (ADR-0046): the route and its floor as the start left them, the list's id,
// the state and why an unknown one is unknown, how old the read is, the
// active stops, at most reaction.MaxListedEntries of them, the list's use of
// its bounds, the active stops whose subject the plane does not hold, and
// what the reader counted. A plane with no route says only disabled. The
// entries and the stops they name are the whole answer's; counted leaves
// them out.
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
	// UnheldEntries are the entry ids of the listed stops that match no call
	// of this plane: a run the runs directory holds no record of for the
	// plane's project, or an agent or principal, or a tenant, other than the
	// listener's. UnreadEntries are those whose run's record could not be
	// read. Unheld and Unread count them.
	Unheld        int            `json:"unheld"`
	Unread        int            `json:"unread"`
	UnheldEntries []string       `json:"unheld_entries"`
	UnreadEntries []string       `json:"unread_entries"`
	Polls         map[string]any `json:"polls,omitempty"`
	// Signed is a signed list's header serial, and on the whole answer alone
	// who signed it and the route.
	Signed *stopsSigned `json:"signed,omitempty"`
}

type stopsSigned struct {
	Serial       int64  `json:"serial"`
	Subject      string `json:"subject,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	RouteSubject string `json:"route_subject,omitempty"`
	RouteKeyID   string `json:"route_key_id,omitempty"`
}

type routeAnswer struct {
	ID     string `json:"id"`
	Serial int64  `json:"serial"`
	Digest string `json:"digest"`
}

// stopEntryAnswer is one active stop: its scope and subject, and the run
// whose finding made it, which under scope run is the subject.
type stopEntryAnswer struct {
	EntryID   string `json:"entry_id"`
	Scope     string `json:"scope"`
	Subject   string `json:"subject"`
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
	out := stopsAnswer{State: at.State().String(), Entries: []stopEntryAnswer{}, UnheldEntries: []string{}, UnreadEntries: []string{}}
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
	if h := held.Header().Signed; h.Digest != "" {
		out.Signed = &stopsSigned{Serial: h.Serial, Subject: held.Signer().Subject, KeyID: held.Signer().KeyID,
			RouteSubject: route.Signer().Subject, RouteKeyID: route.Signer().KeyID}
	}
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
		t := e.Target()
		out.Entries = append(out.Entries, stopEntryAnswer{
			EntryID: e.EntryID, Scope: t.Scope, Subject: t.Subject, RunID: e.RunID, FindingID: e.FindingID, RuleID: e.RuleID,
			ExpiresAt: e.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	unheld, unread := unheldStops(p.runsDir, p.cfg, entries)
	for _, e := range unheld {
		out.UnheldEntries = append(out.UnheldEntries, e.EntryID)
	}
	for _, e := range unread {
		out.UnreadEntries = append(out.UnreadEntries, e.EntryID)
	}
	out.Unheld, out.Unread = len(out.UnheldEntries), len(out.UnreadEntries)
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

// unheldStops names, in order, the entries that match no call of the plane
// cfg configures, and those it cannot tell: a stop of a run the runs
// directory holds no record of under the plane's project is unheld, and one
// whose record cannot be read unread; a stop of an agent or a principal is
// unheld unless its tenant and subject are the listener's, which every
// opened run of the plane carries.
func unheldStops(dir *runs.Plane, cfg *gatewayconfig.Config, entries []reaction.Entry) (unheld, unread []reaction.Entry) {
	for _, e := range entries {
		switch t := e.Target(); t.Scope {
		case reaction.ScopeAgent:
			if e.TenantID != cfg.ListenerTenant() || t.Subject != cfg.Listener.AgentID {
				unheld = append(unheld, e)
			}
		case reaction.ScopePrincipal:
			if e.TenantID != cfg.ListenerTenant() || t.Subject != cfg.Listener.PrincipalID {
				unheld = append(unheld, e)
			}
		default:
			if held, known := runHeld(dir, cfg.ProjectID, e.RunID); !known {
				unread = append(unread, e)
			} else if !held {
				unheld = append(unheld, e)
			}
		}
	}
	return unheld, unread
}

// runHeld reports whether the runs directory holds a record of id under
// project, and known is false when it cannot say: no directory, or a record
// that does not read. A signed record of another tenant or project is held
// by none of this plane's.
func runHeld(dir *runs.Plane, project, id string) (held, known bool) {
	if dir == nil {
		return false, false
	}
	rec, err := dir.Lookup(context.Background(), id)
	switch {
	case errors.Is(err, runs.ErrNoRun), errors.Is(err, runs.ErrOtherScope):
		return false, true
	case err != nil:
		return false, false
	}
	return rec.Who.ProjectID == project, true
}

// countedHealth is the health answer as GET /healthz gives it: the stops'
// entries and the runs they name left out, their counts kept, so no run id
// reaches a listener any local account can read.
type countedHealth struct {
	healthAnswer
	Stops countedStops `json:"stops"`
}

// countedStops shadows the members of stopsAnswer that list stops with
// members that are always empty and so never encoded.
type countedStops struct {
	stopsAnswer
	Entries       *struct{} `json:"entries,omitempty"`
	UnheldEntries *struct{} `json:"unheld_entries,omitempty"`
	UnreadEntries *struct{} `json:"unread_entries,omitempty"`
}

// counted is a as GET /healthz answers it, the operators who signed the
// pause, the stop list and the route left out as well, and the plane's id,
// a name the operator chose, which a port that takes no credential keeps.
func (a healthAnswer) counted() countedHealth {
	if a.Pause.Signed != nil {
		signed := *a.Pause.Signed
		signed.Subject, signed.KeyID = "", ""
		a.Pause.Signed = &signed
	}
	if a.Stops.Signed != nil {
		signed := stopsSigned{Serial: a.Stops.Signed.Serial}
		a.Stops.Signed = &signed
	}
	if _, named := a.Trust["plane_id"]; named {
		trust := make(map[string]any, len(a.Trust))
		for key, value := range a.Trust {
			if key != "plane_id" {
				trust[key] = value
			}
		}
		a.Trust = trust
	}
	return countedHealth{healthAnswer: a, Stops: countedStops{stopsAnswer: a.Stops}}
}
