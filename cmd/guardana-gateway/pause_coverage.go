package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/runs"
)

// The share of a plane's calls a pause entry can cover.
const (
	coverAll  = "all"
	coverSome = "some"
	coverNone = "none"
)

// The causes of a run entry that covers none, as /healthz and doctor name
// them.
const (
	runAbsent     = "no such run"
	runElsewhere  = "another project's run"
	runExpired    = "expired"
	runClosed     = "closed"
	runUnreadable = "its record cannot be read"
	runsUnread    = "the runs directory cannot be read"
)

// cover is the share of a plane's calls one entry can cover and, for a run
// entry that covers none, why.
type cover struct {
	share, cause string
}

// coverage names, by entry id, the share of cfg's plane's calls each entry
// can cover at now. A run entry covers all where no runs.dir opens a run,
// since a call under no opened run matches every run entry, and otherwise
// what runCover finds in dir; an agent or a principal entry all or none,
// since every call carries the listener's; a provider or action entry none
// when stray names it. An entry that covers none is the unsafe failure of an
// emergency control, so it is never left unsaid.
func coverage(entries []pause.Entry, cfg *gatewayconfig.Config, stray []strayEntry, dir *runs.Plane, now time.Time) map[string]cover {
	out := make(map[string]cover, len(entries))
	for _, e := range entries {
		c := cover{share: coverAll}
		switch s := e.Scope; s.Kind {
		case pause.ScopeRun:
			if cfg.Runs.Dir != "" {
				c = runCover(dir, cfg.ProjectID, s.ID, now)
			}
		case pause.ScopeAgent:
			c.share = allOrNone(s.ID == cfg.Listener.AgentID)
		case pause.ScopePrincipal:
			c.share = allOrNone(s.ID == cfg.Listener.PrincipalID)
		case pause.ScopeProvider, pause.ScopeAction:
			c.share = coverSome
			if slices.ContainsFunc(stray, func(x strayEntry) bool { return x.id == e.ID }) {
				c.share = coverNone
			}
		}
		out[e.ID] = c
	}
	return out
}

// runCover is what a run entry naming id covers on a plane of project that
// serves the opened runs of dir, as the stop list judges a stop's run: none
// for a run dir holds no record of, another project's, expired, or closed
// unless it is a root, whose runs stay open after it closes; none with its
// cause where the record cannot be read; and some otherwise.
func runCover(dir *runs.Plane, project, id string, now time.Time) cover {
	if dir == nil {
		return cover{coverNone, runsUnread}
	}
	rec, err := dir.Lookup(context.Background(), id)
	switch {
	case errors.Is(err, runs.ErrNoRun):
		return cover{coverNone, runAbsent}
	case err != nil:
		return cover{coverNone, runUnreadable}
	case rec.Who.ProjectID != project:
		return cover{coverNone, runElsewhere}
	case !now.Before(rec.ExpiresAt):
		return cover{coverNone, runExpired}
	case rec.Closed() && rec.Root != rec.ID:
		return cover{coverNone, runClosed}
	}
	return cover{share: coverSome}
}

func allOrNone(all bool) string {
	if all {
		return coverAll
	}
	return coverNone
}

// printCoverage prints each agent or principal entry that is not the
// listener's and each run entry that covers none, with why, and returns how
// many entries cover all, some and none of the plane's calls.
func (d *examination) printCoverage(entries []pause.Entry, stray []strayEntry) string {
	var dir *runs.Plane
	if d.cfg.Runs.Dir != "" {
		if opened, err := d.openRunsCheck(); err == nil {
			dir = opened
			defer func() {
				if err := opened.Close(); err != nil {
					writeLine(d.out, "       the runs directory did not close: "+oneLine(err.Error()))
				}
			}()
		}
	}
	covers := coverage(entries, d.cfg, stray, dir, time.Now())
	counts := map[string]int{}
	for _, e := range entries {
		c := covers[e.ID]
		counts[c.share]++
		if c.share != coverNone {
			continue
		}
		switch k := e.Scope.Kind; k {
		case pause.ScopeAgent, pause.ScopePrincipal:
			writeLine(d.out, fmt.Sprintf("       pause entry %s names %s %s, which is not this listener's: it pauses no call this plane runs",
				oneLine(e.ID), k, oneLine(strconv.Quote(e.Scope.ID))))
		case pause.ScopeRun:
			then := "so it pauses no call this plane runs"
			if c.cause == runUnreadable || c.cause == runsUnread {
				then = "so whether it pauses a call is unknown"
			}
			writeLine(d.out, fmt.Sprintf("       pause entry %s names run %s: %s, %s", oneLine(e.ID), oneLine(e.Scope.ID), c.cause, then))
		}
	}
	return fmt.Sprintf("%d covering all of this plane's calls, %d some, %d none", counts[coverAll], counts[coverSome], counts[coverNone])
}
