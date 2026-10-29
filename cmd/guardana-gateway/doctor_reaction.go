package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/runs"
)

// reaction reads the route, its floor and the stop list as a start would, and
// takes no lock and writes nothing: the floor is read and never raised, so its
// bytes and its time stay as they were. It prints the route, the floor, the
// list's id and state, each active stop up to reaction.MaxListedEntries, each
// of those naming a run the runs directory does not hold, and each rule whose
// lifetime ends a stop before its run can end. A route, a floor or a list the
// start would refuse fails here, naming the cause.
func (d *examination) reaction(context.Context) (string, string, string) {
	if !d.cfg.Reaction.Configured() {
		return verdictOK, "reaction", "disabled: reaction.route is not set, so no finding stops a run"
	}
	route, err := readRoute(d.cfg)
	if err != nil {
		return verdictFail, "reaction", err.Error() + "; run refuses to start on it"
	}
	floorDir := d.cfg.Resolve(d.cfg.Reaction.FloorDir)
	floor, err := policystate.ReadRoute(floorDir, route.ID())
	if err == nil {
		err = routeAgainstFloor(floor, route)
	}
	if err != nil {
		return verdictFail, "reaction", fmt.Sprintf("reaction.floor_dir: %v; run refuses to start on it", err)
	}
	poller, err := openStopList(d.cfg, route, nil)
	if err != nil {
		return verdictFail, "reaction", err.Error() + "; run refuses to start on it"
	}
	snap := poller.Current()
	now := time.Now()
	entries, active := snap.ActiveEntries(now, now)
	checked := d.printStops(entries)
	for _, r := range route.Rules() {
		if r.Lifetime != 0 && r.Lifetime < runs.MaxTTL {
			writeLine(d.out, fmt.Sprintf("       rule %s %s of procedure %s %s ends a stop after %s, before its run can end at %s",
				oneLine(r.RuleID), oneLine(r.RuleVersion), oneLine(r.ProcedureID), oneLine(r.ProcedureVersion), r.Lifetime, runs.MaxTTL))
		}
	}
	usage := snap.Usage()
	found := fmt.Sprintf("route %s serial %d digest %s, floor %s in %s; list %s in %s is %s, read %s ago, every %s; %d active stop(s); %d of %d bytes and %d of %d lines",
		oneLine(route.ID()), route.Serial(), route.Digest(), routeFloorText(floor), filepath.ToSlash(floorDir),
		oneLine(snap.Header().ListID), filepath.ToSlash(d.cfg.Resolve(d.cfg.Reaction.Stops)), snap.State(),
		now.Sub(snap.ReadAt()).Round(time.Millisecond), d.cfg.Reaction.PollInterval, active,
		usage.Bytes, reaction.MaxListBytes, usage.Lines, reaction.MaxListLines)
	if usage.Degraded() {
		found += "; degraded: past nine tenths of a bound, so few more stops can be written"
	}
	if !checked {
		return verdictUnknown, "reaction", found + "; whether each listed stop's run is held is unknown"
	}
	return verdictOK, "reaction", found
}

// printStops prints each listed active stop and, where the runs directory can
// be read, each naming a run it does not hold for the plane's project, which
// that stop never matches.
// It reports false when a stop's run could not be checked: the directory did
// not open or close, or a record did not read.
func (d *examination) printStops(entries []reaction.Entry) (checked bool) {
	checked = true
	var dir *runs.Plane
	if d.cfg.Runs.Dir != "" {
		opened, err := runs.OpenPlane(d.cfg.Resolve(d.cfg.Runs.Dir))
		if err != nil {
			writeLine(d.out, "       the runs directory cannot be opened, so no stop's run is checked: "+oneLine(err.Error()))
			checked = len(entries) == 0
		} else {
			dir = opened
			defer func() {
				if err := opened.Close(); err != nil {
					writeLine(d.out, "       the runs directory did not close: "+oneLine(err.Error()))
					checked = false
				}
			}()
		}
	}
	unheld, unread := unheldRuns(dir, d.cfg.ProjectID, entries)
	for _, e := range entries {
		writeLine(d.out, fmt.Sprintf("       stop %s of run %s for finding %s under rule %s, until %s",
			oneLine(e.EntryID), oneLine(e.RunID), oneLine(e.FindingID), oneLine(e.RuleID), e.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	for _, id := range unheld {
		writeLine(d.out, fmt.Sprintf("       stop of run %s: the runs directory holds no such run of this plane's project, so the stop matches no call", oneLine(id)))
	}
	if dir != nil {
		for _, id := range unread {
			writeLine(d.out, fmt.Sprintf("       stop of run %s: the run's record cannot be read, so whether it is held is unknown", oneLine(id)))
			checked = false
		}
	}
	return checked
}
