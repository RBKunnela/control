package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/runs"
)

// reaction reads the route, its floor and the stop list as a start would, and
// takes no lock and writes nothing: the floor is read and never raised, so its
// bytes and its time stay as they were. It prints the route, the floor, the
// list's id and state, each active stop up to reaction.MaxListedEntries, each
// of those that matches no call of the plane, and each rule whose
// lifetime ends a stop before its run can end. A route, a floor or a list the
// start would refuse fails here, naming the cause.
func (d *examination) reaction(context.Context) (string, string, string) {
	if !d.cfg.Reaction.Configured() {
		return verdictOK, "reaction", "disabled: reaction.route is not set, so no finding stops a run"
	}
	var (
		route reaction.Route
		read  = stopListRead{owner: stoplist.OwnedByThisUser}
		err   error
	)
	if signedStops(d.cfg) {
		route, read, err = d.signedRoute()
	} else {
		route, err = readRoute(d.cfg)
	}
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
	poller, err := openStopList(d.cfg, route, nil, read)
	if err != nil {
		return verdictFail, "reaction", err.Error() + "; run refuses to start on it"
	}
	snap := poller.Current()
	now := time.Now()
	entries, active := snap.ActiveEntries(now, now)
	checked := d.printStops(entries)
	d.printShortLifetimes(route)
	usage := snap.Usage()
	found := fmt.Sprintf("route %s serial %d digest %s, floor %s in %s; list %s in %s is %s, read %s ago, every %s; %d active stop(s); %d of %d bytes and %d of %d lines",
		oneLine(route.ID()), route.Serial(), route.Digest(), routeFloorText(floor), filepath.ToSlash(floorDir),
		oneLine(snap.Header().ListID), filepath.ToSlash(d.cfg.Resolve(d.cfg.Reaction.Stops)), snap.State(),
		now.Sub(snap.ReadAt()).Round(time.Millisecond), d.cfg.Reaction.PollInterval, active,
		usage.Bytes, reaction.MaxListBytes, usage.Lines, reaction.MaxListLines)
	found += signersText(route, snap)
	if usage.Degraded() {
		found += "; degraded: past nine tenths of a bound, so few more stops can be written"
	}
	if !checked {
		return verdictUnknown, "reaction", found + "; whether each listed stop's run is held is unknown"
	}
	return verdictOK, "reaction", found
}

// printShortLifetimes prints each rule of route that stops an agent or a
// principal, and so every run of the plane, for its lifetime, and each rule
// whose lifetime ends a run's stop before its run can end.
func (d *examination) printShortLifetimes(route reaction.Route) {
	for _, r := range route.Rules() {
		if r.Scope == reaction.ScopeAgent || r.Scope == reaction.ScopePrincipal {
			writeLine(d.out, fmt.Sprintf("       rule %s %s of procedure %s %s stops the %s for %s, every run of this plane and calls with no run",
				oneLine(r.RuleID), oneLine(r.RuleVersion), oneLine(r.ProcedureID), oneLine(r.ProcedureVersion), r.Scope, r.Lifetime))
			continue
		}
		if r.Lifetime != 0 && r.Lifetime < runs.MaxTTL {
			writeLine(d.out, fmt.Sprintf("       rule %s %s of procedure %s %s ends a stop after %s, before its run can end at %s",
				oneLine(r.RuleID), oneLine(r.RuleVersion), oneLine(r.ProcedureID), oneLine(r.ProcedureVersion), r.Lifetime, runs.MaxTTL))
		}
	}
}

// signersText names who signed the route and the list's header, or nothing
// when the list carries no signer.
func signersText(route reaction.Route, snap reaction.Snapshot) string {
	signer := snap.AcceptedList().Signer()
	if signer.KeyID == "" {
		return ""
	}
	return fmt.Sprintf("; route signed by %s (key %s), list header serial %d signed by %s (key %s)",
		oneLine(route.Signer().Subject), oneLine(route.Signer().KeyID), snap.Header().Signed.Serial,
		oneLine(signer.Subject), oneLine(signer.KeyID))
}

// printStops prints each listed active stop, an agent's or a principal's
// with the run its finding was about, and each that matches no call: a run
// the runs directory, where it can be read, does not hold for the plane's
// project, or an agent, principal or tenant other than the listener's.
// It reports false when a stop's run could not be checked: the directory did
// not open or close, or a record did not read.
func (d *examination) printStops(entries []reaction.Entry) (checked bool) {
	checked = true
	var dir *runs.Plane
	if d.cfg.Runs.Dir != "" {
		opened, err := d.openRunsCheck()
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
	unheld, unread := unheldStops(dir, d.cfg, entries)
	for _, e := range entries {
		of := "of run " + oneLine(e.RunID)
		if t := e.Target(); t.Scope != reaction.ScopeRun {
			of = fmt.Sprintf("of %s %s, found on run %s,", t.Scope, oneLine(t.Subject), oneLine(e.RunID))
		}
		writeLine(d.out, fmt.Sprintf("       stop %s %s for finding %s under rule %s, until %s",
			oneLine(e.EntryID), of, oneLine(e.FindingID), oneLine(e.RuleID), e.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	for _, e := range unheld {
		t := e.Target()
		why := "the runs directory holds no such run of this plane's project"
		if t.Scope != reaction.ScopeRun {
			why = fmt.Sprintf("this plane serves %s %s of tenant %s", t.Scope, oneLine(served(d.cfg, t.Scope)), oneLine(d.cfg.ListenerTenant()))
		}
		writeLine(d.out, fmt.Sprintf("       stop of %s %s: %s, so the stop matches no call", t.Scope, oneLine(t.Subject), why))
	}
	if dir != nil {
		for _, e := range unread {
			writeLine(d.out, fmt.Sprintf("       stop of run %s: the run's record cannot be read, so whether it is held is unknown", oneLine(e.RunID)))
			checked = false
		}
	}
	return checked
}

// served is the agent or principal the listener serves, by scope.
func served(cfg *gatewayconfig.Config, scope string) string {
	if scope == reaction.ScopeAgent {
		return cfg.Listener.AgentID
	}
	return cfg.Listener.PrincipalID
}
