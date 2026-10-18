package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/runs"
)

const (
	reactName = "react"
	reactForm = "--findings <dir> --runs <dir> --route <file> --public-key <file>\n" +
		"      --stops <dir>"
)

type reactArgs struct {
	routeFlags
	findings, runs, stops string
	// lockWait bounds each wait for another writer's lock on --stops, and
	// nothing else.
	lockWait time.Duration
}

func reactFlags(command string, out io.Writer) (*flag.FlagSet, *reactArgs) {
	flags := commandFlags(command, out)
	a := &reactArgs{lockWait: stopsLockWait}
	a.declare(flags)
	flags.StringVar(&a.findings, "findings", "", "the findings log directory supervise writes")
	flags.StringVar(&a.runs, "runs", "", "the runs directory, read and never written")
	flags.StringVar(&a.stops, "stops", "", "the stops directory stops init started")
	return flags, a
}

func reactFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := reactFlags(command, out)
	return flags
}

// reactCommand exits 0 when every finding the route allows is on the list,
// 1 on any refusal, a finding it could not write among them, and 2 on a
// usage error.
func reactCommand(args []string, stdout, stderr io.Writer) int {
	flags, a := reactFlags(reactName, io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !a.set() ||
		a.findings == "" || a.runs == "" || a.stops == "" {
		return usageError(stderr, reactName, "takes --findings, --runs, --route, --public-key and --stops, and no argument")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return react(ctx, *a, time.Now, stdout, stderr)
}

// beforeStopsLock runs as a pass is about to wait for the lock on --stops.
// A test signals the command from it.
var beforeStopsLock = func() {}

// react appends to the list in --stops a stop or a covered line for each
// finding of the log the route allows to stop a run and the list does not
// name yet. A route naming a rule that may not stop a run is refused whole
// before the list or a finding is read. It holds no key and never lifts.
// When ctx ends, or a lock wait runs out, the pass stops with the lines it
// wrote and its summary.
func react(ctx context.Context, a reactArgs, clock func() time.Time, stdout, stderr io.Writer) int {
	now := clock().UTC().Truncate(time.Second)
	route, err := a.verified()
	if err != nil {
		return fail(stderr, reactName, err)
	}
	list, _, err := judgedList(a.stops, route, now)
	if err != nil {
		return fail(stderr, reactName, err)
	}
	records, err := findinglog.ReadFile(filepath.Join(a.findings, findinglog.FileName))
	if err != nil {
		return fail(stderr, reactName, fmt.Errorf("--findings %s: %w", a.findings, err))
	}
	plane, err := runs.OpenPlane(a.runs)
	if err != nil {
		return fail(stderr, reactName, fmt.Errorf("--runs %s: %w", a.runs, err))
	}
	r := newReactor(ctx, route, list, plane.Lookup, a.stops, clock)
	r.lockWait = a.lockWait
	err = r.each(records)
	if cerr := plane.Close(); cerr != nil {
		err = errors.Join(err, fmt.Errorf("--runs %s: %w", a.runs, cerr))
	}
	lines := slices.Concat(r.written, r.unwritten, []string{fmt.Sprintf(
		"stops %d, covered %d, already named %d, not stopping %d, not written %d",
		r.stops, r.covered, r.alreadyNamed, r.skipped, len(r.unwritten))})
	if werr := emit(stdout, stderr, reactName, lines, a.stops); werr != exitOK {
		return werr
	}
	switch {
	case err != nil:
		return fail(stderr, reactName, err)
	case len(r.unwritten) > 0:
		return fail(stderr, reactName, fmt.Errorf("%d finding(s) the route allows were not written", len(r.unwritten)))
	}
	return exitOK
}

// lookupRun is runs.Plane's Lookup.
type lookupRun func(ctx context.Context, id string) (runs.Record, error)

// reactor is one pass over a findings log.
type reactor struct {
	ctx      context.Context
	lockWait time.Duration
	route    reaction.Route
	list     reaction.List
	lookup   lookupRun
	dir      string
	// clock is read for each finding before the lock, to skip one that may
	// not stop, and again once the lock is held, so a stop is created and
	// expires by the time it reaches the list, however long the pass has run
	// and the lock was waited for.
	clock func() time.Time

	runFacts map[string]reaction.RunFacts
	// named is the finding ids this pass wrote.
	named map[string]bool
	// full is the list's refusal of a line for its bounds, as text. The list
	// only grows, so every later line is refused without taking the lock,
	// which would otherwise shut other writers out for the rest of the pass.
	full string

	written, unwritten                    []string
	stops, covered, alreadyNamed, skipped int
}

func newReactor(ctx context.Context, route reaction.Route, list reaction.List, lookup lookupRun, dir string, clock func() time.Time) *reactor {
	return &reactor{ctx: ctx, lockWait: stopsLockWait, route: route, list: list, lookup: lookup, dir: dir, clock: clock,
		runFacts: map[string]reaction.RunFacts{}, named: map[string]bool{}}
}

// each takes the findings of records in file order. A run it cannot look up
// for a reason other than there being no such run stops it, as does a write
// refused for a reason other than the list's bound or the judge, and so does
// the end of the pass's context.
func (r *reactor) each(records []*findingv1alpha1.Record) error {
	for _, rec := range records {
		if fr := rec.GetFindingRecord(); fr != nil {
			if err := r.ctx.Err(); err != nil {
				return fmt.Errorf("stopped before finding %s: %w", oneLine(fr.GetFinding().GetFindingId()), err)
			}
			if err := r.finding(fr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *reactor) finding(fr *findingv1alpha1.FindingRecord) error {
	f := fr.GetFinding()
	id := f.GetFindingId()
	if r.list.Names(id) || r.named[id] {
		r.alreadyNamed++
		return nil
	}
	// Only a deterministic, confirmed finding is worth a lookup; Eligible
	// judges it whole below.
	if f.GetSource() != controlv1.FindingSource_FINDING_SOURCE_DETERMINISTIC ||
		f.GetVerdict() != controlv1.FindingVerdict_FINDING_VERDICT_CONFIRMED {
		r.skipped++
		return nil
	}
	run, err := r.run(f.GetRunId())
	if err != nil {
		return err
	}
	if _, ok := r.stopping(fr, run, r.now()); !ok {
		r.skipped++
		return nil
	}
	return r.write(fr, run)
}

// now is the clock in whole seconds, which is what a line spells.
func (r *reactor) now() time.Time { return r.clock().UTC().Truncate(time.Second) }

// errNotStopping is a finding that no longer stops at the reading taken
// under the lock, such as one whose run expired while the pass waited.
var errNotStopping = errors.New("the finding does not stop at the clock read under the lock")

// stopping is the stop fr would be at now, when Eligible takes it with run's
// facts and the route permits it.
func (r *reactor) stopping(fr *findingv1alpha1.FindingRecord, run reaction.RunFacts, now time.Time) (reaction.StopClaim, bool) {
	f := fr.GetFinding()
	facts := reaction.FindingFacts{Source: f.GetSource(), Verdict: f.GetVerdict(), TenantID: fr.GetTenantId(), RunID: f.GetRunId()}
	if reaction.Eligible(facts, run, now) != nil {
		return reaction.StopClaim{}, false
	}
	claim, ok := r.claim(fr, run, now)
	return claim, ok && r.route.Permits(claim) == nil
}

// run is the facts of the run id names. No record, and an id no record can
// have, are the zero facts, which no finding is eligible under.
func (r *reactor) run(id string) (reaction.RunFacts, error) {
	if facts, ok := r.runFacts[id]; ok {
		return facts, nil
	}
	rec, err := r.lookup(r.ctx, id)
	switch {
	case errors.Is(err, runs.ErrNoRun), errors.Is(err, runs.ErrRunID):
		rec = runs.Record{}
	case err != nil:
		return reaction.RunFacts{}, fmt.Errorf("--runs: run %s: %w", oneLine(id), err)
	}
	facts := reaction.RunFacts{RunID: rec.ID, TenantID: rec.Who.TenantID,
		Open: rec.ID != "" && !rec.Closed(), ExpiresAt: rec.ExpiresAt}
	r.runFacts[id] = facts
	return facts, nil
}

// claim is the stop the finding would be, created at now and expiring at
// now plus its rule's lifetime, never after its run expires, or when its run
// expires for a rule with none. A line spells whole seconds, so the run's
// expiry is rounded up to one: rounded down, the run's last fraction of a
// second would run unstopped. A finding no rule of the route names makes no
// claim.
func (r *reactor) claim(fr *findingv1alpha1.FindingRecord, run reaction.RunFacts, now time.Time) (reaction.StopClaim, bool) {
	proc, f := fr.GetProcedure(), fr.GetFinding()
	c := reaction.StopClaim{
		TenantID: fr.GetTenantId(), ProcedureID: proc.GetProcedureId(), ProcedureVersion: proc.GetVersion(),
		ProcedureDigest: proc.GetDigest(), RuleID: f.GetRuleId(), RuleVersion: f.GetRuleVersion(), CreatedAt: now,
	}
	for _, rule := range r.route.Rules() {
		if rule.ProcedureID == c.ProcedureID && rule.ProcedureVersion == c.ProcedureVersion &&
			rule.ProcedureDigest == c.ProcedureDigest && rule.RuleID == c.RuleID && rule.RuleVersion == c.RuleVersion {
			c.ExpiresAt = ceilSecond(run.ExpiresAt)
			limit := rule.Lifetime
			if limit == 0 {
				limit = reaction.MaxLifetime
			}
			if end := now.Add(limit); end.Before(c.ExpiresAt) {
				c.ExpiresAt = end
			}
			return c, true
		}
	}
	return reaction.StopClaim{}, false
}

// write appends a stop for a run with no active stop and a covered line for
// one with, the writer choosing under its lock over the list as it stands,
// so a react running beside this one cannot give the run a second stop. The
// stop is the finding's claim at the clock read under the lock. A write the
// list's bound or the judge refuses is named and the pass goes on; any other
// refusal stops it.
func (r *reactor) write(fr *findingv1alpha1.FindingRecord, run reaction.RunFacts) error {
	id, runID := fr.GetFinding().GetFindingId(), fr.GetFinding().GetRunId()
	stopAt := func(now time.Time) (reaction.Stop, error) {
		c, ok := r.stopping(fr, run, now)
		if !ok {
			return reaction.Stop{}, errNotStopping
		}
		return reaction.Stop{EntryID: reaction.EntryID(id), TenantID: c.TenantID, RunID: runID, FindingID: id,
			ProcedureID: c.ProcedureID, ProcedureVersion: c.ProcedureVersion, ProcedureDigest: c.ProcedureDigest,
			RuleID: c.RuleID, RuleVersion: c.RuleVersion, CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt}, nil
	}
	if r.full != "" {
		r.unwritten = append(r.unwritten, fmt.Sprintf("not written: finding %s run %s: %s", oneLine(id), oneLine(runID), r.full))
		return nil
	}
	// The wait is the lock's alone: reading and judging a list near its bound
	// is work, and a pass over many findings must not spend one budget on it.
	ctx, cancel := context.WithTimeout(r.ctx, r.lockWait)
	beforeStopsLock()
	n, s, covered, err := stopwrite.AppendFinding(ctx, r.dir, r.route, r.now, stopAt)
	cancel()
	switch {
	case errors.Is(err, errNotStopping):
		r.skipped++
		return nil
	case errors.Is(err, stopwrite.ErrNamed):
		// Another writer named it after this pass read the list.
		r.alreadyNamed++
		return nil
	case errors.Is(err, stopwrite.ErrFull), errors.Is(err, stopwrite.ErrRefused):
		if errors.Is(err, stopwrite.ErrFull) {
			r.full = oneLine(err.Error())
		}
		r.unwritten = append(r.unwritten, fmt.Sprintf("not written: finding %s run %s: %s", oneLine(id), oneLine(runID), oneLine(err.Error())))
		return nil
	case err != nil:
		return fmt.Errorf("finding %s run %s: %w", oneLine(id), oneLine(runID), err)
	}
	r.named[id] = true
	if covered {
		r.covered++
		r.written = append(r.written, fmt.Sprintf("covered line %d run %s finding %s", n, oneLine(runID), oneLine(id)))
		return nil
	}
	r.stops++
	r.written = append(r.written, fmt.Sprintf("stop line %d run %s finding %s rule %s expires_at %s",
		n, oneLine(runID), oneLine(id), oneLine(s.RuleID), policy.FormatIssuedAt(s.ExpiresAt)))
	return nil
}

// ceilSecond is t rounded up to a whole second.
func ceilSecond(t time.Time) time.Time {
	if down := t.Truncate(time.Second); down.Before(t) {
		return down.Add(time.Second)
	}
	return t
}
