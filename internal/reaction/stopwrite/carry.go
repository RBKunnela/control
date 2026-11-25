package stopwrite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// Carried is what a carry wrote.
type Carried struct {
	// Header is the new list's header.
	Header reaction.Header
	// Stops is how many stops the new list holds.
	Stops int
	// Covered is how many covered lines it holds.
	Covered int
	// LeftOut is how many lines of the old list, from the first one the
	// plane's judge refuses to its end, the carry left out; zero when it took
	// the whole list.
	LeftOut int64
	// Refused is the first line left out and why; nil when none was.
	Refused error
}

// carrying, when a test sets it, runs once a carry read the old list and
// before it writes the new one.
var carrying func()

// stopped, when a test sets it, runs between a signed carry's two writes, the
// old list's mode and the new list; an error stops the carry there, as a
// process killed between them would.
var stopped func() error

// afterCreate, when a test sets it, takes what a signed carry's create of the
// new list returned and answers what the carry goes on with, as a create that
// failed once its list stood in place would.
var afterCreate func(error) error

// Carry starts a stop list in dir, judged against route, from the list in
// from, judged against fromRoute, which alone may name a rule version a later
// one superseded (reaction.CheckCarrySource). The new list keeps every stop of
// the old one no lift ended, expired or not, since the writer's clock may be
// one a plane would not trust, and a covered line for every other finding the
// old list names, so none of them stops a run again. A list a plane refuses at
// one of its lines is carried up to that line (acceptedPart). The old list
// stays locked until the new one is written, whole or not at all, so no write
// to it falls between the two; a dir that already holds a list is ErrExists.
// Both routes are v1alpha1: a list an operator signed is carried by
// CarrySigned, and the unsigned list Carry would write under another route is
// refused by the judge every write passes.
func Carry(ctx context.Context, from string, fromRoute reaction.Route, dir string, route reaction.Route, now time.Time) (Carried, error) {
	return carry(ctx, from, fromRoute, dir, route, now, false, func(part) (reaction.Header, []byte, error) {
		h, err := newHeader(route)
		if err != nil {
			return reaction.Header{}, nil, err
		}
		line, err := h.Marshal()
		if err != nil {
			return reaction.Header{}, nil, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		return h, line, nil
	})
}

// CarrySigned is Carry into the 3.0 list of a v1alpha3 route from the 2.0
// list of a v1alpha2 route or the 3.0 list of a v1alpha3 one, each route
// taken by a voucher: the old list is judged line by line as a plane judges
// it, its header and lifts through the old route's voucher, before anything
// of it is signed again, and the new header, signed by s, takes the next
// serial and names the old list's head as its previous, so the plane's floor
// follows the carry. A stop or covered line carried from 2.0 names scope run
// and its run as its subject. hold, when set, is what the part of the old
// list carried is held to before anything is signed, with that part's bytes:
// the plane's stop list floor, so a list cut back below what the plane
// accepted is not carried. Before the new list is written the old one loses
// its write bits under the lock, and no writer here appends to it again
// (ErrCarried): a stop a plane still serving it took after the carry would
// be one the new list lacks, and its floor follows the new header whatever
// the old list held. A write that leaves no new list gives the bits back; a
// carry stopped between the two leaves the old list read-only, and a rerun
// finishes it.
func CarrySigned(ctx context.Context, from string, fromRoute reaction.Route, dir string, route reaction.Route, now time.Time, s Signer,
	hold func(reaction.List, []byte) error) (Carried, error) {
	switch fromRoute.Format() {
	case reaction.FormatV1Alpha2Carry, reaction.FormatV1Alpha3:
	default:
		return Carried{}, fmt.Errorf("%w: a signed carry is from the list of a v1alpha2 or v1alpha3 route", ErrRefused)
	}
	if route.Format() != reaction.FormatV1Alpha3 {
		return Carried{}, fmt.Errorf("%w: a signed carry is into the list of a v1alpha3 route", ErrRefused)
	}
	return carry(ctx, from, fromRoute, dir, route, now, true, func(old part) (reaction.Header, []byte, error) {
		if hold != nil {
			if err := hold(old.list, old.accepted); err != nil {
				return reaction.Header{}, nil, fmt.Errorf("%w: the list carried from: %w", ErrRefused, err)
			}
		}
		prev := old.list.Header().Signed
		if prev.Serial >= policy.MaxSerial {
			return reaction.Header{}, nil, fmt.Errorf("%w: the old list's serial is the last", ErrRefused)
		}
		return signedHeader(route, s, prev.Serial+1, prev.Digest)
	})
}

// headerFor is the header of a carry's new list, given the part of the old
// list carried, and its line.
type headerFor func(old part) (reaction.Header, []byte, error)

func carry(ctx context.Context, from string, fromRoute reaction.Route, dir string, route reaction.Route, now time.Time, retire bool, next headerFor) (Carried, error) {
	var out Carried
	err := locked(ctx, from, func(root *os.Root) error {
		same, err := sameDir(root, dir)
		if err != nil {
			return err
		}
		if same {
			return fmt.Errorf("%w: %s", ErrExists, dir)
		}
		old, err := readList(root)
		if err != nil {
			return err
		}
		part, err := acceptedPart(fromRoute, old, now)
		if err != nil {
			return err
		}
		h, header, err := next(part)
		if err != nil {
			return err
		}
		out = Carried{Header: h, LeftOut: part.leftOut, Refused: part.refused}
		stops, covered, err := carriedLines(part, route.Format())
		if err != nil {
			return err
		}
		out.Stops, out.Covered = len(stops), len(covered)
		if carrying != nil {
			carrying()
		}
		lines := append(append([][]byte{header}, stops...), covered...)
		if err := writeCarried(ctx, root, dir, route, now, lines, retire); err != nil {
			return liftFirst(err, part.list.Entries(), fromRoute.Format(), route)
		}
		return nil
	})
	if err != nil {
		return Carried{}, err
	}
	return out, nil
}

// writeCarried is create of the new list, retiring the old list root holds
// first when retire is set.
func writeCarried(ctx context.Context, root *os.Root, dir string, route reaction.Route, now time.Time, lines [][]byte, retire bool) error {
	if retire {
		return createRetiring(ctx, root, dir, route, now, lines)
	}
	return create(ctx, dir, route, now, lines)
}

// liftFirst is err, the new list's refusal, naming the stop it refused when
// that is a stop the carry brought from entries, and what ends the refusal
// (remedy): an upgrade lifts no stop, so the operator does.
func liftFirst(err error, entries []reaction.Entry, from reaction.RouteFormat, route reaction.Route) error {
	var at *reaction.LineError
	if !errors.As(err, &at) || !errors.Is(err, reaction.ErrStopRefused) || at.Line < 2 || at.Line-2 >= int64(len(entries)) {
		return err
	}
	e := entries[at.Line-2]
	target := e.Target()
	return fmt.Errorf("%w: it is the stop of %s %q at line %d of the list carried from, for finding %q under rule %s %s, "+
		"which the new route does not grant; %s",
		err, target.Scope, target.Subject, e.Line, e.FindingID, e.RuleID, e.RuleVersion, remedy(err, e, from, route))
}

// remedy is what ends err, route's refusal of e, a stop carried from a list
// under a route of format from. A carry keeps a stop's tenant and project,
// so only a route of those or a new list does when they differ. Otherwise the
// stop is lifted on the old list under its route, but no lift is written
// under a v1alpha2 route: for its list the route takes a rule that keeps the
// stop, the rule it holds at another scope moved to the stop's when it names
// one, since a route names a rule once.
func remedy(err error, e reaction.Entry, from reaction.RouteFormat, route reaction.Route) string {
	target := e.Target()
	fresh := "start a new list with stops init"
	if from != reaction.FormatV1Alpha1 {
		fresh += " under a new stop list floor (stops floor init)"
	}
	fresh += ", which keeps none of the old list's stops"
	switch {
	case errors.Is(err, reaction.ErrClaimTenant) || errors.Is(err, reaction.ErrClaimProject):
		return "a carry keeps each stop's tenant and project, and the new route's differ: " +
			"carry under a route of the list's tenant and project, or " + fresh
	case from != reaction.FormatV1Alpha2Carry:
		return fmt.Sprintf("end it there with stops lift --%s %q under the route it was written under, then carry again",
			target.Scope, target.Subject)
	}
	span := int64(math.Ceil(e.ExpiresAt.Sub(e.CreatedAt).Seconds()))
	version := currentVersion(e.RuleID, e.RuleVersion)
	if held, ok := heldAtAnotherScope(err, e, version, route); ok {
		return fmt.Sprintf("stops lift takes no reaction-route/v1alpha2 route, and the new route names rule %s %s of procedure %q version %q "+
			"at scope %s, and a route names a rule once: give it scope %s, so it stops no agent or principal, with expires_seconds "+
			"of at least %d, sign it and carry again, or %s",
			held.RuleID, held.RuleVersion, held.ProcedureID, held.ProcedureVersion, held.Scope, target.Scope, span, fresh)
	}
	keeps := "rule " + e.RuleID + " " + version + " of"
	if reaction.Retired(e.RuleID, e.RuleVersion) {
		keeps = "a rule of"
	}
	return fmt.Sprintf("stops lift takes no reaction-route/v1alpha2 route, so either give the new route %s procedure %q version %q "+
		"at scope %s with expires_seconds of at least %d, sign it and carry again, or %s",
		keeps, e.ProcedureID, e.ProcedureVersion, target.Scope, span, fresh)
}

// currentVersion is the version of rule id a route names for a stop of it at
// version: the one that replaced a superseded version, or version itself.
func currentVersion(id, version string) string {
	if !reaction.Superseded(id, version) {
		return version
	}
	for _, r := range reaction.StoppingRules() {
		if r.ID == id {
			return r.Version
		}
	}
	return version
}

// heldAtAnotherScope is route's rule of e's procedure and rule, at version,
// when err refuses e for its scope. No route names a retired version, so a
// retired stop finds none.
func heldAtAnotherScope(err error, e reaction.Entry, version string, route reaction.Route) (reaction.Rule, bool) {
	if !errors.Is(err, reaction.ErrClaimScope) {
		return reaction.Rule{}, false
	}
	for _, r := range route.Rules() {
		if r.ProcedureID == e.ProcedureID && r.ProcedureVersion == e.ProcedureVersion && r.ProcedureDigest == e.ProcedureDigest &&
			r.RuleID == e.RuleID && r.RuleVersion == version {
			return r, true
		}
	}
	return reaction.Rule{}, false
}

// createRetiring is create of a new list from the old list root holds, which
// loses its write bits first; a dir that already holds a list is ErrExists
// before the old list loses any. A create that failed with no new list in place
// gives them back; a process killed between the two leaves the old list
// read-only, where no stop reaches a list nothing carries, and a rerun
// finishes the carry.
func createRetiring(ctx context.Context, root *os.Root, dir string, route reaction.Route, now time.Time, lines [][]byte) error {
	// create judges the lines before it finds a list already in dir, and a
	// refusal then could not tell that list from one create placed.
	if _, err := os.Lstat(filepath.Join(dir, stoplist.FileName)); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: %s", ErrExists, dir)
	}
	was, err := retireList(root)
	if err != nil {
		return fmt.Errorf("the list carried from was not made read-only: %w", err)
	}
	if stopped != nil {
		if err := stopped(); err != nil {
			return err
		}
	}
	err = create(ctx, dir, route, now, lines)
	if afterCreate != nil {
		err = afterCreate(err)
	}
	if err != nil && noListPlaced(dir, err) {
		_, back := chmodList(root, func(fs.FileMode) fs.FileMode { return was })
		return errors.Join(err, back)
	}
	return err
}

// noListPlaced reports whether create's failure err left no new list in dir:
// a list that stood there before, or nothing at its name. A list left in
// place by a create that failed after placing it is one a plane may take, so
// the old list keeps no write bit beside it.
func noListPlaced(dir string, err error) bool {
	if errors.Is(err, ErrExists) {
		return true
	}
	_, lerr := os.Lstat(filepath.Join(dir, stoplist.FileName))
	return errors.Is(lerr, fs.ErrNotExist)
}

// CarriedLines is what Carry writes after the new list's header when it
// carries old, the bytes of a list judged against route at now: a stop line
// for every stop of old no lift ended, then a covered line for every other
// finding old names. A list whose lines after its header begin with them
// holds what a carry of old would.
func CarriedLines(route reaction.Route, old []byte, now time.Time) ([]byte, error) {
	part, err := acceptedPart(route, old, now)
	if err != nil {
		return nil, err
	}
	stops, covered, err := carriedLines(part, route.Format())
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, line := range append(stops, covered...) {
		out = append(append(out, line...), '\n')
	}
	return out, nil
}

// carriedLines is the stop lines and the covered lines a carry of p writes
// into a list judged against a route of format into.
func carriedLines(p part, into reaction.RouteFormat) (stops, covered [][]byte, err error) {
	kept := map[string]bool{}
	for _, e := range p.list.Entries() {
		if into == reaction.FormatV1Alpha3 && e.Subject == "" {
			e.Scope, e.Subject = reaction.ScopeRun, e.RunID
		}
		line, err := e.Marshal()
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		stops = append(stops, line)
		kept[e.FindingID] = true
	}
	covered, err = coveredLines(p.accepted, kept, into)
	return stops, covered, err
}

// part is what a carry takes of an old list: the list a plane accepts, its
// bytes, and how many lines after them it leaves out and why.
type part struct {
	list     reaction.List
	accepted []byte
	leftOut  int64
	refused  error
}

// acceptedPart judges old against route as a plane does. A list it accepts is
// taken whole. One it refuses at a line is taken up to that line, which
// repairs a list someone broke by appending a line the route refuses, but
// only where nothing left out could be a stop the old list was meant to hold:
// a refused header, a line refused for a created_at past the writer's clock,
// which another writer whose clock runs ahead wrote in good faith, and a stop
// or covered line after the refused line each refuse the carry, as does a
// route naming a rule that may not stop a run and was never superseded.
func acceptedPart(route reaction.Route, old []byte, now time.Time) (part, error) {
	if err := reaction.CheckCarrySource(route); err != nil {
		return part{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	list, err := reaction.JudgeCarrySource(route, old, now)
	if err == nil {
		return part{list: list, accepted: old}, nil
	}
	var at *reaction.LineError
	if !errors.As(err, &at) || at.Line < 2 || errors.Is(err, reaction.ErrDatedAhead) {
		return part{}, fmt.Errorf("the list carried from: %w", refusal(err))
	}
	complete := old[:bytes.LastIndexByte(old, '\n')+1]
	lines := bytes.SplitAfter(complete, []byte{'\n'})
	lines = lines[:len(lines)-1]
	for i, raw := range lines[at.Line:] {
		l, perr := reaction.ParseLine(bytes.TrimSuffix(raw, []byte{'\n'}))
		if perr == nil && (l.Kind == reaction.KindStop || l.Kind == reaction.KindCovered) {
			return part{}, fmt.Errorf("the list carried from: %w: line %d names a finding after line %d, which is refused: %w",
				ErrRefused, at.Line+int64(i)+1, at.Line, at.Err)
		}
	}
	accepted := bytes.Join(lines[:at.Line-1], nil)
	if list, err = reaction.JudgeCarrySource(route, accepted, now); err != nil {
		return part{}, fmt.Errorf("the list carried from: %w", refusal(err))
	}
	return part{list: list, accepted: accepted, leftOut: int64(len(lines)) - at.Line + 1, refused: at}, nil
}

// sameDir reports whether dir names the directory root holds. A dir that
// cannot be read is not that directory; the write into it reports why.
func sameDir(root *os.Root, dir string) (bool, error) {
	held, err := root.Stat(".")
	if err != nil {
		return false, err
	}
	named, err := os.Stat(dir)
	return err == nil && os.SameFile(held, named), nil
}

// coveredLines is a covered line for each finding a stop or covered line of
// old names that kept does not, for a list judged against a route of format
// into.
func coveredLines(old []byte, kept map[string]bool, into reaction.RouteFormat) ([][]byte, error) {
	var covered [][]byte
	complete := old[:bytes.LastIndexByte(old, '\n')+1]
	for raw := range bytes.Lines(complete) {
		l, err := reaction.ParseLine(bytes.TrimSuffix(raw, []byte{'\n'}))
		if err != nil {
			return nil, fmt.Errorf("the list carried from: %w", refusal(err))
		}
		var c reaction.Covered
		switch l.Kind {
		case reaction.KindStop:
			c = reaction.Covered{FindingID: l.Stop.FindingID, TenantID: l.Stop.TenantID, RunID: l.Stop.RunID,
				ProjectID: l.Stop.ProjectID, Scope: l.Stop.Scope, Subject: l.Stop.Subject, CreatedAt: l.Stop.CreatedAt}
		case reaction.KindCovered:
			c = l.Covered
		default:
			continue
		}
		if kept[c.FindingID] {
			continue
		}
		if into == reaction.FormatV1Alpha3 && c.Subject == "" {
			c.Scope, c.Subject = reaction.ScopeRun, c.RunID
		}
		line, err := c.Marshal()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		covered = append(covered, line)
	}
	return covered, nil
}

// retireList takes the write bits off the list in root, forces the change to
// disk, and answers the mode the list had.
func retireList(root *os.Root) (fs.FileMode, error) {
	return chmodList(root, func(m fs.FileMode) fs.FileMode { return m &^ 0o222 })
}

// chmodList gives the list in root the mode to makes of its own, through the
// file it checked is the list, forces the change to disk, and answers the
// mode before.
func chmodList(root *os.Root, to func(fs.FileMode) fs.FileMode) (fs.FileMode, error) {
	named, err := stoplist.Named(root)
	if err != nil {
		return 0, err
	}
	f, err := root.OpenFile(stoplist.FileName, os.O_RDONLY|stoplist.OpenFlags, 0)
	if err != nil {
		return 0, err
	}
	was := named.Mode().Perm()
	err = stoplist.CheckOpened(named, f)
	if err == nil {
		err = f.Chmod(to(was))
	}
	if err == nil {
		err = f.Sync()
	}
	return was, errors.Join(err, f.Close())
}

// readList reads the list root holds, with every check a plane's read makes;
// the caller holds the lock.
func readList(root *os.Root) ([]byte, error) {
	named, err := stoplist.Named(root)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(stoplist.FileName, os.O_RDONLY|stoplist.OpenFlags, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if err := stoplist.CheckOpened(named, f); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, reaction.MaxListBytes+1))
}
