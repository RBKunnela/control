package holdjournal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/guardana/control/internal/core/approval"
)

const (
	// ledgerDir is the ledger's directory inside the journal's.
	ledgerDir = "ledger"
	// ledgerMarkerFile says the ledger directory is a ledger.
	ledgerMarkerFile = "ledger.meta"
	ledgerMarkerKind = "spent_ledger"
)

// Ledger is the plane's mark that it spent an approval or gave it up, kept in
// the ledger directory inside the journal's. It is reached only through a
// journal opened for writing, so it is written under that journal's exclusive
// lock and its mutex, and held to the journal's rules: owned by this account,
// writable by nobody else, no name this package did not write. A mark is made
// by a create that never replaces a name, so a spend is one compare-and-swap.
//
// A ledger closes with its journal.
type Ledger struct {
	j *Journal
	dirFiles
	// opened is what the ledger directory was at open, which the journal's
	// directory has to hold under ledgerDir still.
	opened fs.FileInfo
	// entries is how many marks the directory holds; only this process
	// writes them, under the lock.
	entries int
}

// Ledger opens the ledger directory of j, making it and its marker where the
// journal holds none, and sweeps the writes a crash left unfinished. It is the
// same handle on every call. A journal opened read-only has no ledger.
func (j *Journal) Ledger() (*Ledger, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.mayWrite(); err != nil {
		return nil, err
	}
	if j.ledger != nil {
		return j.ledger, nil
	}
	if err := j.root.Mkdir(ledgerDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("%w: the ledger: %w", ErrNotAJournal, err)
	}
	info, err := j.root.Lstat(ledgerDir)
	if err != nil {
		return nil, fmt.Errorf("%w: the ledger: %w", ErrNotAJournal, err)
	}
	if err := checkDir(info); err != nil {
		return nil, fmt.Errorf("the ledger: %w", err)
	}
	root, err := j.root.OpenRoot(ledgerDir)
	if err != nil {
		return nil, fmt.Errorf("%w: the ledger: %w", ErrNotAJournal, err)
	}
	l := &Ledger{j: j, dirFiles: dirFiles{root: root}, opened: info}
	if err := l.init(); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	j.ledger = l
	return l, nil
}

// init judges the directory as opened, then reads or writes its marker,
// refuses a foreign name, sweeps the temporary files and counts the marks.
func (l *Ledger) init() error {
	if err := l.judge(); err != nil {
		return err
	}
	names, temps, err := l.list()
	if err != nil {
		return err
	}
	marker, err := l.root.Lstat(ledgerMarkerFile)
	switch {
	case err == nil && marker.Mode().IsRegular():
		if err := l.readMarker(); err != nil {
			return err
		}
	case errors.Is(err, fs.ErrNotExist) && len(names) == 0:
		if err := l.writeMarker(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: the ledger holds no %s", ErrNotAJournal, ledgerMarkerFile)
	}
	for _, name := range temps {
		if err := l.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: the ledger: %w", ErrNotAJournal, err)
		}
	}
	l.entries = len(names)
	return nil
}

// list reads the directory: the marks, sorted, and the temporary files. A
// name this package did not write, or anything that is not a regular file,
// refuses the whole pass.
func (l *Ledger) list() (marks, temps []string, err error) {
	d, err := l.root.Open(".")
	if err != nil {
		return nil, nil, err
	}
	entries, err := d.ReadDir(-1)
	if err = errors.Join(err, d.Close()); err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		name := e.Name()
		isMark := isMarkName(name)
		switch {
		case !e.Type().IsRegular():
			return nil, nil, fmt.Errorf("%w: the ledger's %q is not a regular file", ErrForeignFile, cause(name))
		case isMark:
			marks = append(marks, name)
		case name == ledgerMarkerFile:
		case strings.HasPrefix(name, tmpPrefix) && strings.HasSuffix(name, tmpSuffix):
			temps = append(temps, name)
		default:
			return nil, nil, fmt.Errorf("%w: the ledger's %q", ErrForeignFile, cause(name))
		}
	}
	slices.Sort(marks)
	return marks, temps, nil
}

// judge holds the journal and the ledger directory to what they were at open.
func (l *Ledger) judge() error {
	if err := l.j.mayWrite(); err != nil {
		return err
	}
	now, err := l.root.Stat(".")
	if err != nil {
		return fmt.Errorf("%w: the ledger: %w", ErrDirectoryChanged, err)
	}
	if err := checkDir(now); err != nil {
		return fmt.Errorf("the ledger: %w", err)
	}
	named, err := l.j.root.Lstat(ledgerDir)
	if err != nil || !os.SameFile(l.opened, named) || !os.SameFile(now, named) {
		return fmt.Errorf("%w: another directory stands at the ledger's name", ErrDirectoryChanged)
	}
	return nil
}

func (l *Ledger) readMarker() error {
	raw, err := l.readBounded(ledgerMarkerFile, 4<<10)
	if err != nil {
		return fmt.Errorf("%w: the ledger: %w", ErrNotAJournal, err)
	}
	if err := checkMembers(raw, markerKeys...); err != nil {
		return fmt.Errorf("%w: the ledger's marker: %w", ErrNotAJournal, err)
	}
	var m journalMarker
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%w: %s", ErrNotAJournal, cause(err.Error()))
	}
	if m.Kind != ledgerMarkerKind {
		return fmt.Errorf("%w: the ledger's marker names kind %q", ErrNotAJournal, cause(m.Kind))
	}
	if err := checkSchemaVersion(m.SchemaVersion); err != nil {
		return fmt.Errorf("%w: the ledger's marker: %w", ErrNotAJournal, err)
	}
	return nil
}

func (l *Ledger) writeMarker() error {
	raw, err := json.Marshal(journalMarker{SchemaVersion: LedgerSchemaVersion, Kind: ledgerMarkerKind})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotAJournal, err)
	}
	if err := l.create(ledgerMarkerFile, append(raw, '\n')); err != nil {
		return fmt.Errorf("%w: the ledger: %w", ErrNotAJournal, err)
	}
	return nil
}

// begin holds the journal's mutex for one ledger call and judges both
// directories; the caller unlocks.
func (l *Ledger) begin(ctx context.Context, now time.Time) error {
	if l == nil || l.j == nil {
		return ErrClosed
	}
	if now.IsZero() {
		return ErrZeroTime
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	l.j.mu.Lock()
	if err := l.judge(); err != nil {
		l.j.mu.Unlock()
		return err
	}
	return nil
}

// Spend marks approval appr of request req under b consumed at now, with
// proof. It answers nil when this call made the mark, ErrSpent when the mark
// was there already, ErrSettled when the approval is marked not resumed, and
// ErrTooManyEntries at the bound. An error wrapping ErrMaybeRecorded is a
// mark that may stand: the caller runs nothing on it, and a later spend of
// the same approval finds it if it survived.
func (l *Ledger) Spend(ctx context.Context, b approval.Binding, req, appr, proof string, now time.Time) error {
	if err := checkMarkNames(b, req, appr); err != nil {
		return err
	}
	if err := l.begin(ctx, now); err != nil {
		return err
	}
	defer l.j.mu.Unlock()
	switch m, err := l.markOf(b, req, appr); {
	case err != nil:
		return err
	case m == MarkConsumed:
		return ErrSpent
	case m == MarkNotResumed:
		return ErrSettled
	}
	return l.mark(LedgerEntry{Mark: MarkConsumed, Binding: b, RequestID: req, ApprovalID: appr, Proof: proof, Written: now}, ErrSpent)
}

// Settle marks approval appr of request req under b not resumed at now. It
// answers nil when the mark is made now or was made before, and ErrSpent when
// the approval is marked consumed: that mark is proof of an execution and
// nothing writes over it.
func (l *Ledger) Settle(ctx context.Context, b approval.Binding, req, appr string, now time.Time) error {
	if err := checkMarkNames(b, req, appr); err != nil {
		return err
	}
	if err := l.begin(ctx, now); err != nil {
		return err
	}
	defer l.j.mu.Unlock()
	switch m, err := l.markOf(b, req, appr); {
	case err != nil:
		return err
	case m == MarkConsumed:
		return ErrSpent
	case m == MarkNotResumed:
		return nil
	}
	err := l.mark(LedgerEntry{Mark: MarkNotResumed, Binding: b, RequestID: req, ApprovalID: appr, Written: now}, nil)
	if errors.Is(err, errExists) {
		return nil
	}
	return err
}

// markOf is the mark of one approval, the consumed one first, read from the
// names alone: only this process writes them, under the lock.
func (l *Ledger) markOf(b approval.Binding, req, appr string) (Mark, error) {
	for _, m := range []Mark{MarkConsumed, MarkNotResumed} {
		info, err := l.root.Lstat(markName(b, req, appr, m))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return MarkUnknown, err
		case !info.Mode().IsRegular():
			return MarkUnknown, fmt.Errorf("%w: the ledger's mark of %q is not a regular file", ErrForeignFile, cause(req))
		}
		return m, nil
	}
	return MarkUnknown, nil
}

// mark files e under its name, which must not be there; lost is what an
// existing name answers.
func (l *Ledger) mark(e LedgerEntry, lost error) error {
	e.SchemaVersion = LedgerSchemaVersion
	body, err := encodeMark(e, l.j.opts.maxEntryBytes)
	if err != nil {
		return err
	}
	if l.entries >= l.j.opts.maxEntries {
		return fmt.Errorf("%w: the ledger holds %d marks, limit %d", ErrTooManyEntries, l.entries, l.j.opts.maxEntries)
	}
	err = l.create(markName(e.Binding, e.RequestID, e.ApprovalID, e.Mark), body)
	switch {
	case errors.Is(err, errExists):
		if lost != nil {
			return lost
		}
		return err
	case err == nil, errors.Is(err, ErrMaybeRecorded):
		l.entries++
	}
	return err
}

// Lookup answers every mark under b, keyed by request id. Where one request
// has marks under two approval ids, MarkConsumed wins. A mark under b that will
// not decode, or that disagrees with its name, refuses the whole lookup: it may
// be the one that refuses an execution.
func (l *Ledger) Lookup(ctx context.Context, b approval.Binding, now time.Time) (map[string]Mark, error) {
	if b == "" || len(b) > MaxLedgerBindingBytes {
		return nil, fmt.Errorf("%w: a binding of %d bytes, limit %d", ErrLedgerEntry, len(b), MaxLedgerBindingBytes)
	}
	if err := l.begin(ctx, now); err != nil {
		return nil, err
	}
	defer l.j.mu.Unlock()
	names, _, err := l.list()
	if err != nil {
		return nil, err
	}
	out := make(map[string]Mark)
	prefix := bindingPrefix(b)
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		e, err := l.readMark(name)
		if err != nil {
			return nil, err
		}
		if out[e.RequestID] != MarkConsumed {
			out[e.RequestID] = e.Mark
		}
	}
	return out, nil
}

// Prune removes every mark written before before and reports how many. A mark
// that will not decode cannot be dated and stays; the pass goes on and the
// refusal is returned beside the count.
func (l *Ledger) Prune(ctx context.Context, before time.Time) (int, error) {
	if err := l.begin(ctx, before); err != nil {
		return 0, err
	}
	defer l.j.mu.Unlock()
	names, _, err := l.list()
	if err != nil {
		return 0, err
	}
	pruned := 0
	var errs []error
	for _, name := range names {
		e, err := l.readMark(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !e.Written.Before(before) {
			continue
		}
		if err := l.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		pruned++
		l.entries = max(l.entries-1, 0)
	}
	if pruned > 0 {
		errs = append(errs, l.syncDir())
	}
	return pruned, errors.Join(errs...)
}

// readMark reads the mark filed under name and holds it to that name.
func (l *Ledger) readMark(name string) (LedgerEntry, error) {
	raw, err := l.readBounded(name, headerBytes+l.j.opts.maxEntryBytes)
	if err != nil {
		return LedgerEntry{}, err
	}
	e, err := decodeMark(raw, l.j.opts.maxEntryBytes)
	if err != nil {
		return LedgerEntry{}, fmt.Errorf("the ledger's %q: %w", cause(name), err)
	}
	if markName(e.Binding, e.RequestID, e.ApprovalID, e.Mark) != name {
		return LedgerEntry{}, fmt.Errorf("%w: the ledger's %q holds another mark", ErrNameMismatch, cause(name))
	}
	return e, nil
}

// close releases the ledger directory.
func (l *Ledger) close() error {
	if l == nil {
		return nil
	}
	return l.root.Close()
}
