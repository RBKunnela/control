package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/holdjournal"
)

// evidence opens the spool where it will run: the directory has to exist, take
// the lock, take a file, and whatever is already in it has to check. Opening
// cuts a torn tail, as a start would, and the line names what that cut.
func (d *examination) evidence(context.Context) (string, string, string) {
	dir := d.cfg.Resolve(d.cfg.Evidence.Dir)
	sp, err := openSpool(d.cfg)
	if err != nil {
		return verdictFail, "evidence", err.Error()
	}
	stats, statsErr := sp.Stats()
	closeErr := sp.Close()
	switch {
	case statsErr != nil:
		return verdictUnknown, "evidence", "the spool opened and cannot answer its stats: " + statsErr.Error()
	case closeErr != nil:
		return verdictUnknown, "evidence", "the spool opened and did not close: " + closeErr.Error()
	}
	if err := writable(dir); err != nil {
		return verdictFail, "evidence", err.Error()
	}
	return verdictOK, "evidence", fmt.Sprintf("%s locks and is writable; %d segment(s), %d byte(s) unacknowledged, %d reserved, %d quarantined; "+
		"opening it cut a torn tail of %d byte(s); on_unwritable %s",
		filepath.ToSlash(dir), stats.Segments, stats.Unacknowledged, stats.Reserved, stats.QuarantinedRecords, stats.Truncated,
		d.cfg.Evidence.OnUnwritable)
}

// writable proves the directory takes a file and gives it back, because the
// lock alone does not: on unix it is taken on the directory, which a process
// with no permission to write in it can still open.
func writable(dir string) error {
	probe, err := os.CreateTemp(dir, ".writable-*")
	if err != nil {
		return fmt.Errorf("the directory is not writable: %w", err)
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		return fmt.Errorf("the write probe did not close: %w", err)
	}
	if err := os.Remove(filepath.Clean(name)); err != nil {
		return fmt.Errorf("the write probe was left behind: %w", err)
	}
	return nil
}

// approvals says where a held request is kept and what a reconciliation would
// close. Each directory is judged as its store judges it, taking no lock and
// creating nothing: a lock an approver's probe saw would read as a plane
// waiting to consume their answer (ADR-0016). The records are left to `run`:
// the one lock-free handle on them is the approver's, which carries the method
// that answers an approval and which this binary must not hold, and the
// plane's own handle takes the lock and makes an unused directory a store.
func (d *examination) approvals(ctx context.Context) (string, string, string) {
	if d.cfg.Approvals.Provider != gatewayconfig.ProviderFile {
		return verdictOK, "approvals", fmt.Sprintf(
			"held requests are kept in process memory under the %s provider: nothing outside this process answers one, and a hold lost to a restart is never closed",
			d.cfg.Approvals.Provider)
	}
	for _, named := range []struct {
		key   string
		judge func(string) error
		dir   string
	}{
		{"approvals.dir", approvals.JudgeDirectory, d.cfg.Resolve(d.cfg.Approvals.Dir)},
		{"approvals.hold_journal_dir", holdjournal.JudgeDirectory, d.cfg.Resolve(d.cfg.Approvals.HoldJournalDir)},
	} {
		if err := named.judge(named.dir); err != nil {
			return verdictFail, "approvals", fmt.Sprintf("%s: %v", named.key, err)
		}
	}
	return d.holdJournal(ctx)
}

// holdJournal reports the holds a reconciliation would close, read through a
// handle that takes no lock and refuses every write. A directory no plane has
// made a journal yet is never read as an empty journal: it is reported as
// empty only where this check found it empty itself.
func (d *examination) holdJournal(ctx context.Context) (string, string, string) {
	dir, journalDir := d.cfg.Resolve(d.cfg.Approvals.Dir), d.cfg.Resolve(d.cfg.Approvals.HoldJournalDir)
	bounds := fmt.Sprintf("at most %d record(s) of %d byte(s), %d entry(ies) per pass",
		d.cfg.Approvals.MaxRecords, d.cfg.Approvals.MaxRecordBytes, d.cfg.Approvals.ReconcileMax)
	where := fmt.Sprintf("records in %s, holds in %s", filepath.ToSlash(dir), filepath.ToSlash(journalDir))
	journal, err := holdjournal.OpenReadOnly(journalDir,
		holdjournal.WithMaxEntries(d.cfg.Approvals.MaxRecords),
		holdjournal.WithMaxEntryBytes(d.cfg.Approvals.MaxRecordBytes))
	if err != nil {
		return unusedJournal(journalDir, where, bounds, err)
	}
	listing, listErr := journal.List(ctx, d.cfg.Approvals.ReconcileMax)
	if closeErr := journal.Close(); closeErr != nil {
		return verdictUnknown, "approvals", "the hold journal was read and did not close: " + closeErr.Error()
	}
	if listErr != nil {
		return verdictUnknown, "approvals", "the hold journal opened and cannot be read: " + listErr.Error()
	}
	found := fmt.Sprintf("%s; a restart would close %d lost hold(s), %d entry(ies) were left mid-close and %d will not decode; %s",
		where, len(listing.Held), listing.Interrupted, listing.Unreadable, bounds)
	if !listing.Complete {
		return verdictUnknown, "approvals", found + "; the pass did not read every entry, so those counts are a floor and not a total"
	}
	return verdictOK, "approvals", found
}

// unusedJournal reads a refusal of the journal directory against what is in
// it. An empty directory is one no plane has written a hold in, which is a
// pass with nothing to close; a directory holding anything else is refused as
// what it is, rather than reported as a journal with no holds.
func unusedJournal(dir, where, bounds string, refusal error) (string, string, string) {
	if !errors.Is(refusal, holdjournal.ErrNotAJournal) {
		return verdictFail, "approvals", fmt.Sprintf("approvals.hold_journal_dir: %v", refusal)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return verdictUnknown, "approvals", fmt.Sprintf("approvals.hold_journal_dir: %v", err)
	}
	if len(entries) > 0 {
		return verdictFail, "approvals", fmt.Sprintf("approvals.hold_journal_dir: %v", refusal)
	}
	return verdictOK, "approvals", fmt.Sprintf(
		"%s; no plane has written a hold here yet, so there is none to close; %s", where, bounds)
}
