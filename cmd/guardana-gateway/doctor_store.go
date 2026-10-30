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
	"github.com/guardana/control/internal/spool"
)

// evidence reads the spool where it will run, as `run` would open it, and
// changes nothing there: the directory has to exist, be writable and hold
// nothing that does not check. A torn tail a start would cut is named and
// left in place, and a directory a running spool holds is refused, since
// `run` would be refused it too.
func (d *examination) evidence(context.Context) (string, string, string) {
	dir := d.cfg.Resolve(d.cfg.Evidence.Dir)
	found, err := spool.Inspect(evidenceOptions(d.cfg))
	switch {
	case err != nil:
		return verdictFail, "evidence", "evidence: " + err.Error()
	case found.Held:
		return verdictFail, "evidence", fmt.Sprintf("%s: %v, so run with this configuration would be refused; nothing in it was read",
			filepath.ToSlash(dir), spool.ErrLocked)
	}
	if err := writable(dir); err != nil {
		return verdictFail, "evidence", err.Error()
	}
	return verdictOK, "evidence", fmt.Sprintf("access(2), which reads mode bits, a read-only mount and the ACLs the kernel applies, "+
		"lets this account create a file in %s; %d segment(s), %d byte(s) unacknowledged, %d quarantined; "+
		"a start would cut a torn tail of %d byte(s), which this check left in place; on_unwritable %s",
		filepath.ToSlash(dir), found.Segments, found.Unacknowledged, found.QuarantinedRecords, found.Torn,
		d.cfg.Evidence.OnUnwritable)
}

// writable asks access(2) whether this process may create a file in dir,
// without creating one, because the spool's lock does not prove it: on unix it
// is taken on the directory, which a process with no permission to write in it
// can still open. access(2) does not see a rule a security module applies to
// paths, a file system that answers it without checking, or a full disk.
func writable(dir string) error {
	if err := mayWrite(dir); err != nil {
		return fmt.Errorf("the directory is not writable: %w", err)
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
