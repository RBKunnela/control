package recovery

import (
	"errors"
	"fmt"

	"github.com/guardana/control/internal/gatewayconfig"
)

// holdPlane takes the locks a serving plane holds on the spool's and the
// hold journal's directories and returns what releases both. Holding them
// for the whole run keeps a plane from starting halfway through, which a
// check that no lock is held, made once, would not.
func holdPlane(cfg *gatewayconfig.Config) (func() error, error) {
	if cfg.Evidence.Dir == "" || cfg.Approvals.HoldJournalDir == "" {
		return nil, errors.New("evidence.dir and approvals.hold_journal_dir are both needed to keep a plane from starting")
	}
	releaseSpool, err := holdDir(cfg.Resolve(cfg.Evidence.Dir))
	if err != nil {
		return nil, fmt.Errorf("evidence.dir: %w", err)
	}
	releaseJournal, err := holdDir(cfg.Resolve(cfg.Approvals.HoldJournalDir))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("approvals.hold_journal_dir: %w", err), releaseSpool())
	}
	return func() error { return errors.Join(releaseJournal(), releaseSpool()) }, nil
}
