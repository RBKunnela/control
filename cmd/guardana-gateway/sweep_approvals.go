package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/guardana/control/internal/gateway"
)

// minRecordSweep is the shortest interval between two sweeps of the approval
// stores. Each sweep reads every record and every mark, up to
// approvals.max_records of each, so a tiny lifetime must not make it spin.
const minRecordSweep = time.Second

// recordSweepEvery is how often a serving plane sweeps its approval stores:
// a quarter of the approval lifetime, so a record or a mark is forgotten at
// most a quarter of a lifetime late, and never more often than once a second.
func recordSweepEvery(ttl time.Duration) time.Duration {
	return max(ttl/4, minRecordSweep)
}

// sweepApprovals sweeps the approval stores every recordSweepEvery until ctx
// ends. A sweep in flight when ctx ends runs to its end: its work is bounded
// by the stores' own bounds, and stopping it half way would read as a
// failure.
func (p *plane) sweepApprovals(ctx context.Context) {
	tick := time.NewTicker(recordSweepEvery(p.cfg.Approvals.TTL))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.sweepStores(context.WithoutCancel(ctx), time.Now())
		}
	}
}

// sweepStores forgets, at now, the approval records that expired and then the
// ledger marks older than one approval lifetime. ALREADY_USED rests on a live
// record and a spent mark together, and a mark is written after its record's
// request, so a mark this forgets speaks only for a record expired at now.
// A pass whose records sweep failed leaves the marks and the inbox for the
// next one, so no mark goes while the records beside it are unread. Last go the
// inbox answers to approvals no longer held. A failure is counted and logged;
// nothing here blocks a call or stops the plane.
func (p *plane) sweepStores(ctx context.Context, now time.Time) {
	if p.records != nil {
		n, err := p.records.Prune(ctx, now)
		p.sweeps.note(p.logger, sweptRecords, n, err)
		if err != nil {
			return
		}
	}
	n, err := p.pipeline.PruneLedger(ctx, now)
	p.sweeps.note(p.logger, sweptMarks, n, err)
	if p.inbox != nil {
		pruned, err := p.pruneInbox(ctx, now)
		p.sweeps.note(p.logger, sweptAnswers, pruned.Removed, err)
		p.sweeps.refuse(pruned.Refused)
	}
}

// swept names one of the two stores a sweep reaches.
type swept int

const (
	sweptRecords swept = iota
	sweptMarks
	sweptAnswers
)

// sweptWhat is how a log line names each store.
var sweptWhat = [...]string{sweptRecords: "approval records", sweptMarks: "ledger marks", sweptAnswers: "inbox answers"}

// sweepCounts is what the sweeps of a serving plane forgot and how often one
// failed, by store, with the cause last logged for each: a failure is logged
// when its cause differs from the one before, and a recovery once.
type sweepCounts struct {
	mu        sync.Mutex
	forgotten [3]uint64
	failed    [3]uint64
	cause     [3]string
	// refused is the inbox answers a sweep could not unlink.
	refused uint64
}

// refuse counts answers the inbox sweep was not allowed to remove.
func (c *sweepCounts) refuse(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refused += uint64(max(n, 0))
}

// note counts one sweep of store, which forgot n and ended with err.
func (c *sweepCounts) note(logger *slog.Logger, store swept, n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forgotten[store] += uint64(max(n, 0))
	if err == nil {
		if c.cause[store] != "" {
			logger.Info("the sweep of "+sweptWhat[store]+" reads the whole store again", "forgotten", n)
			c.cause[store] = ""
		}
		return
	}
	c.failed[store]++
	if cause := oneLine(err.Error()); cause != c.cause[store] {
		c.cause[store] = cause
		logger.Error("the sweep of "+sweptWhat[store]+" stopped early; the store keeps what it did not reach, and refuses holds at its bound",
			"forgotten", n, "err", err)
	}
}

// counters is the sweeps as /healthz reports them.
func (c *sweepCounts) counters() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{
		"records_forgotten": c.forgotten[sweptRecords], "records_failed": c.failed[sweptRecords],
		"marks_forgotten": c.forgotten[sweptMarks], "marks_failed": c.failed[sweptMarks],
		"answers_forgotten": c.forgotten[sweptAnswers], "answers_failed": c.failed[sweptAnswers],
		"answers_refused": c.refused,
	}
}

var _ gateway.LedgerPruner = (*spentLedger)(nil)

// Prune forgets the marks of the ledger beside the journal written before
// before, in the pipeline's vocabulary.
func (l *spentLedger) Prune(ctx context.Context, before time.Time) (int, error) {
	n, err := l.ledger.Prune(ctx, before)
	return n, ledgerError(err)
}
