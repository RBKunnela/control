package stoplist

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardana/control/internal/reaction"
)

// Options configure a Poller.
type Options struct {
	// Dir is the directory holding the stop list.
	Dir string
	// Route is the route every read is judged against.
	Route reaction.Route
	// Interval is how often the list is read, and the tolerance a line's
	// created_at has over the plane's clock; a snapshot answers for three of
	// them.
	Interval time.Duration
	// Clock is the plane's clock.
	Clock func() time.Time
	// Logger takes each change of the state and each stop that becomes
	// active or ends; nil logs nothing.
	Logger *slog.Logger
	// Owner is whose account the list and its directory are owned by:
	// OwnedByAnother under the signed authority.
	Owner Owner
	// Take, when set, is what the list each read accepts is held to, with
	// the bytes read, whether or not its accepted part grew: the stop list
	// floor under the signed authority, which another reader may have raised
	// since. A refusal makes the read Unknown and keeps the list accepted
	// before.
	Take func(l reaction.List, content []byte) error
}

// PollStats is what a Poller counted since Open.
type PollStats struct {
	// Polls counts the reads, the first included.
	Polls uint64
	// Failed counts the reads that were Unknown, by cause.
	Failed map[reaction.Cause]uint64
	// Active is how many entries the last read held active at its clock.
	Active int
}

// Poller reads the stop list every interval and serves the last read as an
// immutable snapshot. Each read is judged from the prefix the reads before
// accepted, and an Unknown read keeps that prefix, so a list that shrank or
// was rewritten stays Unknown until it extends the accepted prefix again.
type Poller struct {
	opts    Options
	current atomic.Pointer[reaction.Snapshot]

	// mu serialises the polls, so each judges from the one before, and
	// guards what they count.
	mu     sync.Mutex
	stats  PollStats
	active map[string]reaction.Entry
}

// Open checks o, reads the list once and returns a poller serving that read,
// or refuses: with ErrOptions for an empty directory, a route that was never
// read, a nil clock or an interval that is not positive, and with
// ErrNotServable naming the cause for a first read that is Unknown, so a
// plane never starts on a stop list it cannot read.
func Open(o Options) (*Poller, error) {
	if o.Dir == "" || o.Route.Digest() == "" || o.Clock == nil || o.Interval <= 0 {
		return nil, ErrOptions
	}
	p := &Poller{opts: o, stats: PollStats{Failed: map[reaction.Cause]uint64{}}}
	if first := p.Poll(); first.State() == reaction.Unknown {
		return nil, fmt.Errorf("%w: %s: %s", ErrNotServable, first.Cause(), first.Detail())
	}
	return p, nil
}

// Current is the snapshot of the last read. A nil poller, and one nothing
// read, serve the zero snapshot, which is Unknown.
func (p *Poller) Current() reaction.Snapshot {
	if p == nil {
		return reaction.Snapshot{}
	}
	if s := p.current.Load(); s != nil {
		return *s
	}
	return reaction.Snapshot{}
}

// Poll reads the list now, judges it from the prefix accepted so far,
// publishes the snapshot and returns it. A file that cannot be read is
// Unknown with the file's cause, and keeps the accepted prefix. What a
// signed read asks its voucher again is held to one interval, so ports that
// do not answer in it leave the read Unknown rather than the poll stalled.
func (p *Poller) Poll() reaction.Snapshot {
	if p == nil {
		return p.Current()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.opts.Clock()
	prev := p.Current()
	var next reaction.Snapshot
	raw, err := ReadAs(p.opts.Dir, p.opts.Owner)
	if err != nil {
		next = prev.Unknown(CauseOf(err), err.Error(), now, p.opts.Interval)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), p.opts.Interval)
		next = prev.NextContext(ctx, p.opts.Route, raw, now, p.opts.Interval)
		cancel()
	}
	if t := p.opts.Take; t != nil && next.State() != reaction.Unknown {
		if err := t(next.AcceptedList(), raw); err != nil {
			next = prev.Unknown(CauseOf(err), err.Error(), now, p.opts.Interval)
		}
	}
	p.current.Store(&next)
	p.count(prev, next, now)
	return next
}

// Run polls at once and then every interval until ctx ends. A nil poller
// only waits for ctx.
func (p *Poller) Run(ctx context.Context) {
	if p == nil {
		<-ctx.Done()
		return
	}
	p.Poll()
	t := time.NewTicker(p.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Poll()
		}
	}
}

// Stats is what the poller counted so far.
func (p *Poller) Stats() PollStats {
	if p == nil {
		return PollStats{Failed: map[reaction.Cause]uint64{}}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.stats
	out.Failed = maps.Clone(p.stats.Failed)
	return out
}

// count counts one read, with p.mu held, and logs what it changed.
func (p *Poller) count(prev, next reaction.Snapshot, now time.Time) {
	p.stats.Polls++
	first := p.stats.Polls == 1
	if next.State() == reaction.Unknown {
		p.stats.Failed[next.Cause()]++
		p.stats.Active = 0
	} else {
		p.stats.Active = p.track(next, now)
	}
	log := p.opts.Logger
	if log == nil || (!first && prev.State() == next.State() && prev.Cause() == next.Cause()) {
		return
	}
	if next.State() == reaction.Unknown {
		log.Warn("stop state unknown; every call is blocked",
			"dir", p.opts.Dir, "cause", string(next.Cause()), "detail", next.Detail())
		return
	}
	log.Info("stop state changed", "dir", p.opts.Dir, "state", next.State().String(), "active", p.stats.Active)
}

// track replaces the active entries with those next holds active at now,
// logs each that became active or ended, and returns how many are active.
// An entry that ends while no lift names it expired.
func (p *Poller) track(next reaction.Snapshot, now time.Time) int {
	unlifted := map[string]bool{}
	active := map[string]reaction.Entry{}
	for _, e := range next.Entries() {
		unlifted[e.EntryID] = true
		if now.Before(e.ExpiresAt) {
			active[e.EntryID] = e
		}
	}
	if log := p.opts.Logger; log != nil {
		for id, e := range active {
			if _, was := p.active[id]; !was {
				log.Info("stop active", "entry_id", id, "finding_id", e.FindingID, "run_id", e.RunID,
					"expires_at", e.ExpiresAt)
			}
		}
		for id, e := range p.active {
			if _, is := active[id]; !is {
				how := "lifted"
				if unlifted[id] {
					how = "expired"
				}
				log.Info("stop ended", "entry_id", id, "finding_id", e.FindingID, "run_id", e.RunID, "how", how)
			}
		}
	}
	p.active = active
	return len(active)
}
