package pause

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Options configure a Poller.
type Options struct {
	// Path is the pause file.
	Path string
	// Interval is how often the file is read; a snapshot answers for three
	// of them.
	Interval time.Duration
	// Clock is the plane's clock, the one its calls judge a snapshot's age by.
	Clock func() time.Time
	// Logger takes each change of the snapshot; nil logs nothing.
	Logger *slog.Logger
	// Judge, when set, is what every read is judged by under the signed
	// authority, with ReadSigned; nil reads with Read.
	Judge Judge
	// PlaneOwned lets a signed read take a file the plane's own account
	// owns. Only a dev plane sets it: its one account is the operator's too.
	PlaneOwned bool
	// UnlistedOnly names the entries of a read that pause only calls
	// carrying no provider, which are calls to names no upstream lists. A
	// change that leaves any is logged at warn, naming them; nil names none.
	UnlistedOnly func([]Entry) []string
}

// PollStats is what a Poller counted since Open.
type PollStats struct {
	// Polls counts the reads, the first included.
	Polls uint64
	// Failed counts the reads that were Unknown, by cause.
	Failed map[Cause]uint64
	// Changes counts the reads whose state, cause or entries differ from the
	// read before, the first included.
	Changes uint64
}

// Poller reads the pause file every interval and serves the last read as an
// immutable snapshot. A read that fails replaces the last good one: a file
// that broke is never answered for by the file it was.
type Poller struct {
	opts    Options
	current atomic.Pointer[Snapshot]

	mu    sync.Mutex
	stats PollStats
}

// Open checks o, reads the file once and returns a poller serving that read,
// or refuses: with ErrOptions for an empty path, a nil clock or an interval
// that is not positive, and with
// ErrNotServable naming the cause for a first read that is Unknown, so a
// plane never starts on a pause file it cannot read.
func Open(o Options) (*Poller, error) {
	if o.Path == "" || o.Clock == nil || o.Interval <= 0 {
		return nil, ErrOptions
	}
	p := &Poller{opts: o, stats: PollStats{Failed: map[Cause]uint64{}}}
	if first := p.Poll(); first.State() == Unknown {
		return nil, fmt.Errorf("%w: %s: %s", ErrNotServable, first.Cause(), first.Detail())
	}
	return p, nil
}

// Current is the last read. A poller nothing read, and a nil one, serve the
// zero snapshot, which is Unknown.
func (p *Poller) Current() Snapshot {
	if p == nil {
		return Snapshot{}
	}
	if s := p.current.Load(); s != nil {
		return *s
	}
	return Snapshot{}
}

// Poll reads the file now, publishes the read and returns it. A signed read
// is held to one interval: a roster or a floor that does not answer in it
// leaves the read Unknown rather than the poll stalled.
func (p *Poller) Poll() Snapshot {
	var s Snapshot
	if p.opts.Judge == nil {
		s = Read(p.opts.Path, p.opts.Clock(), p.opts.Interval)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), p.opts.Interval)
		o := ownedByAnother
		if p.opts.PlaneOwned {
			o = anyOwner
		}
		s = readSignedAs(ctx, p.opts.Path, p.opts.Clock(), p.opts.Interval, p.opts.Judge, o)
		cancel()
	}
	prev := p.current.Swap(&s)
	p.count(prev, s)
	return s
}

// Run polls at once and then every interval until ctx ends. The first poll
// is not left to the first tick: a start slower than three intervals would
// otherwise leave the calls before it under a stale read.
func (p *Poller) Run(ctx context.Context) {
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
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.stats
	out.Failed = maps.Clone(p.stats.Failed)
	return out
}

// count counts one read and logs it when it changed the snapshot.
func (p *Poller) count(prev *Snapshot, next Snapshot) {
	added, removed := diff(prev, next)
	changed := prev == nil || prev.state != next.state || prev.Cause() != next.Cause() ||
		len(added) > 0 || len(removed) > 0
	p.mu.Lock()
	p.stats.Polls++
	if next.state == Unknown {
		p.stats.Failed[next.Cause()]++
	}
	if changed {
		p.stats.Changes++
	}
	p.mu.Unlock()
	if !changed || p.opts.Logger == nil {
		return
	}
	if next.state == Unknown {
		p.opts.Logger.Warn("pause state unknown; every call is blocked",
			"path", p.opts.Path, "cause", string(next.Cause()), "detail", next.detail)
		return
	}
	level, unlisted := slog.LevelInfo, []string(nil)
	if p.opts.UnlistedOnly != nil {
		unlisted = p.opts.UnlistedOnly(next.Entries())
	}
	if len(unlisted) > 0 {
		level = slog.LevelWarn
	}
	p.opts.Logger.Log(context.Background(), level, "pause state changed",
		"path", p.opts.Path, "state", next.state.String(), "entries", len(next.entries),
		"added", added, "removed", removed, "unlisted_only", unlisted)
}

// diff names the ids of the entries next holds and prev does not, and the
// reverse, an entry changed under its id counting as both.
func diff(prev *Snapshot, next Snapshot) (added, removed []string) {
	var before []Entry
	if prev != nil {
		before = prev.entries
	}
	for _, e := range next.entries {
		if !slices.ContainsFunc(before, func(b Entry) bool { return sameEntry(b, e) }) {
			added = append(added, e.ID)
		}
	}
	for _, b := range before {
		if !slices.ContainsFunc(next.entries, func(e Entry) bool { return sameEntry(b, e) }) {
			removed = append(removed, b.ID)
		}
	}
	return added, removed
}
