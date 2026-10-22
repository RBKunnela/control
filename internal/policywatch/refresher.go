package policywatch

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/guardana/control/internal/policy"
)

// Refresher reads the bundle and the statement every interval and moves the
// holder only as the statement and the floor allow.
type Refresher struct {
	o Options

	// mu serializes the reading and judging of the files; the bytes judged
	// are its. The clock mark has its own lock, so a poll held up reading or
	// raising never keeps the next one from judging the clock.
	mu        sync.Mutex
	bundle    *diskBundle
	statement *diskStatement
	// latestSeen is the latest issuedAt a floor this refresher read or
	// confirmed held; a floor read back below it is a restored copy.
	latestSeen time.Time
	// beforeRead, when set, is called with each file's path just before a
	// poll reads it.
	beforeRead func(path string)

	clockMu sync.Mutex
	clock   mark

	// statsMu guards the counts, the last outcome logged and the monotonic
	// reading of the last completed poll.
	statsMu sync.Mutex
	stats   Stats
	last    string
	polled  time.Duration
}

// New checks o and takes the first reading of both clocks, the clock mark's
// first value.
func New(o Options) (*Refresher, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	r := &Refresher{o: o, stats: Stats{Refused: map[Cause]uint64{}}, polled: o.Mono()}
	r.clock.back(o.Wall(), o.Mono())
	return r, nil
}

// Poll reads both files once and moves the holder as they allow. Nothing is
// installed or confirmed while the wall clock stands more than a second
// below the mark; a new bundle is installed only with the statement bound to
// it; and anything refused leaves the snapshot, its confirmation and the
// floor as they were, counted under its cause.
func (r *Refresher) Poll(ctx context.Context) {
	defer r.polledNow()
	r.count(func(s *Stats) { s.Polls++ })
	now, back := r.judgeClock()
	if back {
		r.refuse(CauseClockBack, ErrClockBack)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.o.Holder.Current()
	if cur == nil {
		r.refuse(CauseFloor, ErrNoSnapshot)
		return
	}
	r.reading(r.o.BundlePath)
	r.bundle = readBundle(r.o, r.bundle)
	if r.bundle.err != nil {
		r.refuse(r.bundle.cause, r.bundle.err)
		return
	}
	r.reading(r.o.StatementPath)
	r.statement = readStatement(r.o, r.statement)
	if r.statement.err != nil {
		r.refuse(r.statement.cause, r.statement.err)
		return
	}
	st, disk := r.statement.st, r.bundle.snap
	if disk.Ref().GetDigest() == cur.Ref().GetDigest() {
		r.renew(ctx, cur, st, now)
		return
	}
	r.replace(ctx, cur, st)
}

// renew judges st against the current bundle, which is the bundle on disk;
// now is the poll's reading of the wall clock.
func (r *Refresher) renew(ctx context.Context, cur *policy.Snapshot, st policy.Statement, now time.Time) {
	switch {
	case binds(st, cur) && cur.ConfirmedAt().Equal(st.IssuedAt()):
		if err := r.floorStillTakes(ctx, st, now); err != nil {
			r.refuse(causeOf(err), err)
			return
		}
		r.settle("confirmed")
	case binds(st, cur):
		r.confirm(ctx, cur, st, nil)
	case st.BundleID() == r.o.BundleID && st.Serial() > cur.Serial():
		r.await(&r.stats.AwaitingBundle, "the statement names a bundle not yet on disk", st)
	default:
		r.refuse(CauseStatementUnbound, fmt.Errorf("%w: it names %s serial %d", policy.ErrStatementUnbound, st.BundleID(), st.Serial()))
	}
}

// floorStillTakes reads the floor for a poll that would otherwise settle
// without the store, and refuses a floor that cannot be read, that would not
// take st, the statement the current bundle was confirmed by, at now, that
// stands below st, which the confirmation raised it to, or whose latest
// statement is older than one a floor read or confirmed here held. The read
// is bounded by the poll interval, as a raise is.
func (r *Refresher) floorStillTakes(ctx context.Context, st policy.Statement, now time.Time) error {
	read, cancel := context.WithTimeout(ctx, r.o.Interval)
	defer cancel()
	f, err := r.o.Floor.Floor(read, r.o.BundleID)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %w", policy.ErrFloorRead, err)
	case f.BundleID() != r.o.BundleID:
		return fmt.Errorf("%w: the store returned the floor of another bundle id", policy.ErrFloorRead)
	}
	if f.LatestIssuedAt().Before(r.latestSeen) {
		return fmt.Errorf("%w: its latest statement issued %s, after one issued %s was read", ErrFloorBehind,
			policy.FormatIssuedAt(f.LatestIssuedAt()), policy.FormatIssuedAt(r.latestSeen))
	}
	// Taken from every floor read, refused or not, so a floor raised
	// elsewhere and then restored to an older copy is still seen going back.
	r.latestSeen = f.LatestIssuedAt()
	if err := f.Takes(st, now); err != nil {
		return err
	}
	if !f.HasSerial() || f.Serial() < st.Serial() || (f.Serial() == st.Serial() && f.IssuedAt().Before(st.IssuedAt())) {
		return fmt.Errorf("%w: floor serial %d issued %s, confirmed serial %d issued %s", ErrFloorBehind,
			f.Serial(), policy.FormatIssuedAt(f.IssuedAt()), st.Serial(), policy.FormatIssuedAt(st.IssuedAt()))
	}
	return nil
}

// replace judges the bundle on disk, which is not the current one, and st.
func (r *Refresher) replace(ctx context.Context, cur *policy.Snapshot, st policy.Statement) {
	disk := r.bundle.snap
	switch {
	case disk.Serial() < cur.Serial():
		r.refuse(CauseRollback, fmt.Errorf("%w: serial %d after %d", policy.ErrRollback, disk.Serial(), cur.Serial()))
		return
	case disk.Serial() == cur.Serial():
		r.refuse(CauseSerialReused, fmt.Errorf("%w: serial %d", policy.ErrSerialReused, disk.Serial()))
		return
	}
	if err := outlastsPoll(disk, r.o); err != nil {
		r.refuse(CauseBundleBudget, err)
		return
	}
	switch {
	case binds(st, disk):
		r.confirm(ctx, disk, st, r.bundle)
	case binds(st, cur):
		r.await(&r.stats.AwaitingStatement, "the bundle on disk awaits its statement", st)
	case st.BundleID() == r.o.BundleID && st.Serial() > disk.Serial():
		r.await(&r.stats.AwaitingBundle, "the statement names a bundle not yet on disk", st)
	default:
		r.refuse(CauseStatementUnbound, fmt.Errorf("%w: it names %s serial %d", policy.ErrStatementUnbound, st.BundleID(), st.Serial()))
	}
}

// confirm confirms snap by st: a renewal of the current bundle when install
// is nil, and otherwise the install of the bundle install holds. A statement
// whose budget has run out when it would be published is refused before
// the floor is raised.
func (r *Refresher) confirm(ctx context.Context, snap *policy.Snapshot, st policy.Statement, install *diskBundle) {
	// The clock is judged again under its lock, held until the holder has
	// published or refused, so a withdrawal cannot land between the two, and
	// expiry is judged on that same reading, the moment st would be
	// published; the raise is bounded, since the holder keeps its own lock
	// across it and the clock rule needs both.
	r.clockMu.Lock()
	defer r.clockMu.Unlock()
	now := r.o.Wall()
	if r.clock.back(now, r.o.Mono()) {
		r.withdraw()
		r.refuse(CauseClockBack, ErrClockBack)
		return
	}
	if expired(st, snap, r.o.MaxStale, now) {
		r.refuse(CauseStatementExpired, expiry(st, snap, r.o.MaxStale))
		return
	}
	raise, cancel := context.WithTimeout(ctx, r.o.Interval)
	defer cancel()
	var err error
	if install == nil {
		err = r.o.Holder.Confirm(raise, st, now)
	} else {
		err = r.o.Holder.InstallConfirmed(raise, install.msg, r.o.BundleKeys, st, now)
	}
	if err != nil {
		r.refuse(causeOf(err), err)
		return
	}
	if st.IssuedAt().After(r.latestSeen) {
		r.latestSeen = st.IssuedAt()
	}
	r.count(func(s *Stats) {
		s.Confirmations++
		if install != nil {
			s.Installs++
		}
	})
	r.settle("")
	if r.o.Logger != nil {
		r.o.Logger.Info("policy confirmed", "serial", st.Serial(), "digest", st.Digest(),
			"issued_at", policy.FormatIssuedAt(st.IssuedAt()), "installed", install != nil)
	}
}

// withdraw unconfirms the snapshot, counting a confirmation it took back.
func (r *Refresher) withdraw() {
	if cur := r.o.Holder.Current(); cur != nil && !cur.ConfirmedAt().IsZero() {
		r.count(func(s *Stats) { s.Withdrawals++ })
		if r.o.Logger != nil {
			r.o.Logger.Warn("the wall clock stepped back past the mark; the policy is unconfirmed until a newer statement",
				"withdrawn", policy.FormatIssuedAt(cur.ConfirmedAt()))
		}
	}
	r.o.Holder.Unconfirm()
}

// refuse counts a poll that moved nothing under cause, and logs it when the
// outcome changed since the poll before.
func (r *Refresher) refuse(cause Cause, err error) {
	r.count(func(s *Stats) { s.Refused[cause]++ })
	if r.changed("refused " + string(cause)) {
		r.o.Logger.Warn("policy refresh refused; the last good snapshot stays", "cause", string(cause), "err", err)
	}
}

// await counts a poll that found one file of a pair, and logs it when the
// outcome changed since the poll before.
func (r *Refresher) await(counter *uint64, what string, st policy.Statement) {
	r.count(func(*Stats) { *counter++ })
	if r.changed(what) {
		r.o.Logger.Info(what, "statement_serial", st.Serial(), "statement_digest", st.Digest())
	}
}

// settle notes a poll that found the snapshot as it should be.
func (r *Refresher) settle(outcome string) { r.changed(outcome) }

// changed records outcome and reports whether it differs from the last one
// and there is a logger to tell.
func (r *Refresher) changed(outcome string) bool {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	differs := outcome != r.last
	r.last = outcome
	return differs && r.o.Logger != nil
}

// reading is called before a poll reads the file at path.
func (r *Refresher) reading(path string) {
	if r.beforeRead != nil {
		r.beforeRead(path)
	}
}

func (r *Refresher) count(f func(*Stats)) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	f(&r.stats)
}

// Run polls every interval, and judges the clock on a timer of its own,
// until ctx ends.
func (r *Refresher) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(1)
	go r.watchClock(ctx, &wg)
	defer wg.Wait()
	t := time.NewTicker(r.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Poll(ctx)
		}
	}
}

// Stats is what the refresher counted so far.
func (r *Refresher) Stats() Stats {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	out := r.stats
	out.Refused = make(map[Cause]uint64, len(r.stats.Refused))
	for k, v := range r.stats.Refused {
		out.Refused[k] = v
	}
	return out
}
