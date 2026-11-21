package trailfile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/segmentlog"
)

// ErrBinding is an event of a tenant or project other than the one the log
// is bound to. It matches otel.ErrSinkRefused too, so a receiver refuses the
// request for good and the sender quarantines the record.
const ErrBinding Error = "trailfile: an event of another tenant or project than the log's"

// LogConfig is what a log of trail segments opens with.
type LogConfig struct {
	// Dir is the log's directory.
	Dir string
	// Tenant and Project bind the log and every event it takes.
	Tenant, Project string
	// SegmentBytes and MaxBytes are the segment's and the log's byte bounds;
	// both zero takes no append, as a log opened to be pruned.
	SegmentBytes, MaxBytes int64
	// Now dates seals and prunes; nil is the system clock.
	Now func() time.Time
}

// Log keeps the evidence a collector accepts in trail segments, bound to one
// tenant and project. Every segment not pruned is indexed by event id, with
// where its line stands, so an event sent again after its segment was sealed
// is not written again once its line is read back where the log wrote it.
type Log struct {
	mu sync.Mutex
	rl segmentlog.RecordLog
	// dir is the log's directory by its absolute, cleaned path, the one the
	// segment log opened.
	dir string
	// dirInfo is the directory as the log opened it.
	dirInfo os.FileInfo
	bound   binding
	// ids places each line at its offset in the segments not pruned, read in
	// order, the live one last.
	ids index
	// stale is an index a prune left naming pruned lines; the next append
	// reads the segments left again first.
	stale bool
	// failed is a failure of the log that refuses every later call, an
	// append whose events the index holds included.
	failed error
}

// OpenLog opens the log in cfg.Dir, of the default kind, and holds it until
// Close. Every line of every segment not pruned is read and indexed, and the
// open is refused when a line is not one event, is of another tenant or
// project, or carries an event id another line carries with other content.
// The live segment is opened as Open opens a file, which cuts what a crash
// left of its last line.
func OpenLog(cfg LogConfig) (*Log, error) {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	if cfg.Dir == "" {
		return nil, fmt.Errorf("%w: no directory", segmentlog.ErrConfig)
	}
	dir, err := filepath.Abs(cfg.Dir)
	if err != nil {
		return nil, err
	}
	l := &Log{dir: dir, bound: binding{tenant: cfg.Tenant, project: cfg.Project}, ids: index{}}
	number, at := 0, int64(0)
	rl, err := segmentlog.Open(segmentlog.Config{
		Kind: segmentlog.KindSegments, Dir: dir, Tenant: cfg.Tenant, Project: cfg.Project,
		SegmentBytes: cfg.SegmentBytes, MaxBytes: cfg.MaxBytes, MaxLineBytes: evidence.MaxLineBytes, Now: now,
		OpenLive: openLive,
		Visit: func(line []byte) error {
			number++
			ev, err := l.ids.addLine(number, at, line)
			at += int64(len(line))
			if err == nil && l.bound.refusesEvent(ev) {
				err = fmt.Errorf("%w: %w: line %d", ErrDamaged, ErrBinding, number)
			}
			return err
		},
	})
	if err != nil {
		return nil, err
	}
	if l.dirInfo, err = os.Stat(dir); err != nil {
		return nil, errors.Join(err, rl.Close())
	}
	l.rl = rl
	return l, nil
}

// openLive opens the live segment as Open opens a trail file, by name in the
// directory the log judged and holds.
func openLive(root *os.Root, name string) (segmentlog.LiveFile, error) {
	w, err := openIn(root, name)
	if err != nil {
		return nil, err
	}
	return liveFile{w}, nil
}

// liveFile is a Writer taking lines the log encoded and indexed.
type liveFile struct{ w *Writer }

func (f liveFile) AppendLines(ctx context.Context, lines []byte) error {
	return liveChanged(f.w.appendLines(ctx, lines))
}

func (f liveFile) Check() error {
	return liveChanged(f.w.check())
}

// liveChanged marks a refusal after which the file is not what the log
// counted, a change under the writer or a cut back that failed.
func liveChanged(err error) error {
	if errors.Is(err, ErrChanged) || errors.Is(err, ErrFailed) {
		return fmt.Errorf("%w: %w", segmentlog.ErrLiveChanged, err)
	}
	return err
}

func (f liveFile) Close() error { return f.w.Close() }

// Append writes events as evidence lines and returns nil once they are
// synced. An event whose line the log holds, byte for byte, is taken and not
// written again once that line is read back where the log wrote it; a line
// gone, cut or changed fails the log and refuses the append. The whole
// append is refused as ErrBinding when one event is of another tenant
// or project, as ErrConflict when an event id the log or the append holds
// arrives with another line, and as segmentlog.ErrBudget when it would take
// the log past its byte bound, which is no refusal for good: the sender
// sends it again.
func (l *Log) Append(ctx context.Context, events []*controlv1.Event) error {
	for i, ev := range events {
		if l.bound.refusesEvent(ev) {
			return fmt.Errorf("%w: %w: event %d of the append", ErrBinding, otel.ErrSinkRefused, i)
		}
	}
	lines, err := encodeLines(events)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.rl == nil:
		return ErrClosed
	case l.failed != nil:
		return l.failed
	}
	if err := l.reindex(); err != nil {
		return err
	}
	buf, added, held, err := l.ids.fresh(events, lines, l.rl.Manifest().Retained)
	if err != nil {
		return err
	}
	if err := l.stillHeld(held); err != nil {
		return err
	}
	if len(buf) == 0 {
		return nil
	}
	if err := l.rl.Append(ctx, buf); err != nil {
		return l.latch(err)
	}
	l.ids.add(added)
	return nil
}

// latch keeps a failure of the segment log, so an append the index alone
// answers is refused too.
func (l *Log) latch(err error) error {
	if errors.Is(err, segmentlog.ErrFailed) {
		l.failed = err
	}
	return err
}

// Prune prunes the sealed segments through the one numbered through. The
// next append indexes the segments left again first, so an event whose line
// was pruned is written again when it is sent again.
func (l *Log) Prune(through int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.rl == nil:
		return ErrClosed
	case l.failed != nil:
		return l.failed
	}
	if err := l.rl.Prune(through); err != nil {
		return l.latch(err)
	}
	l.ids, l.stale = nil, true
	return nil
}

// reindex reads the segments a prune left into the index when it is stale.
// A read that fails fails the log, whose index no longer says what it holds.
func (l *Log) reindex() error {
	if !l.stale {
		return nil
	}
	// The segments are read again by the log's path, so the directory there
	// has to be the one the log holds, before and after the read. The log's
	// own count of the bytes it holds leaves out anything written past it,
	// and the offsets indexed count from the first segment not pruned, as
	// Append's do.
	err := l.sameDir()
	if err == nil {
		var r io.Reader
		var done func()
		if r, _, done, err = openLog(l.dir); err == nil {
			l.ids, err = readIndex(io.LimitReader(r, l.rl.Manifest().Retained))
			done()
		}
	}
	if err == nil {
		err = l.sameDir()
	}
	if err != nil {
		l.failed = fmt.Errorf("%w: the prune completed, and indexing the segments it left failed: %w", segmentlog.ErrFailed, err)
		return l.failed
	}
	l.stale = false
	return nil
}

// sameDir refuses a log path that no longer names the directory the log
// opened.
func (l *Log) sameDir() error {
	info, err := os.Stat(l.dir)
	switch {
	case err != nil:
		return err
	case !os.SameFile(info, l.dirInfo):
		return fmt.Errorf("%s is another directory than the log opened", strconv.Quote(l.dir))
	}
	return nil
}

// Manifest is the log as it is now.
func (l *Log) Manifest() segmentlog.Manifest {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rl == nil {
		return segmentlog.Manifest{}
	}
	return l.rl.Manifest()
}

// Close releases the log. A second Close does nothing.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rl == nil {
		return nil
	}
	err := l.rl.Close()
	l.rl = nil
	return err
}
