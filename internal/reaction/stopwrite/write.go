package stopwrite

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"time"

	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// fileMode is the mode a new list is written with; a plane refuses a list the
// group or others may write.
const fileMode fs.FileMode = 0o600

// listIDPrefix begins every list id this package draws.
const listIDPrefix = "lst-"

// judged, when a test sets it, runs once the judge accepted an append and
// before a byte of it is written.
var judged func()

// Init starts a stop list in dir, which must exist and pass the plane's
// checks, holding only the header of a list id drawn here, judged against
// route at the writer's clock now. It refuses with ErrExists when the list's
// name is taken, by a file or by a link, and returns the header written.
func Init(ctx context.Context, dir string, route reaction.Route, now time.Time) (reaction.Header, error) {
	h, err := newHeader(route)
	if err != nil {
		return reaction.Header{}, err
	}
	line, err := h.Marshal()
	if err != nil {
		return reaction.Header{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if err := create(ctx, dir, route, now, [][]byte{line}); err != nil {
		return reaction.Header{}, err
	}
	return h, nil
}

// AppendLift appends l, signed elsewhere, to the list in dir, judged against
// route at the writer's clock now, and returns its line number. The writer
// holds no key: a lift the route's lift key did not sign is refused.
func AppendLift(ctx context.Context, dir string, route reaction.Route, l reaction.LiftLine, now time.Time) (int64, error) {
	return appendLine(ctx, dir, route, at(now), fixed(l.Marshal()))
}

// AppendFinding appends, for the finding of the stop stopAt makes, a covered
// line of that finding when the list holds a stop of its run and tenant
// active at the writer's clock that lasts at least as long as the stop, and
// the stop itself when it holds none: a stop with a longer lifetime is never
// cut short by covering it under a shorter one. The clock is read once the
// lock is held and stopAt makes the stop from that reading, so the wait for
// the lock shortens no stop and a line another writer added during it is not
// ahead of the reading. The choice is made under the lock, over the list as
// it stands, so two writers never stop one run twice for one lifetime.
// stopAt runs before the list is searched for the finding, so its refusal
// stands even for a finding another writer named meanwhile. It refuses a
// stop naming a rule version a later one superseded, which only a carry
// brings, and returns the line number, the stop and whether the line is
// covered.
func AppendFinding(ctx context.Context, dir string, route reaction.Route, clock func() time.Time,
	stopAt func(now time.Time) (reaction.Stop, error),
) (int64, reaction.Stop, bool, error) {
	var s reaction.Stop
	covered := false
	n, err := appendLine(ctx, dir, route, clock, func(list reaction.List, now time.Time) ([]byte, error) {
		var err error
		if s, err = stopAt(now); err != nil {
			return nil, err
		}
		if err := reaction.CheckCurrent(s); err != nil {
			return nil, err
		}
		// Named before the bound is judged, so a finding another writer
		// named reads as named even on a full list.
		if list.Names(s.FindingID) {
			return nil, ErrNamed
		}
		covered = slices.ContainsFunc(list.Entries(), func(e reaction.Entry) bool {
			return e.RunID == s.RunID && e.TenantID == s.TenantID && e.ActiveAt(now, time.Time{}) && !e.ExpiresAt.Before(s.ExpiresAt)
		})
		if covered {
			return reaction.Covered{FindingID: s.FindingID, TenantID: s.TenantID, RunID: s.RunID, CreatedAt: s.CreatedAt}.Marshal()
		}
		return s.Marshal()
	})
	if err != nil {
		return 0, reaction.Stop{}, false, err
	}
	return n, s, covered, nil
}

// lineFor builds the line to append from the list as it stands under the
// lock and the writer's clock read there.
type lineFor func(list reaction.List, now time.Time) ([]byte, error)

// fixed is a line that does not depend on the list or the clock.
func fixed(line []byte, err error) lineFor {
	return func(reaction.List, time.Time) ([]byte, error) { return line, err }
}

// at is a clock that reads now.
func at(now time.Time) func() time.Time { return func() time.Time { return now } }

// appendLine appends the line build makes under the lock. The clock is read
// once the lock is held; the list is read with every check a plane's read
// makes and judged, the line is built from it, and the list with the line
// after its last complete line is judged again, with no tolerance past the
// reading; only a list the judge accepts is written. Bytes after the last
// newline are a line a writer did not finish, and are cut before the append.
// A refused write changes nothing.
func appendLine(ctx context.Context, dir string, route reaction.Route, clock func() time.Time, build lineFor) (int64, error) {
	if err := stopping(route); err != nil {
		return 0, err
	}
	var n int64
	err := locked(ctx, dir, func(root *os.Root) error {
		named, err := stoplist.Named(root)
		if err != nil {
			return err
		}
		f, err := root.OpenFile(stoplist.FileName, os.O_RDWR|os.O_APPEND|stoplist.OpenFlags, 0)
		if err != nil {
			return err
		}
		n, err = appendTo(f, named, route, clock(), build)
		return errors.Join(err, f.Close())
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func appendTo(f *os.File, named fs.FileInfo, route reaction.Route, now time.Time, build lineFor) (int64, error) {
	if err := stoplist.CheckOpened(named, f); err != nil {
		return 0, err
	}
	content, err := io.ReadAll(io.LimitReader(f, reaction.MaxListBytes+1))
	if err != nil {
		return 0, err
	}
	// Past the bound, the bytes after the last newline read are not a torn
	// tail but lines never read, which a cut would delete.
	if len(content) > reaction.MaxListBytes {
		return 0, fmt.Errorf("%w: %w: limit %d", ErrFull, stoplist.ErrTooLarge, reaction.MaxListBytes)
	}
	complete := content[:bytes.LastIndexByte(content, '\n')+1]
	before, err := reaction.Judge(route, reaction.Prefix{}, complete, now, 0)
	if err != nil {
		return 0, refusal(err)
	}
	line, err := build(before, now)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	next := append(append(bytes.Clone(complete), line...), '\n')
	list, err := reaction.JudgeFrom(route, before, next, now, 0)
	if err != nil {
		return 0, refusal(err)
	}
	if judged != nil {
		judged()
	}
	if len(complete) < len(content) {
		if err := f.Truncate(int64(len(complete))); err != nil {
			return 0, err
		}
	}
	if _, err := f.Write(next[len(complete):]); err != nil {
		return 0, err
	}
	if err := f.Sync(); err != nil {
		return 0, err
	}
	return list.Usage().Lines, nil
}

// create writes lines as a new list in dir, under the lock, once the judge
// accepts them; the name is never replaced.
func create(ctx context.Context, dir string, route reaction.Route, now time.Time, lines [][]byte) error {
	if err := stopping(route); err != nil {
		return err
	}
	body := append(bytes.Join(lines, []byte{'\n'}), '\n')
	if _, err := reaction.Judge(route, reaction.Prefix{}, body, now, 0); err != nil {
		return refusal(err)
	}
	return locked(ctx, dir, func(root *os.Root) error {
		if err := files.CreateNoReplaceIn(root, stoplist.FileName, body, fileMode); err != nil {
			if errors.Is(err, files.ErrExists) {
				return fmt.Errorf("%w: %s", ErrExists, dir)
			}
			return err
		}
		return nil
	})
}

// stopping refuses a route naming a rule that may not stop a run. A caller
// may hand a writer a route no signed file held, so the writer checks it
// rather than trust that the caller verified it.
func stopping(route reaction.Route) error {
	if err := reaction.CheckStopping(route); err != nil {
		return fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return nil
}

// refusal wraps a judge's refusal of the list a write would make.
func refusal(err error) error {
	if errors.Is(err, reaction.ErrListTooLarge) || errors.Is(err, reaction.ErrListLines) {
		return fmt.Errorf("%w: %w", ErrFull, err)
	}
	return fmt.Errorf("%w: %w", ErrRefused, err)
}

// locked runs write through dir, as the plane's reader judges and opens it,
// under the exclusive lock on that directory.
func locked(ctx context.Context, dir string, write func(root *os.Root) error) error {
	root, err := stoplist.OpenDir(dir)
	if err != nil {
		return err
	}
	release, err := lockDir(ctx, root)
	if err != nil {
		return errors.Join(err, root.Close())
	}
	return errors.Join(write(root), release(), root.Close())
}

// newHeader is the header of a list judged against route under a list id
// of 128 random bits.
func newHeader(route reaction.Route) (reaction.Header, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return reaction.Header{}, err
	}
	return reaction.HeaderFor(route, listIDPrefix+hex.EncodeToString(id[:])), nil
}
