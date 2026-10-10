package approvals

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// The defaults a directory is opened with. They bound what a writer of the
// directory can make the plane do: the work of a scan, and the bytes one
// record can cost.
const (
	// DefaultMaxRecords bounds the records under the directory.
	DefaultMaxRecords = 1024
	// DefaultMaxRecordBytes bounds one record's body. An approval with a
	// reason at MaxReasonBytes is far below it.
	DefaultMaxRecordBytes = 16 << 10
	// DefaultMaxApprovalWindow bounds how far a record's expiry may stand
	// from the time it was requested where nothing configures the plane's own
	// approval lifetime. It is far above any lifetime an operator would
	// choose, because a bound below the configured one would refuse the
	// plane's own records.
	DefaultMaxApprovalWindow = 24 * time.Hour
)

type options struct {
	maxRecords        int
	maxRecordBytes    int
	maxApprovalWindow time.Duration
	steps             func(step string)
}

// Option configures a directory at Open.
type Option func(*options) error

// WithMaxRecords bounds the records the directory may hold. A hold past it is
// refused, and a listing past it is reported incomplete rather than short.
func WithMaxRecords(n int) Option {
	return func(o *options) error {
		if n <= 0 {
			return fmt.Errorf("%w: max records %d is not positive", ErrInvalidOption, n)
		}
		o.maxRecords = n
		return nil
	}
}

// WithMaxRecordBytes bounds one record's body, on the way in and on the way
// out.
func WithMaxRecordBytes(n int) Option {
	return func(o *options) error {
		if n <= 0 {
			return fmt.Errorf("%w: max record bytes %d is not positive", ErrInvalidOption, n)
		}
		o.maxRecordBytes = n
		return nil
	}
}

// WithMaxApprovalWindow bounds how far a record's expiry may stand from the
// time it was requested: the longest window this plane could have minted, which
// is its configured approval lifetime. A record past it is refused on the way
// in and on the way back.
//
// It does not make a forged record impossible. Write access to the directory is
// the approval authority, and a writer picks its own expiry; the bound is how
// long such a record can stand before it expires and is pruned like any other.
func WithMaxApprovalWindow(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return fmt.Errorf("%w: max approval window %s is not positive", ErrInvalidOption, d)
		}
		o.maxApprovalWindow = d
		return nil
	}
}

// store is one directory, opened once. Both handles embed it, and neither
// exports it: a composite literal of either from another package has no open
// store, so every method on it fails closed.
type store struct {
	mu sync.Mutex
	// dir is the directory as the caller named it, for what a refusal says
	// and for judging whether the name still names root.
	dir string
	// root is the directory as it was opened. Every file is reached through
	// it, never through dir.
	root *os.Root
	opts options
	// open is read by usable before a call takes mu, so Close beside a call
	// is answered ErrClosed rather than raced.
	open   atomic.Bool
	unlock func() error
	// opened is the directory as it was judged at open, and every call is
	// judged against it again.
	opened dirID
}

// storeMarker says the directory is an approvals store. A directory that does
// not hold it is refused rather than read as an empty store, so a plane
// pointed at the wrong path holds every material call instead of approving
// from nowhere.
type storeMarker struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
}

const markerKind = "approvals"

var markerKeys = []string{"schema_version", "kind"}

// openStore opens dir. The plane takes the directory's exclusive lock and
// sweeps the temporary files a crash left; the approver takes no lock and
// sweeps nothing, because it is not alone in the directory.
func openStore(dir string, plane bool, opts []Option) (*store, error) {
	o := options{
		maxRecords:        DefaultMaxRecords,
		maxRecordBytes:    DefaultMaxRecordBytes,
		maxApprovalWindow: DefaultMaxApprovalWindow,
	}
	for _, apply := range opts {
		if err := apply(&o); err != nil {
			return nil, err
		}
	}
	root, opened, err := openRoot(dir)
	if err != nil {
		return nil, err
	}
	s := &store{dir: dir, root: root, opts: o, unlock: root.Close, opened: opened}
	s.step(stepOpened)
	if plane {
		held, err := lockDirWaiting(root, dir)
		if err != nil {
			return nil, errors.Join(err, root.Close())
		}
		s.unlock = func() error { return errors.Join(held.Close(), root.Close()) }
		s.step(stepLocked)
		if err := s.judge(); err != nil {
			return nil, errors.Join(err, s.unlock())
		}
	}
	if err := s.init(plane); err != nil {
		return nil, errors.Join(err, s.unlock())
	}
	s.open.Store(true)
	return s, nil
}

// How long OpenPlane keeps trying a directory something holds for a moment,
// and how often. An approver has to take the lock to learn whether a plane
// holds it, and it releases it at once; a plane that refused to start inside
// that window would be a failure nobody could diagnose. A plane that is
// genuinely running holds the lock for its whole life, so waiting only delays
// the refusal it was always going to get.
const (
	lockWait          = 250 * time.Millisecond
	lockRetryInterval = 2 * time.Millisecond
)

// lockDirWaiting takes the directory's lock, retrying while something else
// holds it, up to lockWait. Only contention is retried: a platform with no
// lock, and a directory that cannot be opened, answer at once.
func lockDirWaiting(root *os.Root, dir string) (*os.File, error) {
	deadline := time.Now().Add(lockWait)
	for {
		held, err := lockDir(root, dir)
		if err == nil || !errors.Is(err, ErrLocked) || !time.Now().Before(deadline) {
			return held, err
		}
		time.Sleep(lockRetryInterval)
	}
}

// init reads the marker, creating it for a plane over an empty directory, and
// refuses a directory holding anything this package did not write.
func (s *store) init(plane bool) error {
	entries, err := s.readDir()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotAStore, err)
	}
	marker, temps, foreign := sortEntries(entries)
	// The marker decides first: a directory that is not a store is refused as
	// that, whatever else is in it, so a plane pointed at somebody else's
	// directory reads one refusal rather than a report about their files.
	if err := s.marker(plane, marker, len(entries) == len(temps)); err != nil {
		return err
	}
	if foreign != "" {
		return fmt.Errorf("%w: %q", ErrForeignFile, cause(foreign))
	}
	if !plane {
		return nil
	}
	return s.sweep(temps)
}

// sortEntries says what a directory listing holds: whether the marker is
// there, which files are unlinked writes, and the first name this package did
// not write.
func sortEntries(entries []os.DirEntry) (marker bool, temps []string, foreign string) {
	for _, e := range entries {
		// An entry that is not a regular file is foreign whatever it is
		// called, so nothing here opens a pipe and waits for a writer.
		if !e.Type().IsRegular() {
			if foreign == "" {
				foreign = e.Name()
			}
			continue
		}
		switch kind, _, _ := classify(e.Name()); kind {
		case kindMarker:
			marker = true
		case kindTemp:
			temps = append(temps, e.Name())
		case kindRecord, kindView:
		case kindForeign:
			if foreign == "" {
				foreign = e.Name()
			}
		}
	}
	return marker, temps, foreign
}

// marker reads the directory's marker, or writes one where a plane opens an
// empty directory. Anything else is not a store.
func (s *store) marker(plane, present, empty bool) error {
	switch {
	case present:
		return s.readMarker()
	case plane && empty:
		return s.writeMarker()
	}
	return fmt.Errorf("%w: %q holds no %s", ErrNotAStore, s.dir, markerFile)
}

// sweep removes the writes no writer linked into place. Only the plane sweeps,
// under its lock, which keeps another plane's writes out of reach but not an
// approver's: an approver writing as the plane starts can lose its temporary
// file, and its Answer then fails without filing anything.
func (s *store) sweep(temps []string) error {
	for _, name := range temps {
		if err := s.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %w", ErrNotAStore, err)
		}
	}
	return nil
}

func (s *store) readMarker() error {
	raw, err := s.readBounded(markerFile, 4<<10)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotAStore, err)
	}
	if err := checkMembers(raw, markerKeys...); err != nil {
		return fmt.Errorf("%w: the marker: %w", ErrNotAStore, err)
	}
	var m storeMarker
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%w: %s", ErrNotAStore, cause(err.Error()))
	}
	if m.Kind != markerKind {
		return fmt.Errorf("%w: the marker names kind %q", ErrNotAStore, cause(m.Kind))
	}
	if err := checkSchemaVersion(m.SchemaVersion); err != nil {
		return fmt.Errorf("%w: the marker: %w", ErrNotAStore, err)
	}
	return nil
}

func (s *store) writeMarker() error {
	raw, err := json.Marshal(storeMarker{SchemaVersion: SchemaVersion, Kind: markerKind})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotAStore, err)
	}
	if err := s.commit(markerFile, append(raw, '\n')); err != nil {
		return fmt.Errorf("%w: %w", ErrNotAStore, err)
	}
	return nil
}

// usable reports whether the handle may act. The zero value of either handle
// has no store at all, which is the fail-closed answer a composite literal
// from another package gets.
func (s *store) usable() error {
	if s == nil || !s.open.Load() {
		return ErrClosed
	}
	return nil
}

// close releases the lock once.
func (s *store) close() error {
	if s == nil {
		return ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open.Swap(false) {
		return ErrClosed
	}
	return s.unlock()
}
