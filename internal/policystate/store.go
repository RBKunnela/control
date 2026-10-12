package policystate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/guardana/control/internal/policy"
)

// Kind is whose floors a directory keeps. A plane's and a signer's are never
// one directory: each side refuses the other's marker.
type Kind string

// The kinds a marker names.
const (
	// KindPlane is the floors of the planes that enforce one authority's
	// bundles.
	KindPlane Kind = "plane"
	// KindSigner is the floors of the signer that renews statements.
	KindSigner Kind = "signer"
)

func checkKind(k Kind) error {
	if k != KindPlane && k != KindSigner {
		return fmt.Errorf("%w: %q", ErrKind, clip(string(k)))
	}
	return nil
}

// Record is a floor as its file holds it.
type Record struct {
	Floor policy.Floor
	// Reset is nil while the operator never reset the floor.
	Reset *ResetNote
}

// ResetNote is the operator's last reset of a floor: why, and the floor it
// replaced. A raise keeps it, so a plane started after a reset can say so.
type ResetNote struct {
	Reason string
	// From is the floor the reset replaced, one with no serial when the
	// file was missing.
	From policy.Floor
	// FileMissing is true when the reset found no file to replace, so the
	// floor before it is not known.
	FileMissing bool
}

// Store is the plane's handle on a floor directory. It reads a floor and
// raises one; it has no method that creates a floor file or lowers a floor.
// It holds no floor in memory: every call reads the file.
//
// The zero value is not a directory. Every method on it answers ErrClosed.
type Store struct {
	d    *dir
	kind Kind
}

var _ policy.FloorStore = (*Store)(nil)

// Open opens dir as a floor directory of kind and writes nothing to it. It
// refuses a kind that is neither with ErrKind; a path where no directory
// stands, a link, or a directory with no marker with ErrNotStateDir; the
// other kind's directory with ErrWrongKind; a directory or marker another
// user owns with ErrOwner, or one open to the group or the world with
// ErrPermissions; and a directory holding anything this package does not
// write with ErrForeignFile.
func Open(dir string, kind Kind) (*Store, error) {
	return OpenContext(context.Background(), dir, kind)
}

// OpenContext opens as Open does and waits for the directory's lock, which
// it holds while it judges what the directory holds, only until ctx ends.
func OpenContext(ctx context.Context, dir string, kind Kind) (*Store, error) {
	if err := checkKind(kind); err != nil {
		return nil, err
	}
	d, err := openDir(dir)
	if err != nil {
		return nil, err
	}
	if err := d.judgeLocked(ctx, kind); err != nil {
		return nil, errors.Join(err, d.close())
	}
	return &Store{d: d, kind: kind}, nil
}

// judgeLocked judges what the directory holds under its lock, so no marker
// or floor file is read while Init or Reset replaces it.
func (d *dir) judgeLocked(ctx context.Context, kind Kind) (err error) {
	unlock, err := d.lock(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	entries, err := d.readDir()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	_, err = d.judgeContents(entries, kind)
	return err
}

// Close releases the handle. A later call answers ErrClosed.
func (s *Store) Close() error {
	if s == nil {
		return ErrClosed
	}
	return s.d.close()
}

// Floor reads the floor of bundleID from its file. A missing file is
// ErrNoFloor and never a floor with no serial, since a removed file is not a
// first start.
func (s *Store) Floor(ctx context.Context, bundleID string) (policy.Floor, error) {
	rec, err := s.Record(ctx, bundleID)
	if err != nil {
		return policy.Floor{}, err
	}
	return rec.Floor, nil
}

// Record reads the floor of bundleID and the operator's last reset of it,
// as Floor does. It holds the directory's lock while it reads, so it waits
// for a raise or a reset in progress, until ctx ends. An id the marker does
// not list is ErrNoFloor.
func (s *Store) Record(ctx context.Context, bundleID string) (_ Record, err error) {
	if s == nil {
		return Record{}, ErrClosed
	}
	end, err := s.d.begin(ctx)
	if err != nil {
		return Record{}, err
	}
	defer end()
	unlock, err := s.d.lock(ctx)
	if err != nil {
		return Record{}, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	return s.d.readListed(s.kind, bundleID)
}

// Raise holds the directory's exclusive lock while it reads the floor of st's
// bundle id from its file, raises that floor by st at the clock reading now,
// and, when the raised floor differs from the stored one, replaces the file
// whole before it returns the raised floor. A refusal by the stored floor's
// Raise, a missing file, or a read or write that fails is returned and leaves
// the file as it was; a write that failed after its rename may have left the
// raised floor, which is never lower. While another open file holds the lock,
// Raise tries again until ctx ends.
func (s *Store) Raise(ctx context.Context, st policy.Statement, now time.Time) (policy.Floor, error) {
	return s.RaiseWith(ctx, st, now, nil)
}

// RaiseWith raises as Raise does and, when the raise is taken, calls then
// with the raised floor while it still holds the directory's lock, so what
// then does is ordered with every other raise and read of the directory. A
// refused or failed raise never calls then. An error then returns is
// returned, and the raised floor stays written. then must not call s: the
// lock it would wait for is the one s holds.
func (s *Store) RaiseWith(ctx context.Context, st policy.Statement, now time.Time, then func(policy.Floor) error) (_ policy.Floor, err error) {
	if s == nil {
		return policy.Floor{}, ErrClosed
	}
	end, err := s.d.begin(ctx)
	if err != nil {
		return policy.Floor{}, err
	}
	defer end()
	unlock, err := s.d.lockToWrite(ctx)
	if err != nil {
		return policy.Floor{}, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	stored, err := s.d.readListed(s.kind, st.BundleID())
	if err != nil {
		return policy.Floor{}, err
	}
	next, err := stored.Floor.Raise(st, now)
	if err != nil {
		return policy.Floor{}, err
	}
	if !next.Equal(stored.Floor) {
		if err := s.d.writeRecord(Record{Floor: next, Reset: stored.Reset}); err != nil {
			return policy.Floor{}, err
		}
	}
	if then != nil {
		if err := then(next); err != nil {
			return policy.Floor{}, err
		}
	}
	return next, nil
}
