package runs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// Plane is the plane's handle on a runs directory. It resolves tokens, looks
// a run up, and reads and raises a root's state; it has no method that opens,
// closes or lists a run, and nothing it does creates, rewrites or deletes a record. It
// takes no directory lock, so planes side by side share one directory, and a
// root's state is written only under that root's own lock file.
//
// The zero value is not a directory. Every method on it fails closed.
type Plane struct {
	d *dir
}

// OpenPlane opens dir for a plane. It refuses a group- or world-writable
// directory with ErrPermissions, a directory with no marker with
// ErrNotRunsDir, and one holding a file this package does not write with
// ErrForeignFile. It never turns a directory into a runs directory: that is
// the operator's.
func OpenPlane(dir string) (*Plane, error) {
	d, err := openDir(dir)
	if err != nil {
		return nil, err
	}
	if err := d.checkContents(); err != nil {
		return nil, errors.Join(err, d.close())
	}
	return &Plane{d: d}, nil
}

// Close releases the handle. A later call answers ErrClosed.
func (p *Plane) Close() error {
	if p == nil {
		return ErrClosed
	}
	return p.d.close()
}

// Run is an open run as a token resolved it.
type Run struct {
	ID string
	// Root is the run whose state this run shares.
	Root string
	// Who is the identity the run's record names.
	Who Identity
	// Expires is when the run stops resolving.
	Expires time.Time
}

// Resolve returns the run token names when it is open for who at now, its
// project included: planes of two projects that share a directory and a
// listener identity never resolve each other's runs. Every refusal is a
// *Refusal. The causes are judged in an order that tells a caller
// nothing it cannot already prove: the token's shape, then whether its
// secret is right, and only then whose run it is and whether it is still
// open. A zero now is expired, since it would leave every run unexpired.
func (p *Plane) Resolve(ctx context.Context, token string, who Identity, now time.Time) (Run, error) {
	if token == "" {
		return Run{}, refuse(CauseMissing, nil)
	}
	id, secret, err := parseToken(token)
	if err != nil {
		return Run{}, refuse(CauseMalformed, err)
	}
	if p == nil {
		return Run{}, refuse(CauseUnreadable, ErrClosed)
	}
	end, err := p.d.begin(ctx)
	if err != nil {
		return Run{}, refuse(CauseUnreadable, err)
	}
	defer end()
	rec, err := p.d.readRecord(id)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Run{}, refuse(CauseUnknown, nil)
	case err != nil:
		return Run{}, refuse(CauseUnreadable, err)
	case !secretMatches(secret, rec.SecretSHA256):
		return Run{}, refuse(CauseUnknown, nil)
	case rec.Who != who:
		return Run{}, refuse(CauseIdentity, nil)
	case rec.Closed():
		return Run{}, refuse(CauseClosed, nil)
	case now.IsZero() || !now.Before(rec.ExpiresAt):
		return Run{}, refuse(CauseExpired, nil)
	}
	return Run{ID: rec.ID, Root: rec.Root, Who: rec.Who, Expires: rec.ExpiresAt}, nil
}

// Lookup reads the record of run id, with its secret's hash left out, for a
// caller that needs to know whether a run is open, whose it is and what it
// shares state with. It refuses a run no record names with ErrNoRun, and like
// every method of a Plane it locks, creates and rewrites nothing.
func (p *Plane) Lookup(ctx context.Context, id string) (Record, error) {
	if p == nil {
		return Record{}, ErrClosed
	}
	if err := checkRunID(id); err != nil {
		return Record{}, err
	}
	end, err := p.d.begin(ctx)
	if err != nil {
		return Record{}, err
	}
	defer end()
	return p.d.lookup(id)
}

// State reads root's state. A missing or unreadable state file is an error:
// the operator wrote it when the root opened, so a missing one was removed,
// and reading it as a clean start would wash what the run took in.
func (p *Plane) State(ctx context.Context, root string) (State, error) {
	if p == nil {
		return State{}, ErrClosed
	}
	if err := checkRunID(root); err != nil {
		return State{}, err
	}
	end, err := p.d.begin(ctx)
	if err != nil {
		return State{}, err
	}
	defer end()
	return p.d.readState(root)
}

// Raise reads root's state under the root's exclusive lock, applies join to
// it, and when the result differs writes it whole and forces it to disk before
// it returns. The lock is taken through root's lock file, which Raise never
// creates: a missing one is an error. While another writer holds the lock,
// Raise tries again until ctx ends.
//
// join decides alone whether the state rises; nothing else writes it.
func (p *Plane) Raise(ctx context.Context, root string, join func(State) State) (err error) {
	if p == nil {
		return ErrClosed
	}
	if join == nil {
		return fmt.Errorf("%w: no join", ErrState)
	}
	if err := checkRunID(root); err != nil {
		return err
	}
	end, err := p.d.begin(ctx)
	if err != nil {
		return err
	}
	defer end()
	lock, err := p.d.openRegular(root+lockSuffix, os.O_RDWR)
	if err != nil {
		return fmt.Errorf("the lock of %s: %w", root, err)
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if err := lockWaiting(ctx, lock); err != nil {
		return err
	}
	cur, err := p.d.readState(root)
	if err != nil {
		return err
	}
	next := join(cur)
	if next == cur {
		return nil
	}
	body, err := encodeState(root, next)
	if err != nil {
		return err
	}
	if err := p.d.stillLocked(lock, root); err != nil {
		return err
	}
	return p.d.replace(root+stateTemp, root+stateSuffix, body)
}

// stillLocked refuses a raise whose lock file no longer stands at its name:
// another writer that opened the new file holds a lock of its own, so neither
// would keep the other out.
func (d *dir) stillLocked(lock *os.File, root string) error {
	held, err := lock.Stat()
	if err != nil {
		return err
	}
	now, err := d.root.Lstat(root + lockSuffix)
	if err != nil || !os.SameFile(held, now) {
		return fmt.Errorf("%w: %s", ErrLockChanged, root)
	}
	return nil
}
