package policystate

import (
	"context"
	"errors"
	"fmt"
)

// serialAt is where a serial floor stands, or where a document asks it to
// stand: a serial and the digest at it. A floor with no serial holds 0 and no
// digest.
type serialAt struct {
	serial int64
	digest string
}

// serialRefusals are what one kind of serial floor refuses with: a serial
// or digest no document carries, a serial below the floor's, and the floor's
// serial with another digest.
type serialRefusals struct {
	invalid, below, forked Error
}

// takes reports whether a floor at f takes next by raising itself to it. A
// floor with no serial holds 0, below every document's; one at next's serial
// and digest takes it as it is; a lower serial, or the same with another
// digest, is refused.
func (r serialRefusals) takes(f, next serialAt) (raise bool, err error) {
	switch {
	case next.serial > f.serial:
		return true, nil
	case next.serial < f.serial:
		return false, fmt.Errorf("%w: serial %d, the floor's %d", r.below, next.serial, f.serial)
	case next.digest != f.digest:
		return false, fmt.Errorf("%w: serial %d", r.forked, next.serial)
	}
	return false, nil
}

// serialFloor is one kind of floor a raise moves: it checks itself, says
// where it stands and what it refuses with, and reads and writes the floor
// file of its own id.
type serialFloor[F any] interface {
	check() error
	at() serialAt
	refusals() serialRefusals
	readFrom(d *dir) (F, error)
	writeTo(d *dir) error
}

// raiseSerial holds the exclusive lock of the directory at path while it
// reads the floor of next's id, and takes next: a serial above the floor's
// replaces the file whole, and the floor's serial with its digest leaves it as
// it was. It refuses a next of serial 0 and every refusal of check, takes,
// readFrom and the directory, each leaving the file as it was. It returns the
// floor it leaves, and waits for the lock until ctx ends.
func raiseSerial[F serialFloor[F]](ctx context.Context, path string, next F) (_ F, err error) {
	var none F
	if err := next.check(); err != nil {
		return none, err
	}
	if next.at().serial == 0 {
		return none, fmt.Errorf("%w: serial 0", next.refusals().invalid)
	}
	d, err := openDir(path)
	if err != nil {
		return none, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	unlock, err := d.lockToWrite(ctx)
	if err != nil {
		return none, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	stored, err := next.readFrom(d)
	if err != nil {
		return none, err
	}
	raise, err := next.refusals().takes(stored.at(), next.at())
	switch {
	case err != nil:
		return none, err
	case !raise:
		return stored, nil
	}
	if err := next.writeTo(d); err != nil {
		return none, err
	}
	return next, nil
}
