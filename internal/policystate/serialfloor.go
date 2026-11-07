package policystate

import (
	"context"
	"errors"
	"fmt"
)

// serialAt is where a serial floor stands, or where a document asks it to
// stand: a serial and the digest at it, and for a document that grows under
// one serial the length and SHA-256 of the part taken. A floor with no serial
// holds 0 and no digest; a kind whose documents do not grow holds no length.
type serialAt struct {
	serial int64
	digest string
	length int64
	prefix string
}

// serialRefusals are what one kind of serial floor refuses with: a serial
// or digest no document carries, a serial below the floor's, the floor's
// serial with another digest, and at the floor's serial and digest a part
// shorter than the floor's or of its length with other bytes.
type serialRefusals struct {
	invalid, below, forked, rewritten Error
}

// takes reports whether a floor at f takes next by raising itself to it. A
// floor with no serial holds 0, below every document's; a higher serial is
// taken; at next's serial and digest a longer part is taken and the floor's
// own part as it is; a lower serial, the same with another digest, and a
// shorter part or one of the floor's length with another SHA-256 are refused.
// Whether a longer part begins with the floor's is the caller's to check.
func (r serialRefusals) takes(f, next serialAt) (raise bool, err error) {
	switch {
	case next.serial > f.serial:
		return true, nil
	case next.serial < f.serial:
		return false, fmt.Errorf("%w: serial %d, the floor's %d", r.below, next.serial, f.serial)
	case next.digest != f.digest:
		return false, fmt.Errorf("%w: serial %d", r.forked, next.serial)
	case next.length > f.length:
		return true, nil
	case next.length < f.length || next.prefix != f.prefix:
		return false, fmt.Errorf("%w: %d bytes, the floor's %d", r.rewritten, next.length, f.length)
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
// replaces the file whole, as does a longer part at the floor's serial and
// digest, and the floor's serial with its digest and part leaves it as it was. It refuses a next of serial 0 and every refusal of check, takes,
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
