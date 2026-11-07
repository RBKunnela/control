package pause

import (
	"context"
	"fmt"
	"time"
)

// Judge is what a plane under the signed authority takes a signed file
// through: its signature, its signer's authority over the plane's tenant and
// project, and its serial against the pause floor, which a taken document
// raises. It answers who signed, or a refusal wrapping one of this package's
// errors, which names the cause: ErrUnauthenticated, ErrOtherScope,
// ErrOtherFile, ErrUnauthorized, ErrAuthority, ErrBelowFloor, ErrForked or
// ErrFloor.
type Judge interface {
	Judge(ctx context.Context, f Signed) (SignedBy, error)
}

// ReadSigned is Read for a plane under the signed authority, judging with j.
// The file and its directory may not be owned by this process's effective
// user, which is the plane's account, and the file has to be signed and
// taken by j. A file that fails any of these reads as Unknown with that
// cause, as a file Read refuses does.
func ReadSigned(ctx context.Context, path string, now time.Time, interval time.Duration, j Judge) Snapshot {
	return readSignedAs(ctx, path, now, interval, j, ownedByAnother)
}

func readSignedAs(ctx context.Context, path string, now time.Time, interval time.Duration, j Judge, o owner) Snapshot {
	by, doc, err := readSigned(ctx, path, j, o)
	if err != nil {
		return unknown(causeOf(err), bounded(err.Error()), now, interval)
	}
	s := read(doc, now, interval)
	s.signed = &by
	return s
}

func readSigned(ctx context.Context, path string, j Judge, o owner) (SignedBy, Document, error) {
	if j == nil {
		return SignedBy{}, Document{}, ErrOptions
	}
	f, err := inspect(path, o)
	if err != nil {
		return SignedBy{}, Document{}, err
	}
	by, err := j.Judge(ctx, f)
	return by, f.Body.Document, err
}

// Inspect reads the signed file at path with every check ReadSigned makes of
// the file and its directory, and returns it unjudged: it is for a check
// that may not raise a floor.
func Inspect(path string) (Signed, error) {
	return inspect(path, ownedByAnother)
}

func inspect(path string, o owner) (Signed, error) {
	f, err := load(path, o)
	switch {
	case err != nil:
		return Signed{}, err
	case f.signed == nil:
		return Signed{}, fmt.Errorf("%w: %s", ErrUnsigned, path)
	}
	return *f.signed, nil
}
