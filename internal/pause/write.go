package pause

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy"
)

// fileMode is the mode every unsigned write leaves the pause file in:
// whoever may write it may lift every pause.
const fileMode fs.FileMode = 0o600

// signedFileMode is the mode a signed write leaves the file in. The plane's
// account reads it through the file's group and may not write it; the
// signature, not the mode, is what lifts a pause.
const signedFileMode fs.FileMode = 0o640

// beforeReplace, when a test sets it, runs after a signed write read the file
// and before it reads it again to replace it.
var beforeReplace func()

// Init writes a pause file that pauses nothing at path, and refuses with
// ErrExists when the name is taken, by a file or by a link.
func Init(ctx context.Context, path string) error {
	body, err := Marshal(Document{})
	if err != nil {
		return err
	}
	return create(ctx, path, body, fileMode)
}

// InitSigned writes a signed pause file that pauses nothing at path, of h
// signed with s and bound to path whatever h.File says, and refuses what
// Init refuses.
func InitSigned(ctx context.Context, path string, h Header, s Signer) error {
	file, err := BindingOf(path)
	if err != nil {
		return err
	}
	h.File = file
	body, err := signFile(h, Document{}, s)
	if err != nil {
		return err
	}
	return create(ctx, path, body, signedFileMode)
}

func create(ctx context.Context, path string, body []byte, mode fs.FileMode) error {
	return locked(ctx, path, func(root *os.Root) error {
		if err := files.CreateNoReplaceIn(root, filepath.Base(path), body, mode); err != nil {
			if errors.Is(err, files.ErrExists) {
				return fmt.Errorf("%w: %s", ErrExists, path)
			}
			return err
		}
		return nil
	})
}

// Add adds e to the pause file at path, refusing an entry Entry.Check
// refuses, an id the file holds already with ErrDuplicateID, an entry past
// MaxEntries, and a signed file with ErrSigned.
func Add(ctx context.Context, path string, e Entry) error {
	_, err := update(ctx, path, nil, adding(e))
	return err
}

// AddSigned is Add for a signed file, and returns what it signed: the next
// serial, signed with s. It refuses an unsigned file with ErrUnsigned, one
// bound to another path with ErrOtherFile, and one s.Accept refuses with
// ErrNotVouched, before it signs anything.
func AddSigned(ctx context.Context, path string, e Entry, s Signer) (SignedDocument, error) {
	return update(ctx, path, &s, adding(e))
}

func adding(e Entry) func(Document) (Document, error) {
	return func(d Document) (Document, error) {
		if slices.ContainsFunc(d.Entries, func(have Entry) bool { return have.ID == e.ID }) {
			return d, fmt.Errorf("%w: %q", ErrDuplicateID, e.ID)
		}
		d.Entries = append(d.Entries, e)
		return d, nil
	}
}

// Remove removes the entry under id from the pause file at path, refusing an
// id it does not hold with ErrNoEntry and a signed file with ErrSigned.
// Removing the last entry writes a document with none; nothing deletes the
// file, since a missing file blocks every call.
func Remove(ctx context.Context, path, id string) error {
	_, err := update(ctx, path, nil, removing(id))
	return err
}

// RemoveSigned is Remove for a signed file, as AddSigned is Add's.
func RemoveSigned(ctx context.Context, path, id string, s Signer) (SignedDocument, error) {
	return update(ctx, path, &s, removing(id))
}

func removing(id string) func(Document) (Document, error) {
	return func(d Document) (Document, error) {
		i := slices.IndexFunc(d.Entries, func(have Entry) bool { return have.ID == id })
		if i < 0 {
			return d, fmt.Errorf("%w: %q", ErrNoEntry, id)
		}
		d.Entries = slices.Delete(d.Entries, i, i+1)
		return d, nil
	}
}

// Listing is a pause file as its writer reads it: the entries and, for a
// signed file, what the body says of itself. The signature is not checked:
// that is the plane's, against its roster.
type Listing struct {
	Document
	Signed *SignedDocument
}

// List reads the pause file at path with every check a plane's read makes
// of the file, owned by this account, and takes no lock: a write replaces
// the file whole.
func List(path string) (Listing, error) {
	f, err := load(path, ownedByThisUser)
	if err != nil {
		return Listing{}, err
	}
	out := Listing{Document: f.doc}
	if f.signed != nil {
		body := f.signed.Body
		out.Signed = &body
	}
	return out, nil
}

// update reads the pause file under the lock, with every check a plane's
// read makes, and writes back what change makes of it: unsigned where s is
// nil, and otherwise signed with s at the next serial, the tenant, the
// project and the file kept, returning what it signed. A file the plane would
// refuse is refused here too, rather than rewritten into one it reads, and so
// is a signed write to an unsigned file and the reverse.
func update(ctx context.Context, path string, s *Signer, change func(Document) (Document, error)) (SignedDocument, error) {
	var signed SignedDocument
	err := locked(ctx, path, func(root *os.Root) error {
		f, raw, err := loadIn(root, path, ownedByThisUser)
		switch {
		case err != nil:
			return err
		case s == nil && f.signed != nil:
			return fmt.Errorf("%w: %s", ErrSigned, path)
		case s != nil && f.signed == nil:
			return fmt.Errorf("%w: %s", ErrUnsigned, path)
		case s != nil:
			if err := judgeFrom(path, *f.signed, *s); err != nil {
				return err
			}
		}
		next, err := change(Document{Entries: slices.Clone(f.doc.Entries)})
		if err != nil {
			return err
		}
		if s == nil {
			body, err := Marshal(next)
			if err != nil {
				return err
			}
			return files.ReplaceIn(root, filepath.Base(path), body, fileMode)
		}
		signed, err = replaceSigned(root, path, raw, *f.signed, next, *s)
		return err
	})
	return signed, err
}

// judgeFrom refuses from, the signed file a write starts from, unless it is
// bound to path and s.Accept takes it, before anything in it is signed again.
func judgeFrom(path string, from Signed, s Signer) error {
	h := from.Body.Header
	file, err := BindingOf(path)
	switch {
	case err != nil:
		return err
	case h.File != file:
		return fmt.Errorf("%w: it names %s and is at %s", ErrOtherFile, bounded(h.File), file)
	case s.Accept == nil:
		return fmt.Errorf("%w: nothing judges the file the write starts from", ErrSigner)
	}
	if err := s.Accept(from); err != nil {
		return fmt.Errorf("%w: serial %d signed by key %s: %w", ErrNotVouched, h.Serial, bounded(h.KeyID), err)
	}
	return nil
}

// replaceSigned signs next with s at the serial after from's, which
// judgeFrom took, keeping its tenant, project and file, and replaces the
// file through root, refusing one that is no longer raw, the bytes the write
// began from: a writer that skipped the lock would otherwise lose its entries
// unseen. It returns the header and the entries it signed.
func replaceSigned(root *os.Root, path string, raw []byte, from Signed, next Document, s Signer) (SignedDocument, error) {
	h := from.Body.Header
	if h.Serial >= policy.MaxSerial {
		return SignedDocument{}, fmt.Errorf("%w: %d", ErrSerial, h.Serial)
	}
	h.KeyID, h.Serial = s.KeyID, h.Serial+1
	body, err := signFile(h, next, s)
	if err != nil {
		return SignedDocument{}, err
	}
	if beforeReplace != nil {
		beforeReplace()
	}
	_, now, err := loadIn(root, path, ownedByThisUser)
	if err != nil || !bytes.Equal(now, raw) {
		return SignedDocument{}, errors.Join(fmt.Errorf("%w: %s; nothing was written, so read it and write again", ErrChanged, path), err)
	}
	if err := files.ReplaceIn(root, filepath.Base(path), body, signedFileMode); err != nil {
		return SignedDocument{}, err
	}
	return SignedDocument{Header: h, Document: next}, nil
}

// locked runs write through the pause file's directory, as openDir judged
// and opened it, under the exclusive lock on that directory: a directory the
// group or others may write, or another account than this process's
// effective user owns, is refused, since another owner could replace what
// this writer wrote there.
func locked(ctx context.Context, path string, write func(root *os.Root) error) error {
	if !permissionBits {
		return ErrNoPermissionBits
	}
	root, err := openDir(filepath.Dir(path), ownedByThisUser)
	if err != nil {
		return err
	}
	release, err := lockDir(ctx, root)
	if err != nil {
		return errors.Join(err, root.Close())
	}
	return errors.Join(write(root), release(), root.Close())
}
