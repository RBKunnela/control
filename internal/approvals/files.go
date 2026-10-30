package approvals

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/guardana/control/internal/files"
)

// errExists is a name another writer linked first. Each caller translates it
// into the refusal its own operation documents, so no caller has to read a
// file system error to learn that it lost a race.
const errExists Error = "approvals: the name exists already"

// commit writes body to a temporary file, forces it to disk, and links it to
// name. The link is the compare-and-swap: it fails with EEXIST when another
// writer got there first, and nothing in the request path waits on another
// process's lock. The temporary file is removed either way, and the directory
// is forced to disk after a successful link, so a name that was reported
// written survives a power loss.
//
// A failure after the link unlinks the name again. Nothing forces that unlink
// to disk, since forcing the directory is what just failed, so a power loss can
// bring the name back. Until the unlink another process may read the name, and
// one that unlinked it first leaves ErrOutcomeUnknown in the error; a failure of
// the unlink itself, which the error carries, leaves the name in place.
func (s *store) commit(name string, body []byte) error {
	tmp := tmpPrefix + rand.Text() + tmpSuffix
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return errors.Join(err, s.root.Remove(tmp))
	}
	err = s.root.Link(tmp, name)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errors.Join(errExists, s.root.Remove(tmp))
		}
		return errors.Join(err, s.root.Remove(tmp))
	}
	s.step(stepLinked)
	if err := errors.Join(s.root.Remove(tmp), s.syncDir()); err != nil {
		return errors.Join(err, s.undo(name))
	}
	return nil
}

// undo unlinks a name this store linked and could not make durable. A name
// that is already gone was unlinked by another process, which may have read it
// first, so it is reported as an unknown outcome rather than as not filed.
func (s *store) undo(name string) error {
	err := s.root.Remove(name)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %q", ErrOutcomeUnknown, cause(name))
	}
	return err
}

// syncDir forces a directory entry to disk, so a name that was linked before a
// power loss is there after it.
func (s *store) syncDir() error {
	d, err := s.root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// readDir lists the directory, sorted by name as os.ReadDir sorts it.
func (s *store) readDir() ([]os.DirEntry, error) {
	d, err := s.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := d.ReadDir(-1)
	if err = errors.Join(err, d.Close()); err != nil {
		return nil, err
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

// remove unlinks one name. A name that is already gone is not a failure: the
// unlink after a transition is what the order in the package documentation
// makes safe to lose.
func (s *store) remove(name string) error {
	if err := s.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// readBounded reads one file and refuses one larger than limit rather than
// holding what it claims to be. A file that is exactly limit bytes is read;
// one byte more is refused.
//
// The open does not block and the handle is held to a regular file, so a named
// pipe or a device a writer of the directory left behind refuses the call
// rather than waiting inside it for the mutex's whole lifetime.
func (s *store) readBounded(name string, limit int) ([]byte, error) {
	f, err := s.root.OpenFile(name, os.O_RDONLY|nonBlocking, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, cause(name))
	}
	if err := checkFile(name, info); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("%w: over %d bytes", ErrRecordTooLarge, limit)
	}
	return raw, nil
}

// checkFile refuses a file a group or the world may write, or another account
// owns. The directory being this account's alone does not keep out an account
// that may write the file itself, and what is in a record is an approval.
func checkFile(name string, info fs.FileInfo) error {
	if info.Mode().Perm()&writableByOthers != 0 {
		return fmt.Errorf("%w: %q has mode %04o", ErrForeignFile, cause(name), info.Mode().Perm())
	}
	if err := files.CheckOwnedBy(info, effectiveUID()); err != nil {
		return fmt.Errorf("%w: %q: %w", ErrForeignFile, cause(name), err)
	}
	return nil
}

// present reports, without following a link at name, whether name is the
// regular file this package writes: nil when it is, an error matching
// fs.ErrNotExist when nothing is there, and ErrForeignFile when something
// else is. A read follows a link, and takes one to a missing name for no name.
func (s *store) present(name string) error {
	info, err := s.root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, cause(name))
	}
	return nil
}

// listing is what one pass over the directory found: the approval ids, sorted,
// each with the furthest-along name present at that moment.
type listing struct {
	ids   []string
	state map[string]state
	// complete is false when the bound stopped the pass. An incomplete
	// listing is unmeasured: it is neither the whole directory nor an empty
	// one, and a caller says so rather than reporting what it managed to see
	// as all there is.
	complete bool
}

// scan lists the directory. A file this package did not write refuses the
// whole pass: the store owns its directory, and guessing what else is in it is
// how a forged name gets read as a record.
func (s *store) scan() (listing, error) {
	entries, err := s.readDir()
	if err != nil {
		return listing{}, err
	}
	l := listing{state: make(map[string]state), complete: true}
	for _, e := range entries {
		// What an entry is comes from the directory, not from its name. A
		// pipe, a device or a symbolic link named like a record is foreign
		// however well the name reads, and opening one would block this call
		// and every call behind it.
		if !e.Type().IsRegular() {
			return listing{}, fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, cause(e.Name()))
		}
		kind, id, st := classify(e.Name())
		switch kind {
		case kindRecord:
			if furthest, seen := l.state[id]; !seen || st > furthest {
				l.state[id] = st
			}
		case kindMarker, kindTemp, kindView:
		case kindForeign:
			return listing{}, fmt.Errorf("%w: %q", ErrForeignFile, cause(e.Name()))
		}
	}
	for id := range l.state {
		l.ids = append(l.ids, id)
	}
	slices.Sort(l.ids)
	if len(l.ids) > s.opts.maxRecords {
		l.ids = l.ids[:s.opts.maxRecords]
		l.complete = false
	}
	return l, nil
}

// readRecord reads the record of id, preferring the furthest-along name. hint
// is what a scan saw; a name linked since is found by the probe behind it, and
// a name unlinked since costs one open and falls through to the same probe. It
// reports fs.ErrNotExist when no name of id is there.
func (s *store) readRecord(id string, hint state) (Record, state, error) {
	if raw, err := s.readBounded(id+hint.suffix(), headerBytes+s.opts.maxRecordBytes); err == nil {
		rec, err := s.decodeAt(id, hint, raw)
		return rec, hint, err
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Record{}, hint, err
	}
	for _, st := range byRank {
		raw, err := s.readBounded(id+st.suffix(), headerBytes+s.opts.maxRecordBytes)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return Record{}, st, err
		}
		rec, err := s.decodeAt(id, st, raw)
		return rec, st, err
	}
	return Record{}, hint, fs.ErrNotExist
}

// readListed reads a record a scan listed, as readRecord does, except for a
// record whose approver id the claim rule refuses: that record comes back
// beside the refusal, which the caller answers with only for a lookup of the
// record's own approval. Every other error refuses the lookup.
func (s *store) readListed(id string, hint state) (rec Record, st state, refusal, err error) {
	rec, st, err = s.readRecord(id, hint)
	if own, refused := refusedOnlyItself(err); refused {
		return own, st, err, nil
	}
	return rec, st, nil, err
}

// decodeAt decodes raw and holds it to the name it was read under. A record
// whose inner identifier or resolution disagrees with its name is refused,
// never read as if the two agreed: the name is how the store finds it and the
// content is what it answers from.
func (s *store) decodeAt(id string, st state, raw []byte) (Record, error) {
	rec, err := decodeRecord(raw, s.opts.maxRecordBytes, s.opts.maxApprovalWindow)
	own, refused := refusedOnlyItself(err)
	if err != nil && !refused {
		return Record{}, fmt.Errorf("record %q: %w", cause(id+st.suffix()), err)
	}
	if refused {
		rec = own
	}
	if rec.ApprovalID != id {
		return Record{}, fmt.Errorf("%w: %q holds approval %q",
			ErrNameMismatch, cause(id+st.suffix()), cause(rec.ApprovalID))
	}
	if rec.Resolution != st.resolution() {
		return Record{}, fmt.Errorf("%w: %q holds resolution %s",
			ErrNameMismatch, cause(id+st.suffix()), rec.Resolution)
	}
	if refused {
		return Record{}, fmt.Errorf("record %q: %w", cause(id+st.suffix()), err)
	}
	return rec, nil
}

// drop forgets one record: every name it may take, and its projection. It is
// how an expired or rejected record leaves the directory.
func (s *store) drop(id string) error {
	var errs []error
	for _, st := range byRank {
		errs = append(errs, s.remove(id+st.suffix()))
	}
	errs = append(errs, s.remove(id+viewSuffix))
	return errors.Join(errs...)
}
