package runs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/guardana/control/internal/files"
)

// Admin is the operator's handle on a runs directory. It opens, closes and
// lists runs, each under the directory's exclusive lock, so two operator
// commands never interleave. A plane never takes that lock.
//
// The zero value is not a directory. Every method on it answers ErrClosed.
type Admin struct {
	d *dir
	// records is the absolute path of a signed layout's records/, which
	// every record it signs names, and empty for an unsigned directory.
	records string
	// judge is what Lookup, Tree and Children take a signed layout's records
	// through.
	judge Judge
}

// OpenAdmin opens dir for the operator and writes nothing to it: an unsigned
// directory, or a signed layout's records/. It refuses a
// group- or world-writable directory with ErrPermissions, a directory that is
// not a runs directory, an empty one among them, with ErrNotRunsDir, and one
// holding a file this package does not write with ErrForeignFile. It waits
// for the directory's lock, which another operator command may hold, until
// ctx ends.
func OpenAdmin(ctx context.Context, dir string) (*Admin, error) {
	return openAdmin(ctx, dir, false)
}

// InitAdmin is OpenAdmin, except that an empty directory becomes a runs
// directory first; so does one holding only what a crash left while its
// marker was being created.
func InitAdmin(ctx context.Context, dir string) (*Admin, error) {
	return openAdmin(ctx, dir, true)
}

func openAdmin(ctx context.Context, dir string, initialise bool) (*Admin, error) {
	signed, err := signedLayout(dir)
	if err != nil {
		return nil, err
	}
	if signed {
		return openSignedAdmin(ctx, dir, false)
	}
	d, err := openDir(dir, roleFlat, ownedByThisUser)
	if err != nil {
		return nil, err
	}
	a := &Admin{d: d}
	if err := a.init(ctx, initialise); err != nil {
		return nil, errors.Join(err, d.close())
	}
	return a, nil
}

// init judges what the directory holds as a plane does, under the
// directory's lock; asked to, it first makes an empty directory a runs
// directory.
func (a *Admin) init(ctx context.Context, initialise bool) error {
	unlock, err := a.d.lockDir(ctx)
	if err != nil {
		return err
	}
	entries, err := a.d.readDir()
	if err != nil {
		return errors.Join(fmt.Errorf("%w: %w", ErrNotRunsDir, err), unlock())
	}
	if initialise && onlyLeftovers(entries) {
		return errors.Join(a.d.writeMarker(), unlock())
	}
	return errors.Join(a.d.judgeContents(entries), unlock())
}

// onlyLeftovers reports whether entries hold nothing but regular files under
// a temporary name of internal/files, none at all included.
func onlyLeftovers(entries []os.DirEntry) bool {
	for _, e := range entries {
		if !e.Type().IsRegular() || !files.IsTemp(e.Name()) {
			return false
		}
	}
	return true
}

// Signed reports whether the directory is a signed layout, whose records
// only OpenSigned and CloseSigned write.
func (a *Admin) Signed() bool { return a != nil && a.records != "" }

// JudgeWith makes j what Lookup, Tree and Children take every record of a
// signed layout through before it counts; with none they refuse it with
// ErrUnjudged. An unsigned directory reads as it did.
func (a *Admin) JudgeWith(j Judge) {
	if a != nil {
		a.judge = j
	}
}

// Binding is the records/ path every record a signed layout's handle signs
// names, and empty for an unsigned directory.
func (a *Admin) Binding() string {
	if a == nil {
		return ""
	}
	return a.records
}

// Close releases the handle. A later call answers ErrClosed.
func (a *Admin) Close() error {
	if a == nil {
		return ErrClosed
	}
	return a.d.close()
}

// OpenRequest is a run the operator asks for.
type OpenRequest struct {
	Who Identity
	// Parent is the open run of the same project and tenant this run is
	// spawned under, or empty for a root run.
	Parent string
	// TTL is how long the run lives, between MinTTL and MaxTTL.
	TTL time.Duration
	// Now is when the run opens. A zero reading is refused.
	Now time.Time
}

// Open opens a run and returns its record and its token. The token is the only
// copy of the secret: the record keeps its hash, so a token lost is a run
// that nobody can present.
//
// A root run gets its state file, then its lock file, then its record; a
// child gets only its record and shares its root's state. Open refuses a zero
// Now with ErrZeroTime, a lifetime out of bounds with ErrTTL, an identity
// with ErrIdentity, a parent that does not exist, is closed, is expired at Now
// or is another tenant's or project's with the ErrParent sentinel saying
// which, and a run that would expire after its parent with an
// *OutlivesParentError. A signed layout refuses it with ErrSigned.
func (a *Admin) Open(ctx context.Context, req OpenRequest) (Record, string, error) {
	return a.open(ctx, req, nil, nil)
}

// OpenSigned is Open for a signed layout: the record is signed with s and
// names the layout's records/, and a root gets no state, which its plane
// makes. A parent counts only once its record names this records/ and j
// takes it, so no record anybody else wrote is carried into a signature: one
// that does not is refused with ErrNotVouched. The record signed is written
// only once j takes it too. An unsigned directory refuses it with ErrLayout.
func (a *Admin) OpenSigned(ctx context.Context, req OpenRequest, s Signer, j Judge) (Record, string, error) {
	return a.open(ctx, req, &s, j)
}

func (a *Admin) open(ctx context.Context, req OpenRequest, s *Signer, j Judge) (_ Record, _ string, err error) {
	if err := a.signedWrite(s); err != nil {
		return Record{}, "", err
	}
	if err := req.check(); err != nil {
		return Record{}, "", err
	}
	end, err := a.begin(ctx)
	if err != nil {
		return Record{}, "", err
	}
	defer func() { err = errors.Join(err, end()) }()
	rec, secret, err := a.newRecord(ctx, req, j)
	if err != nil {
		return Record{}, "", err
	}
	id := rec.ID
	body, err := a.encode(ctx, rec, s, j)
	if err != nil {
		return Record{}, "", err
	}
	if err := a.fresh(id, req.Parent == "" && !a.Signed()); err != nil {
		return Record{}, "", err
	}
	if req.Parent == "" && !a.Signed() {
		if err := a.startRoot(id); err != nil {
			return Record{}, "", err
		}
	}
	if err := a.d.replace(id+recordTemp, id+recordSuffix, body); err != nil {
		return Record{}, "", err
	}
	return rec, id + "." + secret, nil
}

// newRecord is the record of a fresh run for req and the secret its hash is
// of.
func (a *Admin) newRecord(ctx context.Context, req OpenRequest, j Judge) (Record, string, error) {
	id, err := newRunID()
	if err != nil {
		return Record{}, "", err
	}
	root, err := a.rootFor(ctx, id, req, j)
	if err != nil {
		return Record{}, "", err
	}
	secret, hash, err := newSecret()
	if err != nil {
		return Record{}, "", err
	}
	now := canonTime(req.Now)
	return Record{
		ID: id, Who: req.Who, Root: root, Parent: req.Parent,
		OpenedAt: now, ExpiresAt: now.Add(req.TTL), SecretSHA256: hash,
	}, secret, nil
}

func (req OpenRequest) check() error {
	if req.Now.IsZero() {
		return ErrZeroTime
	}
	if err := checkTTL(req.TTL); err != nil {
		return err
	}
	return req.Who.check()
}

// rootFor is the root a new run shares: its own id with no parent, else its
// parent's root once the parent is shown open, unexpired, the tenant's and
// the project's, and expiring no earlier than the new run would; in a signed
// layout, also signed for it and taken by j.
func (a *Admin) rootFor(ctx context.Context, id string, req OpenRequest, j Judge) (string, error) {
	if req.Parent == "" {
		return id, nil
	}
	if err := checkRunID(req.Parent); err != nil {
		return "", fmt.Errorf("parent: %w", err)
	}
	parent, _, err := a.readOver(ctx, req.Parent, j)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("%w: %s", ErrParentUnknown, req.Parent)
	case err != nil:
		return "", fmt.Errorf("parent: %w", err)
	case parent.Closed():
		return "", fmt.Errorf("%w: %s", ErrParentClosed, req.Parent)
	case !req.Now.Before(parent.ExpiresAt):
		return "", fmt.Errorf("%w: %s", ErrParentExpired, req.Parent)
	case parent.Who.TenantID != req.Who.TenantID:
		return "", fmt.Errorf("%w: %s", ErrParentTenant, req.Parent)
	case parent.Who.ProjectID != req.Who.ProjectID:
		return "", fmt.Errorf("%w: %s", ErrParentProject, req.Parent)
	}
	if expires := canonTime(req.Now).Add(req.TTL); expires.After(parent.ExpiresAt) {
		return "", &OutlivesParentError{Parent: req.Parent, ExpiresAt: expires, ParentExpiresAt: parent.ExpiresAt}
	}
	return parent.Root, nil
}

// fresh refuses an id whose files are there already rather than write over
// another run's.
func (a *Admin) fresh(id string, root bool) error {
	names := []string{id + recordSuffix}
	if root {
		names = append(names, id+stateSuffix, id+lockSuffix)
	}
	for _, name := range names {
		if _, err := a.d.root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrExists, name)
		}
	}
	return nil
}

// startRoot writes a root's initial state and then creates its lock file. The
// plane opens the lock file without creating it, so a missing one is a file
// somebody removed, and the plane refuses rather than starts the root clean.
func (a *Admin) startRoot(id string) error {
	body, err := encodeState(id, initialState)
	if err != nil {
		return err
	}
	if err := a.d.replace(id+stateTemp, id+stateSuffix, body); err != nil {
		return err
	}
	f, err := a.d.createNew(id + lockSuffix)
	if err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	return a.d.syncDir()
}

// CloseRun closes the run id at now by replacing its record. It closes none of
// the runs opened under it. It refuses a zero now with ErrZeroTime, a run no
// record names with ErrNoRun and a run closed already with ErrAlreadyClosed.
// A signed layout refuses it with ErrSigned.
func (a *Admin) CloseRun(ctx context.Context, id string, now time.Time) error {
	_, _, err := a.closeRun(ctx, id, now, nil, nil)
	return err
}

// CloseSigned is CloseRun for a signed layout: the closed record is signed
// with s. The open record it replaces counts only once it names this
// records/ and j takes it, so a record nobody may sign is never signed over:
// one that does not is refused with ErrNotVouched and left as it is.
// CloseSigned returns the record it signed closed and who signed the open
// one. An unsigned directory refuses it with ErrLayout.
func (a *Admin) CloseSigned(ctx context.Context, id string, now time.Time, s Signer, j Judge) (Record, SignedBy, error) {
	return a.closeRun(ctx, id, now, &s, j)
}

func (a *Admin) closeRun(ctx context.Context, id string, now time.Time, s *Signer, j Judge) (_ Record, by SignedBy, err error) {
	if err := a.signedWrite(s); err != nil {
		return Record{}, SignedBy{}, err
	}
	if now.IsZero() {
		return Record{}, SignedBy{}, ErrZeroTime
	}
	if err := checkRunID(id); err != nil {
		return Record{}, SignedBy{}, err
	}
	end, err := a.begin(ctx)
	if err != nil {
		return Record{}, SignedBy{}, err
	}
	defer func() { err = errors.Join(err, end()) }()
	rec, by, err := a.readOver(ctx, id, j)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Record{}, SignedBy{}, fmt.Errorf("%w: %s", ErrNoRun, id)
	case err != nil:
		return Record{}, SignedBy{}, err
	case rec.Closed():
		return Record{}, SignedBy{}, fmt.Errorf("%w: %s", ErrAlreadyClosed, id)
	}
	rec.ClosedAt = canonTime(now)
	body, err := a.encode(ctx, rec, s, j)
	if err != nil {
		return Record{}, SignedBy{}, err
	}
	if err := a.d.replace(id+recordTemp, id+recordSuffix, body); err != nil {
		return Record{}, SignedBy{}, err
	}
	return rec, by, nil
}

// signedWrite refuses an unsigned write to a signed layout with ErrSigned,
// and a signed one to an unsigned directory with ErrLayout.
func (a *Admin) signedWrite(s *Signer) error {
	switch {
	case a.Signed() && s == nil:
		return ErrSigned
	case !a.Signed() && s != nil:
		return fmt.Errorf("%w: the directory holds unsigned runs; a signed layout starts in an empty directory", ErrLayout)
	}
	return nil
}

// encode is rec as the directory holds it: in a signed layout signed with s
// and refused unless j takes it, so no command writes a record a plane would
// refuse.
func (a *Admin) encode(ctx context.Context, rec Record, s *Signer, j Judge) ([]byte, error) {
	if s == nil {
		return a.encodeRecord(rec)
	}
	raw, err := a.signRecord(rec, *s, a.records)
	if err != nil {
		return nil, err
	}
	sr, err := decodeSignedFile(raw)
	if err == nil {
		_, err = a.verify(ctx, sr, j)
	}
	if err != nil {
		return nil, fmt.Errorf("the record signed: %w", err)
	}
	return raw, nil
}

// readOver reads the record of id that a write signs over and, in a signed
// layout, who signed it. There it counts only once verify takes it, and any
// record that cannot be read or taken, short of a missing one, is refused
// with ErrNotVouched.
func (a *Admin) readOver(ctx context.Context, id string, j Judge) (Record, SignedBy, error) {
	stored, err := a.d.readStored(id)
	switch {
	case errors.Is(err, fs.ErrNotExist) || !a.Signed():
		return stored.Record, SignedBy{}, err
	case err == nil:
		var by SignedBy
		if by, err = a.verify(ctx, stored, j); err == nil {
			return stored.Record, by, nil
		}
	}
	return Record{}, SignedBy{}, fmt.Errorf("%w: %s: %w", ErrNotVouched, id, err)
}

// verify takes a record read from a signed layout through the check every
// reader makes: signed for this records/, then taken by j.
func (a *Admin) verify(ctx context.Context, sr SignedRecord, j Judge) (SignedBy, error) {
	return judgeRecord(ctx, sr, a.records, j)
}

// Listing is a bounded listing of the directory's records.
type Listing struct {
	// Records are sorted by run id.
	Records []Record
	// Complete is false when the bound stopped the listing. Such a listing
	// is neither the whole directory nor an empty one.
	Complete bool
}

// List reads at most bound records, by run id. A file this package does not
// write, or a record that does not decode, refuses the listing.
func (a *Admin) List(ctx context.Context, bound int) (_ Listing, err error) {
	if bound <= 0 {
		return Listing{}, fmt.Errorf("%w: %d", ErrBound, bound)
	}
	end, err := a.begin(ctx)
	if err != nil {
		return Listing{}, err
	}
	defer func() { err = errors.Join(err, end()) }()
	entries, err := a.d.readDir()
	if err != nil {
		return Listing{}, err
	}
	ids, err := a.d.scan(entries)
	if err != nil {
		return Listing{}, err
	}
	out := Listing{Complete: len(ids) <= bound}
	if !out.Complete {
		ids = ids[:bound]
	}
	for _, id := range ids {
		rec, err := a.d.readRecord(id)
		if err != nil {
			return Listing{}, err
		}
		out.Records = append(out.Records, rec)
	}
	return out, nil
}

// begin holds the handle open and the directory's lock for one operation, and
// judges the directory again once the lock is held, since waiting for it can
// take as long as the context allows.
func (a *Admin) begin(ctx context.Context) (func() error, error) {
	if a == nil {
		return nil, ErrClosed
	}
	end, err := a.d.begin(ctx)
	if err != nil {
		return nil, err
	}
	unlock, err := a.d.lockDir(ctx)
	if err != nil {
		end()
		return nil, err
	}
	release := func() error { defer end(); return unlock() }
	if err := a.d.judge(); err != nil {
		return nil, errors.Join(err, release())
	}
	return release, nil
}
