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
}

// OpenAdmin opens dir for the operator and writes nothing to it. It refuses a
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
	d, err := openDir(dir)
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
// *OutlivesParentError.
func (a *Admin) Open(ctx context.Context, req OpenRequest) (_ Record, _ string, err error) {
	if err := req.check(); err != nil {
		return Record{}, "", err
	}
	end, err := a.begin(ctx)
	if err != nil {
		return Record{}, "", err
	}
	defer func() { err = errors.Join(err, end()) }()
	id, err := newRunID()
	if err != nil {
		return Record{}, "", err
	}
	root, err := a.rootFor(id, req)
	if err != nil {
		return Record{}, "", err
	}
	secret, hash, err := newSecret()
	if err != nil {
		return Record{}, "", err
	}
	now := canonTime(req.Now)
	rec := Record{
		ID: id, Who: req.Who, Root: root, Parent: req.Parent,
		OpenedAt: now, ExpiresAt: now.Add(req.TTL), SecretSHA256: hash,
	}
	body, err := a.encodeRecord(rec)
	if err != nil {
		return Record{}, "", err
	}
	if err := a.fresh(id, req.Parent == ""); err != nil {
		return Record{}, "", err
	}
	if req.Parent == "" {
		if err := a.startRoot(id); err != nil {
			return Record{}, "", err
		}
	}
	if err := a.d.replace(id+recordTemp, id+recordSuffix, body); err != nil {
		return Record{}, "", err
	}
	return rec, id + "." + secret, nil
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
// the project's, and expiring no earlier than the new run would.
func (a *Admin) rootFor(id string, req OpenRequest) (string, error) {
	if req.Parent == "" {
		return id, nil
	}
	if err := checkRunID(req.Parent); err != nil {
		return "", fmt.Errorf("parent: %w", err)
	}
	parent, err := a.d.readRecord(req.Parent)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("%w: %s", ErrParentUnknown, req.Parent)
	case err != nil:
		return "", err
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
func (a *Admin) CloseRun(ctx context.Context, id string, now time.Time) (err error) {
	if now.IsZero() {
		return ErrZeroTime
	}
	if err := checkRunID(id); err != nil {
		return err
	}
	end, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, end()) }()
	rec, err := a.d.readRecord(id)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: %s", ErrNoRun, id)
	case err != nil:
		return err
	case rec.Closed():
		return fmt.Errorf("%w: %s", ErrAlreadyClosed, id)
	}
	rec.ClosedAt = canonTime(now)
	body, err := a.encodeRecord(rec)
	if err != nil {
		return err
	}
	return a.d.replace(id+recordTemp, id+recordSuffix, body)
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
	ids, err := scan(entries)
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
