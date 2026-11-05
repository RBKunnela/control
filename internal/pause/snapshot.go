package pause

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/guardana/control/internal/files"
)

// State is one of the four states a plane can be in about pauses. The zero
// value is Unknown: a state nobody read is not a clear one.
type State uint8

const (
	// Unknown is a pause state the plane cannot read; it blocks every call.
	Unknown State = iota
	// Disabled is a plane configured with no pause file.
	Disabled
	// Clear is a pause file read whole that pauses nothing.
	Clear
	// Paused is a pause file read whole that holds at least one entry.
	Paused
)

// String names the state as a report prints it.
func (s State) String() string {
	switch s {
	case Disabled:
		return "disabled"
	case Clear:
		return "clear"
	case Paused:
		return "paused"
	}
	return "unknown"
}

// Cause is why a state is Unknown, as a report prints it.
type Cause string

// The causes of an unknown state.
const (
	CauseNeverRead  Cause = "never read"
	CauseMissing    Cause = "missing"
	CauseUnreadable Cause = "unreadable"
	CauseLink       Cause = "a link"
	CauseFileMode   Cause = "file writable by others"
	CauseDirMode    Cause = "directory writable by others"
	CauseFileOwner  Cause = "file owned by another account"
	CauseDirOwner   Cause = "directory owned by another account"
	CauseTooLarge   Cause = "too large"
	CauseMalformed  Cause = "malformed"
	CauseVersion    Cause = "unknown version"
	CauseStale      Cause = "stale"
	CauseAhead      Cause = "dated ahead"
)

// Causes is every cause a snapshot can report, in the order declared. The
// slice is a copy.
func Causes() []Cause {
	return []Cause{
		CauseNeverRead, CauseMissing, CauseUnreadable, CauseLink, CauseFileMode, CauseDirMode,
		CauseFileOwner, CauseDirOwner, CauseTooLarge, CauseMalformed, CauseVersion, CauseStale, CauseAhead,
	}
}

// staleAfter is how many poll intervals a snapshot answers for. A reader that
// stopped cannot leave an old answer standing past it.
const staleAfter = 3

// forbidden is the permission bits no pause file or its directory may carry:
// whoever may write either may lift every pause.
const forbidden fs.FileMode = 0o022

// maxDetailBytes bounds what a snapshot's detail quotes of a refusal, which
// can carry a value read from the file, before it reaches a log line or an
// answer.
const maxDetailBytes = 256

// effectiveUID is the account the pause file and its directory have to be
// owned by: another owner may rewrite either whatever its mode says, and so
// lift every pause.
var effectiveUID = os.Geteuid

// Snapshot is the pause state as one read found it. It is immutable: nothing
// holds a reference into it, and Entries returns a copy.
type Snapshot struct {
	state   State
	cause   Cause
	detail  string
	entries []Entry
	readAt  time.Time
	maxAge  time.Duration
}

// DisabledSnapshot is the state of a plane with no pause file.
func DisabledSnapshot() Snapshot { return Snapshot{state: Disabled} }

// State is the snapshot's state.
func (s Snapshot) State() State { return s.state }

// Cause is why the state is Unknown, and empty for any other state.
func (s Snapshot) Cause() Cause {
	if s.state == Unknown && s.cause == "" {
		return CauseNeverRead
	}
	return s.cause
}

// Detail is what the read refused, for a log line; empty unless Unknown. It
// never holds a reason, and it is cut to maxDetailBytes.
func (s Snapshot) Detail() string { return s.detail }

// Entries is a copy of the entries in force.
func (s Snapshot) Entries() []Entry { return slices.Clone(s.entries) }

// ReadAt is the plane's clock when the file was read.
func (s Snapshot) ReadAt() time.Time { return s.readAt }

// At is s as it stands at now: a read snapshot older than three poll
// intervals, or read after now, is Unknown with that cause.
func (s Snapshot) At(now time.Time) Snapshot {
	if s.state != Clear && s.state != Paused {
		return s
	}
	switch age := now.Sub(s.readAt); {
	case age < 0:
		return unknown(CauseAhead, fmt.Sprintf("read %v after the plane's clock", -age), s.readAt, s.maxAge)
	case age > staleAfter*s.maxAge:
		return unknown(CauseStale, fmt.Sprintf("read %v ago, past %d poll intervals", age, staleAfter), s.readAt, s.maxAge)
	}
	return s
}

// Covers reports whether an entry in force covers a call of the action kind,
// provider and name the envelope carries, made under the identity who the
// plane vouches for. Only a Paused snapshot covers anything; whether an
// Unknown one blocks is the caller's rule, not a match.
func (s Snapshot) Covers(kind, provider, name string, who Vouched) bool {
	if s.state != Paused {
		return false
	}
	for _, e := range s.entries {
		if e.Scope.Matches(kind, provider, name, who) {
			return true
		}
	}
	return false
}

func unknown(cause Cause, detail string, at time.Time, interval time.Duration) Snapshot {
	return Snapshot{state: Unknown, cause: cause, detail: detail, readAt: at, maxAge: interval}
}

// Read reads the pause file at path once, at the plane's clock reading now,
// into a snapshot that answers for staleAfter intervals of interval. A file
// that is missing, a link, not a regular file, writable by the group or
// others, in a directory writable by them, owned or in a directory owned by
// another account than this process's effective user, unreadable, too large,
// malformed or of an unknown version reads as Unknown with that cause. Nothing is
// locked: the writer replaces the file whole, so a read sees one document.
func Read(path string, now time.Time, interval time.Duration) Snapshot {
	doc, err := load(path)
	if err != nil {
		return unknown(causeOf(err), bounded(err.Error()), now, interval)
	}
	state := Clear
	if len(doc.Entries) > 0 {
		state = Paused
	}
	return Snapshot{state: state, entries: doc.Entries, readAt: now, maxAge: interval}
}

// readAttempts is how many times a read starts again on a pause file replaced
// between judging its name and opening it. A writer replaces the file whole,
// and one replace racing a poll is no reason to block every call.
const readAttempts = 3

// load reads and parses the file at path with every check Read names.
func load(path string) (Document, error) {
	if !permissionBits {
		return Document{}, ErrNoPermissionBits
	}
	root, err := openDir(filepath.Dir(path))
	if err != nil {
		return Document{}, err
	}
	defer func() { _ = root.Close() }()
	for attempt := 1; ; attempt++ {
		doc, err := loadIn(root, path)
		if !errors.Is(err, ErrFileChanged) || attempt == readAttempts {
			return doc, err
		}
	}
}

// loadIn reads and parses the pause file at path through root, the directory
// openDir judged, with every check Read names of the file itself. The root
// follows a link at the file's own name whatever the flags say, so the file
// opened has to be the one judged no link.
func loadIn(root *os.Root, path string) (Document, error) {
	name := filepath.Base(path)
	named, err := root.Lstat(name)
	if err != nil {
		return Document{}, missing(err)
	}
	if named.Mode()&fs.ModeSymlink != 0 {
		return Document{}, fmt.Errorf("%w: %s", ErrLink, path)
	}
	step(stepFileNamed)
	f, err := root.OpenFile(name, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return Document{}, missing(err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return Document{}, err
	}
	switch {
	case !os.SameFile(named, info):
		return Document{}, fmt.Errorf("%w: %s", ErrFileChanged, path)
	case !info.Mode().IsRegular():
		return Document{}, fmt.Errorf("%w: %s", ErrNotRegular, info.Mode().Type())
	case info.Mode().Perm()&forbidden != 0:
		return Document{}, fmt.Errorf("%w: mode %04o", ErrFileMode, info.Mode().Perm())
	}
	if err := files.CheckOwnedBy(info, effectiveUID()); err != nil {
		return Document{}, fmt.Errorf("%w: %w", ErrFileOwner, err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return Document{}, err
	}
	return Parse(raw)
}

func missing(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrMissing, err)
	}
	return err
}

// causeOf names the cause of a read that failed with err.
func causeOf(err error) Cause {
	for _, c := range []struct {
		err   Error
		cause Cause
	}{
		{ErrMissing, CauseMissing},
		{ErrLink, CauseLink},
		{ErrDirLink, CauseLink},
		{ErrFileMode, CauseFileMode},
		{ErrDirMode, CauseDirMode},
		{ErrFileOwner, CauseFileOwner},
		{ErrDirOwner, CauseDirOwner},
		{ErrTooLarge, CauseTooLarge},
		{ErrMalformed, CauseMalformed},
		{ErrVersion, CauseVersion},
	} {
		if errors.Is(err, c.err) {
			return c.cause
		}
	}
	return CauseUnreadable
}

// bounded cuts detail to maxDetailBytes, at a character boundary.
func bounded(detail string) string {
	if len(detail) <= maxDetailBytes {
		return detail
	}
	cut := maxDetailBytes
	for cut > 0 && !utf8.RuneStart(detail[cut]) {
		cut--
	}
	return detail[:cut] + "..."
}
