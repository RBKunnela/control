package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"time"

	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policystate"
)

// Kind is how a plane reaches its roster. It is a closed set.
type Kind string

// KindFile reads one signed roster file and keeps its serial on an authority
// floor. It is the default.
const KindFile Kind = "file"

// ParseKind reads a configured kind. The empty kind is the default, KindFile;
// every other spelling this build lacks is ErrUnknownKind.
func ParseKind(s string) (Kind, error) {
	switch Kind(s) {
	case "", KindFile:
		return KindFile, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknownKind, s)
}

// Config is what a roster port starts from.
type Config struct {
	Kind Kind
	// Root is the pinned root key every roster is signed under.
	Root ed25519.PublicKey
	// RosterID is the one roster id the port takes. A roster of any other id
	// is refused, at start as while running, whatever floors the floor
	// directory lists.
	RosterID string
	// Path is the roster file the file kind reads.
	Path string
	// FloorDir is the authority floor directory that lists the roster's id.
	FloorDir string
	// Others are the keys the plane pins for other authorities: policy,
	// freshness, routes and lifts. Neither the root nor a roster key may be
	// one of them.
	Others []ed25519.PublicKey
	// Clock reads the time every expiry is judged at.
	Clock func() time.Time
}

// Open checks c once and starts the roster port of its kind. It refuses an
// unknown kind with ErrUnknownKind, a root CheckRoot refuses, and a
// configuration missing a roster id a roster may carry, a path, a floor
// directory or a clock with ErrConfig.
// A roster that cannot be taken yet does not refuse the start: every lookup
// answers unavailable until one is, and Status says why.
func Open(ctx context.Context, c Config) (Roster, error) {
	kind, err := ParseKind(string(c.Kind))
	if err != nil {
		return nil, err
	}
	if err := CheckRoot(c.Root, c.Others...); err != nil {
		return nil, err
	}
	switch {
	case !ValidRosterID(c.RosterID):
		return nil, fmt.Errorf("%w: no roster id a roster may carry", ErrConfig)
	case c.Path == "":
		return nil, fmt.Errorf("%w: no roster file", ErrConfig)
	case c.FloorDir == "":
		return nil, fmt.Errorf("%w: no authority floor directory", ErrConfig)
	case c.Clock == nil:
		return nil, fmt.Errorf("%w: no clock", ErrConfig)
	}
	f := &fileRoster{
		kind:     kind,
		rosterID: c.RosterID,
		root:     slices.Clone(c.Root),
		path:     filepath.Clean(c.Path),
		floorDir: c.FloorDir,
		others:   cloneKeys(c.Others),
		clock:    c.Clock,
		turn:     make(chan struct{}, 1),
		last:     CauseNoRoster,
		counts:   map[Cause]uint64{},
	}
	f.turn <- struct{}{}
	_ = f.Lookup(ctx, "")
	return f, nil
}

func cloneKeys(keys []ed25519.PublicKey) []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, len(keys))
	for i, k := range keys {
		out[i] = slices.Clone(k)
	}
	return out
}

// fileRoster is the file kind. One lookup runs at a time; each reads the
// file again and takes a roster only when it verifies, is usable at the
// clock, names the configured roster id, and its serial is at least the
// held one's and the floor's. A roster it cannot take leaves the one held,
// which answers until its own expiry.
type fileRoster struct {
	kind     Kind
	rosterID string
	root     ed25519.PublicKey
	path     string
	floorDir string
	others   []ed25519.PublicKey
	clock    func() time.Time

	turn    chan struct{}
	held    *Document
	heldRaw []byte
	last    Cause
	counts  map[Cause]uint64
}

func (f *fileRoster) Lookup(ctx context.Context, keyID string) Answer {
	if ctx.Err() != nil {
		return Unavailable(CauseCanceled)
	}
	select {
	case <-f.turn:
	case <-ctx.Done():
		return Unavailable(CauseCanceled)
	}
	defer func() { f.turn <- struct{}{} }()
	now := f.clock()
	f.note(f.refresh(ctx, now))
	if f.held == nil {
		return Unavailable(f.last)
	}
	if err := f.held.UsableAt(now); err != nil {
		cause := CauseExpired
		if errors.Is(err, ErrFuture) {
			cause = CauseFuture
		}
		f.note(cause)
		return Unavailable(cause)
	}
	k, ok := f.held.key(keyID)
	if !ok {
		return unknownKey()
	}
	return keyAnswer(k)
}

func (f *fileRoster) note(c Cause) {
	f.last = c
	if c != CauseNone {
		f.counts[c]++
	}
}

// refresh reads the file and takes the roster it holds when it may, and
// returns what it met.
func (f *fileRoster) refresh(ctx context.Context, now time.Time) Cause {
	raw, err := files.ReadRegular(f.path, MaxFileBytes, 0)
	if err != nil {
		return CauseUnreadable
	}
	if f.held != nil && bytes.Equal(raw, f.heldRaw) {
		return CauseNone
	}
	d, cause := f.candidate(raw, now)
	if cause != CauseNone {
		return cause
	}
	if cause := f.againstHeld(d); cause != CauseNone || f.held != nil && d.digest == f.held.digest {
		return cause
	}
	_, err = policystate.RaiseAuthority(ctx, f.floorDir, d.id, d.serial, d.digest)
	switch {
	case errors.Is(err, policystate.ErrAuthorityBelowFloor):
		return CauseBelowFloor
	case errors.Is(err, policystate.ErrAuthorityForked):
		return CauseForked
	case err != nil:
		return CauseFloor
	}
	f.held, f.heldRaw = &d, raw
	return CauseNone
}

// candidate verifies raw as a roster of the configured id, usable at now,
// that names none of the keys the plane pins for another authority. The id
// is judged before the floor, so a floor directory listing several ids never
// lets a restart take another one.
func (f *fileRoster) candidate(raw []byte, now time.Time) (Document, Cause) {
	env, err := ParseFile(raw)
	if err != nil {
		return Document{}, CauseRefused
	}
	d, err := VerifyDocument(env, f.root)
	if err == nil {
		err = distinct(d, f.root, f.others)
	}
	if err != nil {
		return Document{}, CauseRefused
	}
	if d.id != f.rosterID {
		return Document{}, CauseOtherRoster
	}
	if err := d.UsableAt(now); err != nil {
		if errors.Is(err, ErrFuture) {
			return Document{}, CauseFuture
		}
		return Document{}, CauseExpired
	}
	return d, CauseNone
}

// againstHeld refuses a roster that would replace the one held with a lower
// serial, or the same serial and another digest. The floor refuses the same,
// but a floor lowered behind the plane's back does not lower what the plane
// holds.
func (f *fileRoster) againstHeld(d Document) Cause {
	switch {
	case f.held == nil:
		return CauseNone
	case d.serial < f.held.serial:
		return CauseBelowFloor
	case d.serial == f.held.serial && d.digest != f.held.digest:
		return CauseForked
	}
	return CauseNone
}

func (f *fileRoster) Status(ctx context.Context) Status {
	select {
	case <-f.turn:
	case <-ctx.Done():
		return Status{Kind: f.kind, Last: CauseCanceled}
	}
	defer func() { f.turn <- struct{}{} }()
	s := Status{Kind: f.kind, Last: f.last, Counts: maps.Clone(f.counts)}
	if f.held != nil {
		s.RosterID, s.Serial, s.Digest, s.ExpiresAt = f.held.id, f.held.serial, f.held.digest, f.held.expiresAt
		if f.held.UsableAt(f.clock()) == nil {
			s.Health = HealthUsable
		}
	}
	return s
}
