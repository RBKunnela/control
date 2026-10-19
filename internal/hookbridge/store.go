package hookbridge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy/strictjson"
)

// Domain tags keep a hash this package makes for one purpose from ever
// equalling one it makes for another.
const (
	entryDomain      = "hookbridge/entry/v1"
	requestKeyDomain = "hookbridge/request-key/v1"
)

const (
	entryMode     = 0o600
	ownerOnly     = 0o077
	maxEntryBytes = 4 << 10
	entryVersion  = "1.0"
	claimedMark   = ".claimed-"
	// SweepLimit bounds the entries one Sweep removes, and sweepExamine the
	// names it looks at, so a hook never stalls on a full directory.
	SweepLimit   = 16
	sweepExamine = 256
)

// Entry is what the store keeps of one admitted call between its admit and
// its completion: the handle and when it expires, and nothing of the call.
type Entry struct {
	Handle    string
	ExpiresAt time.Time
}

// Claimed is an entry one claimer took; no other claimer can take it.
type Claimed struct {
	Entry
	name string
}

// Store keeps entries as files in one directory that only this account may
// enter. It is safe for use by many processes at once.
type Store struct {
	root *os.Root
}

// OpenStore opens the store in dir, refusing a directory another account
// owns or one whose mode gives any access to group or others.
func OpenStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, ErrNoStoreDir
	}
	if !files.PermissionBits {
		return nil, files.ErrNoPermissionBits
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{root: root}
	if err := s.check(); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return s, nil
}

// check refuses the store's directory unless this account owns it and its
// mode gives no access to group or others.
func (s *Store) check() error {
	info, err := s.root.Stat(".")
	if err == nil {
		err = files.CheckOwnedBy(info, os.Geteuid())
	}
	if err == nil && info.Mode().Perm()&ownerOnly != 0 {
		err = fmt.Errorf("%w: mode %04o", files.ErrMode, info.Mode().Perm())
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStoreNotOwnerOnly, err)
	}
	return nil
}

// Close releases the store's directory.
func (s *Store) Close() error { return s.root.Close() }

// Publish writes e under the name of (token, session, call), durably, and
// refuses a name that is taken. It checks the directory again first, since
// the handle it writes lets whoever reads it complete the call.
func (s *Store) Publish(token, session, call string, e Entry) error {
	if token == "" || session == "" || call == "" || e.Handle == "" || e.ExpiresAt.IsZero() {
		return ErrEntry
	}
	if err := s.check(); err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Version   string `json:"version"`
		Handle    string `json:"handle"`
		ExpiresAt string `json:"expires_at"`
	}{entryVersion, e.Handle, e.ExpiresAt.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	if len(body) > maxEntryBytes {
		return fmt.Errorf("%w: over %d bytes", ErrEntry, maxEntryBytes)
	}
	return files.CreateNoReplaceIn(s.root, entryName(token, session, call), body, entryMode)
}

// Claim takes the entry of (token, session, call) by renaming it to a name
// of the claimer's own, so of two claimers exactly one gets it; the other
// gets ErrNoEntry. A claimed entry stays on disk until Remove.
func (s *Store) Claim(token, session, call string) (Claimed, error) {
	if token == "" || session == "" || call == "" {
		return Claimed{}, ErrEntry
	}
	name := entryName(token, session, call)
	claimed := name + claimedMark + rand.Text()
	if err := s.root.Rename(name, claimed); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Claimed{}, ErrNoEntry
		}
		return Claimed{}, err
	}
	e, err := s.read(claimed)
	if err != nil {
		return Claimed{}, errors.Join(err, s.root.Remove(claimed))
	}
	return Claimed{Entry: e, name: claimed}, nil
}

// Remove deletes a claimed entry.
func (s *Store) Remove(c Claimed) error {
	if c.name == "" {
		return ErrEntry
	}
	return s.root.Remove(c.name)
}

// Sweep removes entries, claimed or not, that expired at now: at most
// SweepLimit of them among the first names it reads. It returns how many it
// removed. An entry it cannot read is left alone. A temporary file a publish
// that crashed left behind is swept as an entry when it reads as one, since
// it then holds a whole handle; a torn one holds none and is left, because
// only a file time, which the account can set, could say how old it is.
func (s *Store) Sweep(now time.Time) (int, error) {
	d, err := s.root.Open(".")
	if err != nil {
		return 0, err
	}
	defer func() { _ = d.Close() }()
	removed := 0
	err = examine(d, func(name string) (bool, error) {
		if removed == SweepLimit {
			return true, nil
		}
		swept, err := s.sweepOne(name, now)
		if swept {
			removed++
		}
		return false, err
	})
	return removed, err
}

// examine calls visit with each name d lists, at most sweepExamine of them,
// until visit stops or fails.
func examine(d interface{ Readdirnames(n int) ([]string, error) }, visit func(name string) (stop bool, err error)) error {
	for examined := 0; examined < sweepExamine; {
		names, err := d.Readdirnames(sweepExamine - examined)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, name := range names {
			examined++
			if stop, err := visit(name); stop || err != nil {
				return err
			}
		}
	}
	return nil
}

// sweepOne removes name when it is an entry, or a temporary file that reads
// as one, that expired at now.
func (s *Store) sweepOne(name string, now time.Time) (bool, error) {
	if !isEntryName(name) && !files.IsTemp(name) || !s.expired(name, now) {
		return false, nil
	}
	if err := s.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, nil
}

// expired reports whether name reads as an entry that expired at now; one
// it cannot read is not.
func (s *Store) expired(name string, now time.Time) bool {
	e, err := s.read(name)
	return err == nil && !now.Before(e.ExpiresAt)
}

// read reads one entry, which must be a regular file this account owns with
// no access for anyone else, holding exactly a body this store writes.
func (s *Store) read(name string) (Entry, error) {
	f, err := s.root.OpenFile(name, os.O_RDONLY|nonBlocking, 0)
	if err != nil {
		return Entry{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	switch {
	case err != nil:
		return Entry{}, err
	case !info.Mode().IsRegular():
		return Entry{}, fmt.Errorf("%w: %w", ErrEntry, files.ErrNotRegular)
	case info.Mode().Perm()&ownerOnly != 0:
		return Entry{}, fmt.Errorf("%w: %w", ErrEntry, files.ErrMode)
	}
	if err := files.CheckOwnedBy(info, os.Geteuid()); err != nil {
		return Entry{}, fmt.Errorf("%w: %w", ErrEntry, err)
	}
	raw, err := readBounded(f, maxEntryBytes, ErrEntry)
	if err != nil {
		return Entry{}, err
	}
	return parseEntry(raw)
}

func parseEntry(raw []byte) (Entry, error) {
	o, err := strictObject(raw, "version", "handle", "expires_at")
	if err != nil {
		return Entry{}, fmt.Errorf("%w: %w", ErrEntry, err)
	}
	version, ok1 := strictjson.String(o["version"])
	handle, ok2 := strictjson.String(o["handle"])
	at, ok3 := strictjson.String(o["expires_at"])
	if !ok1 || !ok2 || !ok3 || !strictjson.IsVersion(version, "1") || handle == "" {
		return Entry{}, ErrEntry
	}
	expires, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return Entry{}, ErrEntry
	}
	return Entry{Handle: handle, ExpiresAt: expires}, nil
}

// entryName is the hex SHA-256 of the entry domain and each of token,
// session and call after its length, so no two triples share a name and the
// token cannot be read back from it.
func entryName(token, session, call string) string {
	return hashParts(entryDomain, token, session, call)
}

// RequestKey is the request key an admit of call in session carries: 64
// hex characters, within the receiver's 64 of [A-Za-z0-9._-].
func RequestKey(session, call string) string {
	return hashParts(requestKeyDomain, session, call)
}

func hashParts(domain string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(domain))
	var n [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// isEntryName reports whether name is an entry's name or a claimed entry's.
func isEntryName(name string) bool {
	base, claim, claimed := strings.Cut(name, claimedMark)
	if len(base) != sha256.Size*2 || strings.Trim(base, "0123456789abcdef") != "" {
		return false
	}
	return !claimed || len(claim) == 26
}
