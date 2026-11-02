package spool

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
)

// quarantineName is the file that keeps the records an exporter could not
// deliver for good. It is framed as a segment is, and the plane appends to it
// and never deletes or rewrites it.
const quarantineName = "quarantine.log"

// quarantine is what the quarantine file holds: the records that check, the
// offset just past the last of them, and the digest of every one's line, which
// carries its event identifier, so a record the quarantine holds is never
// written twice and one with another line always is. What the digests take
// grows with the file, which the budget bounds. info is the file the
// listing or the create found, nil while there is none, and synced whether its
// directory entry is known to be on disk.
type quarantine struct {
	records int
	size    int64
	held    map[[sha256.Size]byte]struct{}
	info    fs.FileInfo
	synced  bool
}

// quarantineWhat names the quarantine in a refusal.
const quarantineWhat = "the quarantine"

func (q *quarantine) remember(sum [sha256.Size]byte) {
	if q.held == nil {
		q.held = map[[sha256.Size]byte]struct{}{}
	}
	q.held[sum] = struct{}{}
}

func (q *quarantine) holds(sum [sha256.Size]byte) bool {
	_, ok := q.held[sum]
	return ok
}

// loadQuarantine scans the quarantine when there is one and returns the
// file's size. The file is appended to as a segment is, so a record that does
// not check at its end is the torn tail of an append that never returned, and
// the caller cuts it; a record that does not check with one that checks after
// it is corruption of records the spool reported durable.
func (s *Spool) loadQuarantine() (int64, error) {
	known := s.quarantine.info
	if known == nil {
		return 0, nil
	}
	f, info, err := s.openForRead(quarantineName, quarantineWhat, known)
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck // read only; nothing to lose on close
	found, err := scan(bufio.NewReaderSize(f, 1<<16))
	if err != nil {
		return 0, fmt.Errorf("spool: %w", err)
	}
	if found.good < info.Size() {
		// Every quarantine append is synced, whatever the fsync policy, so a
		// record behind one that does not check is damage.
		if err := s.checkNothingFollows(f, found.good, info.Size()); err != nil {
			return 0, fmt.Errorf("%w: the quarantine: %w", ErrCorrupt, err)
		}
	}
	s.quarantine = quarantine{records: found.records, size: found.good, info: known, synced: s.quarantine.synced}
	if err := s.loadQuarantineIDs(f, found); err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// loadQuarantineIDs reads the line of every record the quarantine holds,
// refusing one that is not an event, and remembers its digest.
func (s *Spool) loadQuarantineIDs(ra io.ReaderAt, found scanned) error {
	for at := int64(0); at < found.good; {
		line, next, err := readRecord(ra, at, found.good)
		if err != nil {
			return fmt.Errorf("%w: the quarantine at %d: %w", ErrCorrupt, at, err)
		}
		events, err := evidence.DecodeJSONL(bytes.NewReader(line), 1)
		if err != nil || len(events) != 1 {
			return fmt.Errorf("%w: the quarantine at %d holds no event: %w", ErrCorrupt, at, err)
		}
		s.quarantine.remember(sha256.Sum256(line))
		at = next
	}
	return nil
}

// cutQuarantineTail truncates the quarantine to the records that check,
// counting what it discards. The file itself stays: the plane never removes
// it.
func (s *Spool) cutQuarantineTail(size int64) error {
	if size == s.quarantine.size {
		return nil
	}
	if err := s.cutBack(quarantineName, quarantineWhat, s.quarantine.info, s.quarantine.size); err != nil {
		return err
	}
	s.truncated += size - s.quarantine.size
	return nil
}

// Quarantine appends to the spool's quarantine the events whose lines it does
// not already hold, and returns how many it wrote once they are durable.
// It is how a record a collector refuses for good leaves the export without
// leaving the evidence: a caller acknowledges past the records only after it
// returns.
//
// The bytes count against the budget from then on and nothing releases them,
// so the append is refused with ErrFull unless the records the caller may
// acknowledge next cover it: what the quarantine takes between two
// acknowledgements is at most what the acknowledgement then releases. A record
// the quarantine already holds is not written twice, so a caller stopped
// between quarantining and acknowledging may repeat both.
func (r *Reader) Quarantine(events []*controlv1.Event) (int, error) {
	if r.s == nil {
		return 0, ErrClosed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return 0, err
	}
	var records bytes.Buffer
	var line bytes.Buffer
	var write [][sha256.Size]byte
	for i, event := range events {
		line.Reset()
		if err := evidence.EncodeJSONL(&line, []*controlv1.Event{event}); err != nil {
			return 0, fmt.Errorf("spool: quarantining event %d: %w", i, err)
		}
		sum := sha256.Sum256(line.Bytes())
		if s.quarantine.holds(sum) || slices.Contains(write, sum) {
			continue
		}
		records.Write(frame(line.Bytes()))
		write = append(write, sum)
	}
	if len(write) == 0 {
		return 0, nil
	}
	r.mark = s.settle(r.mark)
	covered := s.bytesBetween(s.ack, r.mark)
	if taken := s.quarantinedSinceAck + int64(records.Len()); taken > covered {
		return 0, fmt.Errorf("%w: quarantining %d bytes with %d bytes to release", ErrFull, taken, covered)
	}
	if err := s.appendQuarantine(records.Bytes(), write); err != nil {
		return 0, err
	}
	return len(write), nil
}

// appendQuarantine writes framed records at the quarantine's end and syncs
// them, and the directory until its entry for the file is known to be on
// disk. On a failure the file is cut back to what it held through the same
// descriptor and the cut is synced, and when either fails the spool is
// broken: a later append could land behind a record nobody can vouch for. A close that fails after the sync breaks it too, since the
// records are then on disk and no longer counted.
func (s *Spool) appendQuarantine(records []byte, written [][sha256.Size]byte) error {
	f, info, err := s.openForAppend(quarantineName, quarantineWhat, s.quarantine.info)
	if err != nil {
		return err
	}
	s.quarantine.info = info
	_, err = f.Write(records)
	if err == nil {
		err = f.Sync()
	}
	if err == nil && !s.quarantine.synced {
		err = s.opts.syncDir(s.root)
		s.quarantine.synced = err == nil
	}
	if err != nil {
		if cut := errors.Join(cutSynced(f, s.quarantine.size), f.Close()); cut != nil {
			s.breakWith(fmt.Errorf("spool: quarantine: repair after %w: %w", err, cut))
			return s.broken
		}
		return fmt.Errorf("spool: quarantine: %w", err)
	}
	if err := f.Close(); err != nil {
		s.breakWith(fmt.Errorf("spool: quarantine: closing: %w", err))
		return s.broken
	}
	for _, sum := range written {
		s.quarantine.records++
		s.quarantine.remember(sum)
	}
	s.quarantine.size += int64(len(records))
	s.quarantinedSinceAck += int64(len(records))
	return nil
}
