package spool

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
)

// load reads the directory in two passes. The first only reads: it scans every
// segment and the quarantine and refuses what is corrupt. The second cuts the
// torn tail of the last segment and of the quarantine, the only changes Open
// makes on disk.
func (s *Spool) load() error {
	sizes, err := s.read()
	if err != nil {
		return err
	}
	if n := len(s.segments); n > 0 {
		if err := s.cutTail(s.segments[n-1], sizes.last); err != nil {
			return err
		}
	}
	if err := s.cutQuarantineTail(sizes.quarantine); err != nil {
		return err
	}
	// Nothing on disk is acknowledged: a segment acknowledged whole is deleted.
	s.ack = s.end()
	if len(s.segments) > 0 {
		s.ack = Cursor{Segment: s.segments[0].seq}
	}
	return nil
}

// fileSizes are the sizes on disk of the last segment and of the quarantine,
// whose bytes past the records that check are their torn tails.
type fileSizes struct{ last, quarantine int64 }

// read is load's first pass, the one Inspect makes too: it lists and scans
// every segment and the quarantine and changes nothing on disk.
func (s *Spool) read() (fileSizes, error) {
	var sizes fileSizes
	if err := s.listSegments(); err != nil {
		return sizes, err
	}
	for i, seg := range s.segments {
		size, err := s.scanSegment(seg, i == len(s.segments)-1)
		if err != nil {
			return sizes, err
		}
		sizes.last = size
	}
	if err := s.checkSequence(); err != nil {
		return sizes, err
	}
	quarantined, err := s.loadQuarantine()
	if err != nil {
		return sizes, err
	}
	sizes.quarantine = quarantined
	return sizes, nil
}

// listSegments names every segment in the spool's directory in log order: the
// entries are sorted by name and the names are zero-padded. The quarantine and the lock file are
// the spool's too; anything else there is refused. Each segment and the
// quarantine keep the file their entry names, which every later open has to
// find again.
func (s *Spool) listSegments() error {
	entries, err := s.readDir()
	if err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		m := segmentName.FindStringSubmatch(name)
		switch {
		case !entry.Type().IsRegular():
			return fmt.Errorf("%w: %q", ErrForeignFile, name)
		case name == quarantineName:
			info, err := s.root.Lstat(name)
			if err != nil {
				return fmt.Errorf("spool: %w", err)
			}
			s.quarantine.info, s.quarantine.synced = info, true
			continue
		case lockFile != "" && name == lockFile:
			continue
		case m == nil:
			return fmt.Errorf("%w: %q", ErrForeignFile, name)
		}
		seq, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			return fmt.Errorf("%w: %q", ErrForeignFile, name)
		}
		info, err := s.root.Lstat(name)
		if err != nil {
			return fmt.Errorf("spool: %w", err)
		}
		s.segments = append(s.segments, &segment{seq: seq, name: name, info: info})
	}
	return nil
}

// readDir lists the spool's directory through its root, sorted by name.
func (s *Spool) readDir() ([]os.DirEntry, error) {
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

// scanSegment counts seg's records that check and returns the file's size.
// A segment before the last was synced whole before the next one existed, so
// a byte in it that does not check is corruption; one with no record at all
// leaves the next segment's name out of sequence, which checkSequence
// refuses. In the last segment a record that does not check ends the log,
// and under FsyncEveryRecord, where every record before it was forced to
// disk, a record that checks after it is corruption instead.
func (s *Spool) scanSegment(seg *segment, last bool) (int64, error) {
	f, info, err := s.openForRead(seg.name, seg.what(), seg.info)
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck // read only; nothing to lose on close
	found, err := scan(bufio.NewReaderSize(f, 1<<16))
	if err != nil {
		return 0, fmt.Errorf("spool: %w", err)
	}
	seg.records, seg.size = found.records, found.good
	torn := found.good < info.Size()
	switch {
	case !last && torn:
		return 0, fmt.Errorf("%w: segment %d does not check at byte %d of %d", ErrCorrupt, seg.seq, found.good, info.Size())
	case torn && s.opts.Fsync == FsyncEveryRecord:
		if err := s.checkNothingFollows(f, found.good, info.Size()); err != nil {
			return 0, fmt.Errorf("%w: segment %d: %w", ErrCorrupt, seg.seq, err)
		}
	}
	return info.Size(), nil
}

// checkNothingFollows refuses a tail that holds a record which checks, and one
// that costs more to read than a tail may: under FsyncEveryRecord every record
// the log reported durable was forced to disk before the next one, so bytes
// behind one that does not check are damage, not an interrupted append.
func (s *Spool) checkNothingFollows(ra io.ReaderAt, from, size int64) error {
	after, err := recordAfter(ra, from, size)
	switch {
	case errors.Is(err, errTailCost):
		return err
	case err != nil:
		return fmt.Errorf("reading the tail past %d: %w", from, err)
	case after:
		return fmt.Errorf("a record follows byte %d, which does not check", from)
	}
	return nil
}

// checkSequence refuses a segment numbered 0, one that does not follow the one
// before it, and one whose records would carry the sequence past its range.
func (s *Spool) checkSequence() error {
	s.nextSeq = 1
	for i, seg := range s.segments {
		records := uint64(seg.records) //nolint:gosec // G115: a count of records is never negative
		switch {
		case seg.seq == 0:
			return fmt.Errorf("%w: segment 0 names no record", ErrCorrupt)
		case i > 0 && seg.seq != s.nextSeq:
			return fmt.Errorf("%w: segment %d does not follow segment %d", ErrCorrupt, seg.seq, s.segments[i-1].seq)
		case seg.seq > math.MaxUint64-records:
			return fmt.Errorf("%w: segment %d holds %d records, past the sequence's range", ErrCorrupt, seg.seq, records)
		}
		s.nextSeq = seg.seq + records
	}
	return nil
}

// cutTail truncates the last segment to its records that check, counting what
// it discards, and removes it when none does: the next append would otherwise
// name a new segment after the same sequence number.
func (s *Spool) cutTail(last *segment, size int64) error {
	switch {
	case last.records == 0:
		if err := s.root.Remove(last.name); err != nil {
			return fmt.Errorf("spool: %w", err)
		}
		s.segments = s.segments[:len(s.segments)-1]
	case last.size < size:
		if err := s.cutBack(last.name, last.what(), last.info, last.size); err != nil {
			return err
		}
	default:
		return nil
	}
	s.truncated += size - last.size
	return nil
}
