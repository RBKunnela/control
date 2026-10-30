package spool

import (
	"errors"
	"fmt"
	"io/fs"
)

// Inspection is what Inspect read of a spool's directory: the log as Open
// would leave it, and what Open would cut to get there.
type Inspection struct {
	// Held is a directory a spool holds. Its holder cut the torn tails when
	// it opened and appends past its last record, so nothing else is read and
	// every count below is zero; the holder's own Stats are the ones to ask.
	Held bool
	// Segments and Unacknowledged are the segments Open would keep and the
	// bytes of whole records in them, none of which a start knows to be
	// acknowledged.
	Segments       int
	Unacknowledged int64
	// QuarantinedRecords and QuarantinedBytes are the quarantine's whole
	// records.
	QuarantinedRecords int
	QuarantinedBytes   int64
	// Torn is the bytes Open would cut: past the last record that checks in
	// the last segment and in the quarantine, and the whole of a last segment
	// that holds no record.
	Torn int64
}

// Inspect reads the spool's directory as Open does and refuses what Open
// refuses, and changes nothing there: it takes no lock that outlives it,
// cuts no tail and creates no file. Where the directory is locked with flock,
// a shared lock keeps a spool from opening it while the read lasts, so the
// read is of one log.
func Inspect(opts Options) (_ Inspection, err error) {
	if err := opts.check(); err != nil {
		return Inspection{}, err
	}
	if opts.openRead == nil {
		opts.openRead = openOSRead
	}
	root, err := openSpoolDir(opts.Dir)
	if err != nil {
		return Inspection{}, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	release, held, err := shareDir(root, opts.Dir)
	if err != nil || held {
		return Inspection{Held: held}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	s := &Spool{opts: opts, root: root}
	sizes, err := s.read()
	if err != nil {
		return Inspection{}, err
	}
	return s.inspection(sizes)
}

// inspection is what read found, as Open would leave it, refusing a torn tail
// Open could not cut.
func (s *Spool) inspection(sizes fileSizes) (Inspection, error) {
	found := Inspection{
		QuarantinedRecords: s.quarantine.records,
		QuarantinedBytes:   s.quarantine.size,
		Torn:               sizes.quarantine - s.quarantine.size,
	}
	if found.Torn > 0 {
		if err := mayCut(s.quarantine.info, quarantineWhat); err != nil {
			return Inspection{}, err
		}
	}
	segments := s.segments
	if n := len(segments); n > 0 {
		last := segments[n-1]
		found.Torn += sizes.last - last.size
		switch {
		case last.records == 0:
			segments = segments[:n-1]
		case sizes.last > last.size:
			if err := mayCut(last.info, last.what()); err != nil {
				return Inspection{}, err
			}
		}
	}
	for _, seg := range segments {
		found.Segments++
		found.Unacknowledged += seg.size
	}
	return found, nil
}

// mayCut refuses a file, called what, whose torn tail Open would cut when its
// owner, which checkOpened holds to be this account, may not write it: Open
// cuts through a descriptor opened to write, which the kernel then refuses.
// Root writes whatever the mode says.
func mayCut(info fs.FileInfo, what string) error {
	if info.Mode().Perm()&0o200 == 0 && effectiveUID() != 0 {
		return fmt.Errorf("spool: %s: %w: a start would cut its torn tail, and its mode %04o keeps its owner from writing it",
			what, fs.ErrPermission, info.Mode().Perm())
	}
	return nil
}
