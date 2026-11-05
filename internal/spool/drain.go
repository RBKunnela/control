package spool

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/guardana/control/internal/files"
)

// ErrDrainTarget is a drain whose file would land in the spool's own
// directory, where the next Open refuses it as a file that is not the
// spool's.
const ErrDrainTarget Error = "spool: a drain writes its file outside the spool's directory"

// Drained is what a drain moved out of the quarantine.
type Drained struct {
	// Records and Bytes are the whole records the quarantine held, now in the
	// drained file and released from the budget.
	Records int
	Bytes   int64
	// Torn is the bytes past the last whole record, which Open would have
	// cut and the drain cut with the rest.
	Torn int64
}

// Drain moves the quarantine of the spool in dir into out, a file it creates
// for its owner alone and never replaces, as one JSONL line per record. It
// takes the directory's lock, so it refuses with ErrLocked while a plane
// holds the spool, and reads the quarantine as Open does, refusing one Open
// would refuse. The file and its directory are forced to disk before the
// quarantine is truncated, so a drain stopped between the two leaves every
// record in both places, and a second drain into a new file then empties the
// quarantine: a record may be drained twice, and is never lost. The segments
// are listed and left as they are.
func Drain(dir, out string) (Drained, error) {
	return drain(dir, out, nil)
}

// drain is Drain with written called once out is on disk and before the
// quarantine is truncated: an error from it stops the drain there.
func drain(dir, out string, written func() error) (_ Drained, err error) {
	root, err := openSpoolDir(dir)
	if err != nil {
		return Drained{}, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	unlock, err := lockDir(root, dir)
	if err != nil {
		return Drained{}, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := outsideOf(root, out); err != nil {
		return Drained{}, err
	}
	s := &Spool{opts: Options{Dir: dir, openFile: openOSFile, openRead: openOSRead, syncDir: syncDir}, root: root}
	if err := s.listSegments(); err != nil {
		return Drained{}, err
	}
	size, err := s.loadQuarantine()
	if err != nil {
		return Drained{}, err
	}
	d := Drained{Records: s.quarantine.records, Bytes: s.quarantine.size, Torn: size - s.quarantine.size}
	if err := s.writeDrained(out); err != nil {
		return Drained{}, err
	}
	if written != nil {
		if err := written(); err != nil {
			return Drained{}, s.stillQuarantined(out, err)
		}
	}
	if size == 0 {
		return d, nil
	}
	if err := s.emptyQuarantine(); err != nil {
		return Drained{}, s.stillQuarantined(out, err)
	}
	return d, nil
}

// stillQuarantined is a refusal after out was written whole.
func (s *Spool) stillQuarantined(out string, err error) error {
	return fmt.Errorf("spool: the quarantine's %d records are in %q and still in the quarantine, so drain again into a new file: %w",
		s.quarantine.records, out, err)
}

// outsideOf refuses an out whose directory is the spool's.
func outsideOf(root *os.Root, out string) error {
	parent, err := os.Stat(filepath.Dir(out))
	if err != nil {
		return fmt.Errorf("spool: the drained file's directory: %w", err)
	}
	spoolDir, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	if os.SameFile(parent, spoolDir) {
		return fmt.Errorf("%w: %q", ErrDrainTarget, out)
	}
	return nil
}

// writeDrained creates out and writes the quarantine's whole records to it,
// forcing the file and its directory to disk. A file it could not finish is
// removed.
func (s *Spool) writeDrained(out string) (err error) {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator names the file to create
	if err != nil {
		return fmt.Errorf("spool: the drained file: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(out))
		}
	}()
	err = f.Chmod(0o600)
	if err == nil {
		err = s.copyQuarantine(f)
	}
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("spool: the drained file: %w", err)
	}
	return files.SyncDir(filepath.Dir(out))
}

// copyQuarantine writes the line of every whole record the quarantine holds.
func (s *Spool) copyQuarantine(w io.Writer) error {
	if s.quarantine.info == nil {
		return nil
	}
	src, _, err := s.openForRead(quarantineName, quarantineWhat, s.quarantine.info)
	if err != nil {
		return err
	}
	defer src.Close() //nolint:errcheck // read only; nothing to lose on close
	buf := bufio.NewWriter(w)
	for at := int64(0); at < s.quarantine.size; {
		line, next, err := readRecord(src, at, s.quarantine.size)
		if err != nil {
			return fmt.Errorf("%w: the quarantine at %d: %w", ErrCorrupt, at, err)
		}
		if _, err := buf.Write(line); err != nil {
			return err
		}
		at = next
	}
	return buf.Flush()
}

// emptyQuarantine truncates the quarantine to nothing through a descriptor
// judged to be the file the drain read, and forces the cut to disk. The file
// stays, as Open leaves it.
func (s *Spool) emptyQuarantine() error {
	f, _, err := s.openForAppend(quarantineName, quarantineWhat, s.quarantine.info)
	if err != nil {
		return err
	}
	if err := errors.Join(f.Truncate(0), f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("spool: emptying the quarantine: %w", err)
	}
	return nil
}
