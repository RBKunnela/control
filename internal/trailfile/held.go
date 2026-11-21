package trailfile

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/guardana/control/internal/segmentlog"
)

// stillHeld reads back each line the index answers an append with, where the
// log wrote it, in the directory the log opened, reading no more than those
// lines. A line gone, cut or changed means the index no longer says what the
// log holds, so the log fails, refusing this append and every later call.
func (l *Log) stillHeld(held []place) error {
	if len(held) == 0 {
		return nil
	}
	if err := l.readBack(held); err != nil {
		l.failed = fmt.Errorf("%w: a line the log holds is no longer as it was written: %w", segmentlog.ErrFailed, err)
		return l.failed
	}
	return nil
}

func (l *Log) readBack(held []place) error {
	// The trailing "." fails on anything but a directory rather than wait on
	// a named pipe put at the log's path.
	root, err := os.OpenRoot(l.dir + string(os.PathSeparator) + ".")
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Stat(".")
	switch {
	case err != nil:
		return err
	case !os.SameFile(info, l.dirInfo):
		return fmt.Errorf("%s is another directory than the log opened", strconv.Quote(l.dir))
	}
	m := l.rl.Manifest()
	opened := map[string]*os.File{}
	defer func() {
		for _, f := range opened {
			_ = f.Close()
		}
	}()
	for _, p := range held {
		name, offset, err := segmentAt(m, p)
		if err != nil {
			return err
		}
		f, ok := opened[name]
		if !ok {
			if f, err = openHeld(root, name); err != nil {
				return err
			}
			opened[name] = f
		}
		line := make([]byte, p.size)
		if _, err := f.ReadAt(line, offset); err != nil {
			return fmt.Errorf("%s at offset %d: %w", name, offset, err)
		}
		if sha256.Sum256(line) != p.line {
			return fmt.Errorf("%s at offset %d holds another line", name, offset)
		}
	}
	return nil
}

// segmentAt is the file of the segment of m holding the line at p, and the
// line's offset in it.
func segmentAt(m segmentlog.Manifest, p place) (string, int64, error) {
	var start int64
	for _, s := range m.Segments {
		if s.State != segmentlog.StateSealed {
			continue
		}
		if p.at+p.size <= start+s.Bytes {
			return s.File, p.at - start, nil
		}
		start += s.Bytes
	}
	if p.at+p.size <= start+m.Live.Bytes {
		return segmentlog.LiveName, p.at - start, nil
	}
	return "", 0, fmt.Errorf("no segment holds the line at offset %d", p.at)
}

// openHeld opens the regular file at name in root to read it, refusing a
// link at the name, without waiting on a named pipe.
func openHeld(root *os.Root, name string) (*os.File, error) {
	before, err := root.Lstat(name)
	switch {
	case err != nil:
		return nil, err
	case !before.Mode().IsRegular():
		return nil, fmt.Errorf("%s: %w", name, ErrNotRegular)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|readFlags, 0)
	if err != nil {
		return nil, err
	}
	if after, err := f.Stat(); err != nil || !os.SameFile(before, after) {
		return nil, errors.Join(fmt.Errorf("another file stood at %s when it was opened", name), err, f.Close())
	}
	return f, nil
}
