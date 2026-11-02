package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

const (
	stateName  = "state.json"
	stateTemp  = "state.json.tmp"
	alertsName = "alerts.jsonl"

	lockName = "lock"
	// openToOthers are the mode bits that would let another user read or
	// change the state or the alerts, and writableByOthers those of them
	// that would let one change them.
	openToOthers     fs.FileMode = 0o077
	writableByOthers fs.FileMode = 0o022
)

// maxStateBytes bounds state.json. The bounds on open requests, the window
// and each value they keep hold a state under it; TestTheBoundsFitTheState
// computes the largest. Tests lower it.
var maxStateBytes = 64 << 20

// maxPendingBytes bounds the alert log past its checkpoint, which only a run
// that stopped before saving its state leaves there. Tests lower it.
var maxPendingBytes int64 = 64 << 20

// syncFile forces a file of the state directory to disk. Tests record the
// order it is called in.
var syncFile = (*os.File).Sync

// crashAt, nil but in tests, is called where a crash would leave the state
// directory between two writes: "alerts", once the new alerts are synced to
// the log, and "state", once the new state is synced under its temporary
// name and before it replaces the old. An error stops the run there.
var crashAt func(point string) error

func crash(point string) error {
	if crashAt == nil {
		return nil
	}
	return crashAt(point)
}

// judge refuses a state directory or a file in it that another user owns or
// may read or write, a file that is not a regular one, or a directory that
// is not one.
func judge(name string, info fs.FileInfo, dir bool, uid int) error {
	return judgeMode(name, info, dir, uid, openToOthers)
}

func judgeMode(name string, info fs.FileInfo, dir bool, uid int, refused fs.FileMode) error {
	switch {
	case dir && !info.IsDir():
		return fmt.Errorf("%s is not a directory", name)
	case !dir && !info.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", name)
	case info.Mode().Perm()&refused != 0:
		return fmt.Errorf("%s is readable or writable by its group or by everyone, mode %04o", name, info.Mode().Perm())
	}
	owner, ok := ownerOf(info)
	switch {
	case !ok:
		return fmt.Errorf("the owner of %s cannot be read on this platform", name)
	case owner != uid:
		return fmt.Errorf("%s is owned by uid %d, not by uid %d, who runs this", name, owner, uid)
	}
	return nil
}

// stateDir is an open state directory, every file reached through its root.
type stateDir struct{ root *os.Root }

func openStateDir(path string) (*stateDir, error) { return openDir(path, openToOthers) }

func openDir(path string, refused fs.FileMode) (*stateDir, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w; make the directory with -init", err)
	}
	if err := judgeMode(path, info, true, os.Getuid(), refused); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	now, err := root.Stat(".")
	if err == nil && !os.SameFile(info, now) {
		err = fmt.Errorf("%s changed while it was opened", path)
	}
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return &stateDir{root: root}, nil
}

func (d *stateDir) close() { _ = d.root.Close() }

// open opens a file of the directory that judge accepts, and refuses it if
// another file took its name between the look and the open.
func (d *stateDir) open(name string, flag int) (*os.File, error) {
	info, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := judge(name, info, false, os.Getuid()); err != nil {
		return nil, err
	}
	f, err := d.root.OpenFile(name, flag, 0)
	if err != nil {
		return nil, err
	}
	now, err := f.Stat()
	if err == nil && !os.SameFile(info, now) {
		err = fmt.Errorf("%s changed while it was opened", name)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// checkpoint is the state as saved, and what the alert log holds past it.
type checkpoint struct {
	state *followState
	// pending maps the key of each alert a run logged and then stopped
	// before saving, and each the state carries, to where it was raised:
	// they were raised, and are not raised again.
	pending map[string]raisedAt
	// saved is the log's length the state records, logBytes its length to
	// its last whole line, and cut is bytes after it, which the next append
	// drops.
	saved, logBytes int64
	cut             bool
}

func (d *stateDir) load() (*checkpoint, error) {
	f, err := d.open(stateName, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(maxStateBytes)+1))
	if err = errors.Join(err, f.Close()); err != nil {
		return nil, err
	}
	if len(b) > maxStateBytes {
		return nil, fmt.Errorf("%s is over %d bytes", stateName, maxStateBytes)
	}
	file, err := decodeState(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", stateName, err)
	}
	s, err := file.load()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", stateName, err)
	}
	c := &checkpoint{state: s, pending: map[string]raisedAt{}}
	for k, offset := range s.carried {
		c.pending[k] = raisedAt{offset: offset, source: s.source}
	}
	return c, d.readPending(c, file.AlertsBytes)
}

// readPending reads the alert log past the length the state recorded.
func (d *stateDir) readPending(c *checkpoint, saved int64) error {
	f, err := d.open(alertsName, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	switch {
	case err != nil:
		return err
	case info.Size() < saved:
		return fmt.Errorf("%s holds %d bytes, shorter than the %d the state records: the log was cut", alertsName, info.Size(), saved)
	case info.Size()-saved > maxPendingBytes:
		return fmt.Errorf("%s holds %d bytes past the state's checkpoint, over %d", alertsName, info.Size()-saved, maxPendingBytes)
	}
	past := make([]byte, info.Size()-saved)
	if _, err := f.ReadAt(past, saved); err != nil {
		return err
	}
	whole := bytes.LastIndexByte(past, '\n') + 1
	c.saved, c.logBytes, c.cut = saved, saved+int64(whole), whole < len(past)
	for line := range bytes.Lines(past[:whole]) {
		a, err := readAlert(bytes.TrimSuffix(line, []byte("\n")))
		if err != nil {
			return fmt.Errorf("%s past the state's checkpoint: %w", alertsName, err)
		}
		c.pending[a.key()] = raisedAt{offset: *a.Offset, source: cursorSource(a.Cursor)}
	}
	return nil
}

// appendAlerts appends the lines to the log, after the last whole line, and
// syncs it, and returns the log's length.
func (d *stateDir) appendAlerts(c *checkpoint, lines []byte) (int64, error) {
	if len(lines) == 0 && !c.cut {
		return c.logBytes, nil
	}
	f, err := d.open(alertsName, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return 0, err
	}
	if c.cut {
		err = f.Truncate(c.logBytes)
	}
	if err == nil {
		_, err = f.Write(lines)
	}
	if err = errors.Join(err, syncFile(f), f.Close()); err != nil {
		return 0, err
	}
	return c.logBytes + int64(len(lines)), nil
}

// encodeState is state.json's bytes, refused over maxStateBytes.
func encodeState(f stateFile) ([]byte, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	if len(b) > maxStateBytes {
		return nil, fmt.Errorf("the new state would be %d bytes, over the bound of %d", len(b), maxStateBytes)
	}
	return b, nil
}

// writeState replaces state.json whole with b: a fresh file at the
// temporary name, synced, renamed over it, and the directory synced.
// Whatever stood at the temporary name is removed first, so the exclusive
// create never writes through a link left there.
func (d *stateDir) writeState(b []byte) error {
	if err := d.root.Remove(stateTemp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	t, err := d.root.OpenFile(stateTemp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = t.Write(b)
	if err = errors.Join(err, syncFile(t), t.Close()); err != nil {
		return errors.Join(err, d.root.Remove(stateTemp))
	}
	if err := crash("state"); err != nil {
		return err
	}
	if err := d.root.Rename(stateTemp, stateName); err != nil {
		return err
	}
	return d.syncDir()
}

func (d *stateDir) syncDir() error {
	f, err := d.root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(syncFile(f), f.Close())
}

// makeStateDir makes the directory at path, or takes an empty one, mode
// 0700, with a state that has read nothing and an empty alert log.
func makeStateDir(path string) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		if err := judgeMode(path, info, true, os.Getuid(), writableByOthers); err != nil {
			return err
		}
	}
	d, err := openDir(path, writableByOthers)
	if err != nil {
		return err
	}
	defer d.close()
	if err := d.empty(path); err != nil {
		return err
	}
	if err := d.root.Chmod(".", 0o700); err != nil {
		return err
	}
	for _, name := range []string{lockName, alertsName} {
		f, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if err := errors.Join(syncFile(f), f.Close()); err != nil {
			return err
		}
	}
	b, err := encodeState(emptyState().file(0))
	if err != nil {
		return err
	}
	return d.writeState(b)
}

// lock holds the directory's lock until the file it returns is closed, so
// one run at a time reads and replaces the state. A lock another run holds
// is refused, not waited for.
func (d *stateDir) lock() (*os.File, error) {
	f, err := d.open(lockName, os.O_RDWR)
	if err != nil {
		return nil, fmt.Errorf("%w; make the directory with -init", err)
	}
	if err := lockExclusive(f); err != nil {
		return nil, errors.Join(fmt.Errorf("another run holds the state directory: %w", err), f.Close())
	}
	return f, nil
}

func (d *stateDir) empty(path string) error {
	f, err := d.root.Open(".")
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(1)
	err = errors.Join(err, f.Close())
	switch {
	case len(names) > 0:
		return fmt.Errorf("%s is not empty", path)
	case errors.Is(err, io.EOF):
		return nil
	}
	return err
}
