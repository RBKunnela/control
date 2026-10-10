package trailfile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/files"
)

// forbidden is the permission bits neither the file nor its directory may
// have: whoever may write either can write evidence into the trail.
const forbidden fs.FileMode = 0o022

// fileOps are the open of the file and the two calls an append makes on it,
// so a test can change what stands at the name as it is opened, or make either
// call fail.
type fileOps struct {
	open  func(root *os.Root, name string, flag int, perm fs.FileMode) (*os.File, error)
	write func(*os.File, []byte) (int, error)
	sync  func(*os.File) error
}

var osOps = fileOps{open: (*os.Root).OpenFile, write: (*os.File).Write, sync: (*os.File).Sync}

// Writer appends evidence lines to one file it holds under an exclusive lock.
// Its zero value holds no file, and every append to it is refused.
type Writer struct {
	mu   sync.Mutex
	path string
	f    *os.File
	// size is the length of the file up to the end of the last append that
	// was synced.
	size int64
	// ids holds the event id of every line in the file, each with its line.
	ids    index
	failed error
	closed bool
	ops    fileOps
}

// Open opens the file at path for appending, creating it mode 0600, and holds
// it until Close. It refuses a directory or an existing file the group or
// others may write or another account owns, a path that names no file in a
// directory, a link, anything that is not a regular file, and a file another
// writer holds. A last line with no newline is what a crash in the middle of
// an append leaves, and nothing of that append was reported written, so Open
// cuts it, but only when it can be the start of a line the codec writes. A file that is not one this package leaves behind is refused
// as ErrDamaged and left as it is: a whole line that is not one event, a tail
// that is neither a cut through the opening every line has nor a whole object
// that decodes as one event, a tail longer than any line a writer writes, and
// one event id carrying two different lines. A file of one line with no
// newline has no whole line to judge it by, so its tail is all there is. The
// directory is synced, so a file created here is still there after a power
// loss.
func Open(path string) (*Writer, error) { return open(path, osOps) }

func open(path string, ops fileOps) (*Writer, error) {
	name, err := fileName(path)
	if err != nil {
		return nil, err
	}
	if !files.PermissionBits {
		return nil, ErrNoPermissionBits
	}
	root, err := openDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	f, err := openFile(root, name, ops.open)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	w := &Writer{path: path, f: f, ops: ops}
	err = w.claim()
	if err == nil {
		err = syncRoot(root)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close(), root.Close())
	}
	if err := root.Close(); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return w, nil
}

// claim judges the open file, locks it, judges it again, reads the ids of its
// lines and cuts a torn last line, and leaves the writer at the length the
// file is left with. Nothing is cut before every whole line was read.
func (w *Writer) claim() error {
	if _, err := judgedSize(w.f); err != nil {
		return err
	}
	if err := lock(w.f); err != nil {
		return err
	}
	// Another writer may have cut the file or appended between the first
	// judgement and the lock; only a length read under it is the writer's.
	size, err := judgedSize(w.f)
	if err != nil {
		return err
	}
	end, err := lastLineEnd(w.f, size)
	if err != nil {
		return err
	}
	if w.ids, err = readIndex(io.NewSectionReader(w.f, 0, end)); err != nil {
		return err
	}
	if end != size {
		if err := errors.Join(w.f.Truncate(end), w.f.Sync()); err != nil {
			return fmt.Errorf("cutting a torn last line: %w", err)
		}
	}
	w.size = end
	return nil
}

// judgedSize judges the open file as it is now and returns its length.
func judgedSize(f *os.File) (int64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if err := judgeFile(info); err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// lastLineEnd returns the length of the file up to and including its last
// newline. Only the last evidence.MaxLineBytes+1 bytes are read: a writer
// leaves at most evidence.MaxLineBytes after the last newline, so a newline
// that is not among them is ErrDamaged. So is a tail that cannot be the start
// of a line the codec writes, which is no append a crash cut.
func lastLineEnd(f *os.File, size int64) (int64, error) {
	if size == 0 {
		return 0, nil
	}
	window := min(size, int64(evidence.MaxLineBytes)+1)
	tail := make([]byte, window)
	if _, err := f.ReadAt(tail, size-window); err != nil {
		return 0, err
	}
	start := bytes.LastIndexByte(tail, '\n') + 1
	switch {
	case start == 0 && size > evidence.MaxLineBytes:
		return 0, fmt.Errorf("%w: more than %d bytes follow the last newline", ErrDamaged, evidence.MaxLineBytes)
	case start < len(tail) && !torn(tail[start:]):
		return 0, fmt.Errorf("%w: the bytes after the last newline are not the start of an evidence line", ErrDamaged)
	}
	return size - window + int64(start), nil
}

// Append writes events as evidence lines at the end of the file, and syncs it
// before it returns nil.
//
// An event whose line the file already holds, byte for byte, is taken and not
// written again. An event id the file or the append holds with another line
// refuses the whole append as ErrConflict, which matches otel.ErrSinkRefused
// too. An append that fails leaves the file as it was before it, and is
// ErrWrite; when the file cannot be cut back, the writer refuses every later
// append with ErrFailed. Before the write and after the sync, the path must
// still name the writer's file, a regular one and not a link, at the length
// the writer left it; otherwise the append is ErrChanged, and so is every
// later one. Nothing is written for an event the codec refuses, or once ctx
// has ended.
func (w *Writer) Append(ctx context.Context, events []*controlv1.Event) error {
	lines, err := encodeLines(events)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.f == nil || w.closed:
		return ErrClosed
	case w.failed != nil:
		return w.failed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := w.stillHeld(w.size); err != nil {
		return err
	}
	buf, added, err := w.ids.fresh(events, lines)
	if err != nil {
		return err
	}
	if len(buf) == 0 {
		return nil
	}
	if err := w.writeSynced(buf); err != nil {
		return w.cutBack(err)
	}
	if err := w.stillHeld(w.size + int64(len(buf))); err != nil {
		return err
	}
	w.size += int64(len(buf))
	w.ids.add(added)
	return nil
}

// writeSynced writes buf whole at the end of the file and syncs it.
func (w *Writer) writeSynced(buf []byte) error {
	n, err := w.ops.write(w.f, buf)
	switch {
	case err != nil:
		return err
	case n != len(buf):
		return io.ErrShortWrite
	}
	return w.ops.sync(w.f)
}

// encodeLines writes each event as its own evidence line.
func encodeLines(events []*controlv1.Event) ([][]byte, error) {
	out := make([][]byte, 0, len(events))
	for i, ev := range events {
		var b bytes.Buffer
		if err := evidence.EncodeJSONL(&b, []*controlv1.Event{ev}); err != nil {
			return nil, fmt.Errorf("%w: event %d: %w", ErrEvent, i, err)
		}
		out = append(out, b.Bytes())
	}
	return out, nil
}

// stillHeld checks that the path, not followed, still names the writer's file
// and that the file is size bytes long. When either fails, what the writer
// appends no longer reaches a reader of the path as Open would reach it, or
// the file's length is not what the writer left, so the writer takes nothing
// more. The file is not cut back: what it holds then is not the writer's to
// judge.
func (w *Writer) stillHeld(size int64) error {
	held, err := w.f.Stat()
	if err != nil {
		w.failed = fmt.Errorf("%w: %w", ErrChanged, err)
		return w.failed
	}
	named, err := os.Lstat(w.path)
	switch {
	case err != nil:
		w.failed = fmt.Errorf("%w: %w", ErrChanged, err)
	case !named.Mode().IsRegular():
		w.failed = fmt.Errorf("%w: %w", ErrChanged, ErrNotRegular)
	case !os.SameFile(held, named):
		w.failed = fmt.Errorf("%w: the path names another file", ErrChanged)
	case held.Size() != size:
		w.failed = fmt.Errorf("%w: the file is %d bytes long, and the writer left it at %d", ErrChanged, held.Size(), size)
	default:
		return nil
	}
	return w.failed
}

// cutBack returns the file to the length it had before the append that
// failed with cause, and syncs it. The bytes before that length were synced
// when their own append returned, so the file is then what the writer
// reported written and nothing else.
func (w *Writer) cutBack(cause error) error {
	if err := errors.Join(w.f.Truncate(w.size), w.f.Sync()); err != nil {
		w.failed = fmt.Errorf("%w: %w", ErrFailed, err)
		return fmt.Errorf("%w: %w; cutting it back failed too: %w", ErrWrite, cause, err)
	}
	return fmt.Errorf("%w: %w", ErrWrite, cause)
}

// Close releases the file and its lock. A second Close does nothing.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil || w.closed {
		return nil
	}
	w.closed = true
	return w.f.Close()
}
