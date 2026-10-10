package findinglog

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/files"
	"google.golang.org/protobuf/proto"
)

// FileName is the log file's name in its directory.
const FileName = "findings.jsonl"

// MaxLogBytes bounds the log file an open reads whole to index it, and the
// length a write may take it to.
const MaxLogBytes int64 = 1 << 30

// fileOps are the calls a write and a cut make on the file, so a test can
// make any of them fail.
type fileOps struct {
	write    func(*os.File, []byte) (int, error)
	sync     func(*os.File) error
	truncate func(*os.File, int64) error
}

var osOps = fileOps{write: (*os.File).Write, sync: (*os.File).Sync, truncate: (*os.File).Truncate}

// Log appends findings to one findings log it holds under an exclusive lock
// on the log file. Its zero value holds no file, and every write to it is
// refused.
type Log struct {
	mu   sync.Mutex
	path string
	f    *os.File
	// size is the length of the file up to the end of the last write that
	// was synced; limit is the length no write may take it past.
	size, limit int64
	keys        index
	failed      error
	closed      bool
	ops         fileOps
}

// Result is what one Write found: the findings it appended, those it did not
// because the log held their id and verdict with the same content, and the
// finding id of each it did not because the log held them with other
// content, in the order given.
type Result struct {
	Written, Duplicates int
	Conflicts           []string
}

// Open opens the log in dir and holds it until Close. dir must exist, be a
// directory of this account that the group and others cannot reach, with no
// link at its name. The log file is created mode 0600 when absent; an
// existing one must be a regular file of this account that the group and
// others cannot reach, not a link and with no other name. A log another
// writer holds is ErrLocked.
//
// Every line is read and the keys indexed, so a log file past MaxLogBytes is
// refused as ErrTooLarge. Every write ends with its report, so what follows
// the last whole report, or the header when no report follows it, is what a
// crash in the middle of a write left, none of it reported written. Open
// cuts it, but only when the writer could have left it; a log the writer
// does not leave is ErrDamaged, naming the line and its byte offset but none
// of its bytes, and is left as it is. A log holding no line after the cut
// is given a header with a new random log id, synced before Open returns,
// and a header that does not reach the disk is cut back and fails the Open
// as ErrWrite. A log that holds a line and no header, as one made before
// schema "0.2" does, is never given one.
func Open(dir string) (*Log, error) { return open(dir, osOps) }

func open(dir string, ops fileOps) (*Log, error) {
	if !files.PermissionBits {
		return nil, ErrNoPermissionBits
	}
	root, err := openDir(dir)
	if err != nil {
		return nil, err
	}
	f, err := openFile(root)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	l := &Log{path: filepath.Join(filepath.Clean(dir), FileName), f: f, ops: ops, limit: MaxLogBytes}
	err = l.claim()
	if err == nil {
		err = syncRoot(root)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close(), root.Close())
	}
	if err := root.Close(); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return l, nil
}

// claim judges the open file, locks it, judges it again, indexes its lines
// and cuts what follows the last report. Nothing is cut before every whole
// line was read.
func (l *Log) claim() error {
	if _, err := judgedSize(l.f); err != nil {
		return err
	}
	if err := lock(l.f); err != nil {
		return err
	}
	// Another writer may have cut the file or committed a write between the
	// first judgement and the lock; only a length read under it is the log's.
	size, err := judgedSize(l.f)
	if err != nil {
		return err
	}
	if size > MaxLogBytes {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, size, MaxLogBytes)
	}
	end, err := lastLineEnd(l.f, size)
	if err != nil {
		return err
	}
	keys, committed, err := scanLog(io.NewSectionReader(l.f, 0, end), nil)
	if err != nil {
		return err
	}
	if committed != size {
		if err := errors.Join(l.ops.truncate(l.f, committed), l.f.Sync()); err != nil {
			return fmt.Errorf("cutting what follows the last report: %w", err)
		}
	}
	l.keys, l.size = keys, committed
	if committed == 0 {
		return l.writeHeader()
	}
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

// writeHeader starts an empty log with a header of a new random log id. A
// log that already holds a line keeps the identity it has.
func (l *Log) writeHeader() error {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Errorf("drawing the log id: %w", err)
	}
	line, err := marshalLine(&findingv1alpha1.Record{Record: &findingv1alpha1.Record_LogHeader{LogHeader: &findingv1alpha1.LogHeader{
		SchemaVersion: SchemaVersion02,
		LogId:         "log-" + hex.EncodeToString(id[:]),
	}}})
	if err != nil {
		return err
	}
	if err := l.writeSynced(line); err != nil {
		return l.cutBack(err)
	}
	l.size = int64(len(line))
	return nil
}

// Write appends the findings the log does not hold yet, then report, in one
// write that is synced before Write returns; the report is the commit point.
// A finding whose id and verdict the log or an earlier one of findings holds
// is not appended: a duplicate when its content is the same, a conflict when
// it is not, and the write commits all the same. The report written is a
// copy of report with findings_written set to the findings appended.
//
// A finding or a report this log will not write, or none for report,
// refuses the whole call as ErrRecord; so does a write that would take the
// file past MaxLogBytes, as ErrTooLarge. A write that fails leaves the file
// as it was before it, and is ErrWrite; when the file cannot be cut back, the
// log refuses every later write with ErrFailed. Before the write and after
// the sync, the log file's name must still name the file the log holds, at
// the length it left it; otherwise the write is ErrChanged, and so is every
// later one.
func (l *Log) Write(findings []*findingv1alpha1.FindingRecord, report *findingv1alpha1.SuperviseReport) (Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.f == nil || l.closed:
		return Result{}, ErrClosed
	case l.failed != nil:
		return Result{}, l.failed
	}
	b, err := l.keys.fresh(findings)
	if err != nil {
		return Result{}, err
	}
	line, err := reportLine(report, b.found.Written)
	if err != nil {
		return Result{}, err
	}
	buf := append(b.lines, line...)
	if end := l.size + int64(len(buf)); end > l.limit {
		return Result{}, fmt.Errorf("%w: the write would take it to %d bytes, limit %d", ErrTooLarge, end, l.limit)
	}
	if err := l.stillHeld(l.size); err != nil {
		return Result{}, err
	}
	if err := l.writeSynced(buf); err != nil {
		return Result{}, l.cutBack(err)
	}
	if err := l.stillHeld(l.size + int64(len(buf))); err != nil {
		return Result{}, err
	}
	l.size += int64(len(buf))
	l.keys.add(b.added)
	return b.found, nil
}

// reportLine encodes a copy of report with written as its findings written.
func reportLine(report *findingv1alpha1.SuperviseReport, written int) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("%w: no report", ErrRecord)
	}
	r, ok := proto.Clone(report).(*findingv1alpha1.SuperviseReport)
	if !ok {
		return nil, fmt.Errorf("%w: the report does not copy", ErrRecord)
	}
	r.FindingsWritten = uint64(written) //nolint:gosec // G115: a count is never negative
	line, err := marshalLine(&findingv1alpha1.Record{Record: &findingv1alpha1.Record_SuperviseReport{SuperviseReport: r}})
	if err != nil {
		return nil, fmt.Errorf("%w: the report: %w", ErrRecord, err)
	}
	return line, nil
}

// writeSynced writes buf whole at the end of the file and syncs it.
func (l *Log) writeSynced(buf []byte) error {
	n, err := l.ops.write(l.f, buf)
	switch {
	case err != nil:
		return err
	case n != len(buf):
		return io.ErrShortWrite
	}
	return l.ops.sync(l.f)
}

// stillHeld checks that the log file's name, not followed, still names the
// file the log holds, that no other name does, and that the file is size
// bytes long. When any fails, what the log appends no longer reaches a
// reader of the name, so the log takes nothing more. The file is not cut
// back: what it holds then is not the log's to judge.
func (l *Log) stillHeld(size int64) error {
	held, err := l.f.Stat()
	if err != nil {
		l.failed = fmt.Errorf("%w: %w", ErrChanged, err)
		return l.failed
	}
	named, err := os.Lstat(l.path)
	switch {
	case err != nil:
		l.failed = fmt.Errorf("%w: %w", ErrChanged, err)
	case !named.Mode().IsRegular():
		l.failed = fmt.Errorf("%w: %w", ErrChanged, ErrNotRegular)
	case !os.SameFile(held, named):
		l.failed = fmt.Errorf("%w: the name holds another file", ErrChanged)
	case !singleName(held):
		l.failed = fmt.Errorf("%w: %w", ErrChanged, ErrLinks)
	case held.Size() != size:
		l.failed = fmt.Errorf("%w: the file is %d bytes long, and the log left it at %d", ErrChanged, held.Size(), size)
	default:
		return nil
	}
	return l.failed
}

// cutBack returns the file to the length it had before the write that
// failed with cause, and syncs it.
func (l *Log) cutBack(cause error) error {
	if err := errors.Join(l.ops.truncate(l.f, l.size), l.f.Sync()); err != nil {
		l.failed = fmt.Errorf("%w: %w", ErrFailed, err)
		return fmt.Errorf("%w: %w; cutting it back failed too: %w", ErrWrite, cause, err)
	}
	return fmt.Errorf("%w: %w", ErrWrite, cause)
}

// Close releases the log file and its lock. A second Close does nothing.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil || l.closed {
		return nil
	}
	l.closed = true
	return l.f.Close()
}
