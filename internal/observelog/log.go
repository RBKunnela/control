package observelog

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sync"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/proto"
)

// FileName is the log file's name in its directory.
const FileName = "observations.jsonl"

// MaxLogBytes bounds the log file an open reads whole to index it.
const MaxLogBytes int64 = 1 << 30

// fileOps are the calls a write and a cut make on the file, so a test can
// make any of them fail.
type fileOps struct {
	write    func(*os.File, []byte) (int, error)
	sync     func(*os.File) error
	truncate func(*os.File, int64) error
}

var osOps = fileOps{write: (*os.File).Write, sync: (*os.File).Sync, truncate: (*os.File).Truncate}

// Log appends records to one observation log it holds under an exclusive
// lock on the log file. Its zero value holds no file, and every write to it is
// refused.
type Log struct {
	mu   sync.Mutex
	path string
	f    *os.File
	// size is the length of the file up to the end of the last write that
	// was synced; limit is the length no write may take it past.
	size, limit int64
	ids         index
	kinds       sourceKinds
	failed      error
	closed      bool
	ops         fileOps
}

// Written is what one Write found: the observations it appended, and those
// it did not because the log held their id with the same content or with
// other content.
type Written struct {
	Observations, Duplicates, Conflicts int
}

// Open opens the log in dir and holds it until Close. dir must be a
// directory of this account that the group and others cannot reach, with no
// link at its name. The log file is created mode 0600 when absent; an
// existing one must be a regular file of this account that the group and
// others cannot reach, not a link and with no other name. A log another
// writer holds is ErrLocked.
//
// Every line is read and the observation ids indexed, so a log file past
// MaxLogBytes is refused as ErrTooLarge and has to be rotated by hand. Every
// write ends with its import report, so what follows the last whole report
// is what a crash in the middle of a write left, none of it reported
// written: observations of that write and the start of a line. Open cuts it,
// but only when a writer of this package could have left it. A log no writer
// of this package leaves is refused as ErrDamaged and left as it is.
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
// and cuts what follows the last report, and leaves the log at the length the
// file is left with. Nothing is cut before every whole line was read.
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
	ids, kinds, committed, err := readIndex(io.NewSectionReader(l.f, 0, end))
	if err != nil {
		return err
	}
	if committed != size {
		if err := errors.Join(l.ops.truncate(l.f, committed), l.f.Sync()); err != nil {
			return fmt.Errorf("cutting what follows the last import report: %w", err)
		}
	}
	l.ids, l.kinds, l.size = ids, kinds, committed
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

// Write appends the observations the log does not hold yet, then report, in
// one write that is synced before Write returns. An observation whose id the
// log or an earlier one of obs holds is not appended: a duplicate when its
// content digest is the same, a conflict when it is not. The report written
// is a copy of report with those counts added to its own, and the runs the
// conflicts claim to the runs it puts in doubt.
//
// An observation or a report the codec refuses, or none for report, refuses
// the whole call as ErrRecord; one naming a source the log holds records of
// under another kind, or two kinds for one source, refuses it as ErrKind;
// and a write that would take the file past MaxLogBytes is ErrTooLarge; none
// of them writes anything. A write that fails
// leaves the file as it was before it, and is ErrWrite; when the file cannot
// be cut back, the log refuses every later write with ErrFailed. Before the
// write and after the sync, the log file's name must still name the file the
// log holds, at the length it left it; otherwise the write is ErrChanged, and
// so is every later one.
func (l *Log) Write(obs []*observev1.Observation, report *observev1.ImportReport) (Written, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.f == nil || l.closed:
		return Written{}, ErrClosed
	case l.failed != nil:
		return Written{}, l.failed
	}
	b, err := l.ids.fresh(obs)
	if err != nil {
		return Written{}, err
	}
	line, err := reportLine(report, b.found, &b.doubt)
	if err != nil {
		return Written{}, err
	}
	kinds, err := l.kinds.admit(batchRecords(obs, report))
	if err != nil {
		return Written{}, err
	}
	buf := append(b.lines, line...)
	if end := l.size + int64(len(buf)); end > l.limit {
		return Written{}, fmt.Errorf("%w: the write would take it to %d bytes, limit %d", ErrTooLarge, end, l.limit)
	}
	if err := l.stillHeld(l.size); err != nil {
		return Written{}, err
	}
	if err := l.writeSynced(buf); err != nil {
		return Written{}, l.cutBack(err)
	}
	if err := l.stillHeld(l.size + int64(len(buf))); err != nil {
		return Written{}, err
	}
	l.size += int64(len(buf))
	l.ids.add(b.added)
	maps.Copy(l.kinds, kinds)
	return b.found, nil
}

// reportLine encodes a copy of report with found's duplicates and conflicts
// added to its counts, and doubt's runs to its runs in doubt. report itself
// must be one the codec writes, so runs in doubt it names in another form
// are refused rather than put in order.
func reportLine(report *observev1.ImportReport, found Written, doubt *observe.Doubt) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("%w: no import report", ErrRecord)
	}
	if _, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: report}}); err != nil {
		return nil, fmt.Errorf("%w: the import report: %w", ErrRecord, err)
	}
	r, ok := proto.Clone(report).(*observev1.ImportReport)
	if !ok {
		return nil, fmt.Errorf("%w: the import report does not copy", ErrRecord)
	}
	// Merged before this write's own conflicts are counted, which doubt
	// already names, so they are not read as conflicts that name no run.
	doubt.Merge(r)
	if r.Counts == nil {
		r.Counts = &observev1.ImportCounts{}
	}
	r.Counts.Duplicate += uint64(found.Duplicates) //nolint:gosec // G115: a count is never negative
	r.Counts.Conflict += uint64(found.Conflicts)   //nolint:gosec // G115: a count is never negative
	doubt.Fill(r)
	line, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: r}})
	if err != nil {
		return nil, fmt.Errorf("%w: the import report: %w", ErrRecord, err)
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
// file the log holds, that no other name does, and that the file is size bytes
// long. When any fails,
// what the log appends no longer reaches a reader of the name, so the log
// takes nothing more. The file is not cut back: what it holds then is not the
// log's to judge.
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
