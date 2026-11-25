package findinglog

import (
	"fmt"
	"io"
	"os"
	"strconv"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/files"
)

// ReadFile returns, in file order, the log's header when it has one, then
// the records of the log file at path that a report closes. It takes no
// lock, writes nothing and creates nothing, so it reads a log a writer holds
// as the file stood when opened.
//
// The file must pass the writer's own judgement: a regular file of this
// account that the group and others cannot reach, with no other name and no
// longer than MaxLogBytes; a link at path is refused as ErrNotRegular. The
// bytes after the last newline are a line still being written and are left
// out, as are the findings after the last report. A file the writer does not
// leave is ErrDamaged, naming the line and its byte offset but none of its
// bytes. A missing file is an error that matches fs.ErrNotExist.
func ReadFile(path string) ([]*findingv1alpha1.Record, error) {
	if !files.PermissionBits {
		return nil, ErrNoPermissionBits
	}
	named, err := os.Lstat(path)
	switch {
	case err != nil:
		return nil, err
	case !named.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, strconv.Quote(path))
	}
	// A link put at the name after the Lstat is not followed, and a named
	// pipe is not waited on.
	f, err := os.OpenFile(path, os.O_RDONLY|openFlags, 0) //nolint:gosec // G304: the path is the operator's to name, and the descriptor is judged before a byte is read
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := judgeFile(info); err != nil {
		return nil, err
	}
	if info.Size() > MaxLogBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, info.Size(), MaxLogBytes)
	}
	out, _, err := readCommitted(f, info.Size())
	return out, err
}

// Tail is what a log held past its last committed write when it was read.
type Tail struct {
	// Bytes counts the lines no report closes and the bytes after the last
	// newline.
	Bytes int64
	// Held says a writer held the log then, or the file's size changed
	// while it was read, so the tail is a write still open; it is asked only
	// when Bytes is not zero.
	Held bool
}

// ReadFileTail is ReadFile, judging the file as it does, that also returns
// the log's tail: a writer that holds the log is still writing it, and
// without one the tail is a write no report will close.
func ReadFileTail(path string) ([]*findingv1alpha1.Record, Tail, error) {
	f, size, err := openToRead(path)
	if err != nil {
		return nil, Tail{}, err
	}
	defer func() { _ = f.Close() }()
	out, committed, err := readCommitted(f, size)
	if err != nil || committed == size {
		return out, Tail{}, err
	}
	held, err := heldByWriter(f)
	if err != nil {
		return nil, Tail{}, err
	}
	if !held {
		// A writer that committed and let go after the size was taken has
		// changed the size: that tail was a write in progress.
		now, err := f.Stat()
		if err != nil {
			return nil, Tail{}, err
		}
		held = now.Size() != size
	}
	return out, Tail{Bytes: size - committed, Held: held}, nil
}

// readCommitted reads the first size bytes of r as Open judges them and
// returns the header and the records of every write a report closes, and
// where the last of those writes ends.
func readCommitted(r io.ReaderAt, size int64) ([]*findingv1alpha1.Record, int64, error) {
	end, err := lastLineEnd(r, size)
	if err != nil {
		return nil, 0, err
	}
	var out []*findingv1alpha1.Record
	_, committed, err := scanLog(io.NewSectionReader(r, 0, end), func(write []*findingv1alpha1.Record) { out = append(out, write...) })
	if err != nil {
		return nil, 0, err
	}
	return out, committed, nil
}
