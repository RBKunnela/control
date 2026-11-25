package observelog

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/observe"
)

// ReadFile returns, in file order, the records of the log file at path that
// an import report closes. It takes no lock, writes nothing and creates
// nothing, so it reads a log a writer holds as the file stood when opened.
//
// The file must pass the writer's own judgement: a regular file of this
// account that the group and others cannot reach, with no other name and no
// longer than MaxLogBytes; a link at path is refused as ErrNotRegular. The
// bytes after the last newline are a line still being written and are left
// out, as are the records after the last import report. A file a writer of
// this package does not leave is ErrDamaged, naming the line and its byte
// offset but none of its bytes. A missing file is an error that matches
// fs.ErrNotExist.
func ReadFile(path string) ([]*observev1.Record, error) {
	c, err := ReadCommitted(path)
	return c.Records, err
}

// Committed is what ReadCommitted reads of a log file.
type Committed struct {
	// Records are those of every write an import report closes, in file
	// order.
	Records []*observev1.Record
	// Unclosed is true when bytes follow the last import report: a write
	// still under way or one cut short, whose observations are not in
	// Records and may be of any run.
	Unclosed bool
}

// ReadCommitted reads the log file at path as ReadFile does, and says
// whether it holds bytes past the last write an import report closes.
func ReadCommitted(path string) (Committed, error) {
	f, info, err := openJudged(path)
	if err != nil {
		return Committed{}, err
	}
	defer func() { _ = f.Close() }()
	if info.Size() > MaxLogBytes {
		return Committed{}, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, info.Size(), MaxLogBytes)
	}
	return readCommitted(f, info.Size())
}

// openJudged opens the log file at path for reading once the writer's own
// judgement passes it: a regular file at the name itself, of this account,
// that the group and others cannot reach, with no other name.
func openJudged(path string) (*os.File, os.FileInfo, error) {
	if !files.PermissionBits {
		return nil, nil, ErrNoPermissionBits
	}
	named, err := os.Lstat(path)
	switch {
	case err != nil:
		return nil, nil, err
	case !named.Mode().IsRegular():
		return nil, nil, fmt.Errorf("%w: %s", ErrNotRegular, strconv.Quote(path))
	}
	// The writer's flags: a link put at the name after the Lstat is not
	// followed, and a named pipe is not waited on.
	f, err := os.OpenFile(path, os.O_RDONLY|writeFlags, 0) //nolint:gosec // G304: the path is the operator's to name, and the descriptor is judged before a byte is read
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err == nil {
		err = judgeFile(info)
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// readCommitted reads the first size bytes of r as the writer's Open judges
// them and returns the records of every write an import report closes, and
// whether any byte follows the last of them.
func readCommitted(r io.ReaderAt, size int64) (Committed, error) {
	end, err := lastLineEnd(r, size)
	if err != nil {
		return Committed{}, err
	}
	var out []*observev1.Record
	_, committed, err := scanLog(io.NewSectionReader(r, 0, end), func(write []*observev1.Record) { out = append(out, write...) })
	var fault *lineFault
	switch {
	case errors.As(err, &fault) && errors.Is(fault.cause, bufio.ErrBufferFull):
		return Committed{}, fmt.Errorf("%w: line %d, at byte %d, is over %d bytes", ErrDamaged, fault.number, fault.offset, observe.MaxLineBytes)
	case errors.As(err, &fault):
		return Committed{}, fmt.Errorf("%w: line %d, at byte %d", ErrDamaged, fault.number, fault.offset)
	case err != nil:
		return Committed{}, err
	}
	return Committed{Records: out, Unclosed: committed < size}, nil
}
