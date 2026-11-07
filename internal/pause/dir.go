package pause

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/guardana/control/internal/files"
)

// The steps a test can act at: the directory opened and judged, the root on
// it established, and the pause file's name judged no link.
const (
	stepOpened    = "opened"
	stepRooted    = "rooted"
	stepFileNamed = "file named"
)

// dirSteps, when a test sets it, runs at each step, so the test can swap the
// directory or the file under the path in between.
var dirSteps func(step string)

func step(s string) {
	if dirSteps != nil {
		dirSteps(s)
	}
}

// openDir opens the directory holding the pause file and returns a root on
// it. The open refuses a link at dir and never waits on a named pipe; the
// mode and the owner are judged on the opened descriptor; and every later
// open goes through the root, which is proven to be that same directory, so
// a directory swapped in under the path after the check is never read or
// written. Whoever may replace the file in a directory the group or others
// may write, or another account than o allows owns, may lift every pause.
func openDir(dir string, o owner) (*os.Root, error) {
	d, err := files.OpenDir(dir)
	if err != nil {
		if info, lerr := os.Lstat(dir); lerr == nil && info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s", ErrDirLink, dir)
		}
		return nil, missing(err)
	}
	// Held open until the root is proven the same directory, so its identity
	// cannot pass to another directory in between.
	defer func() { _ = d.Close() }()
	judged, err := d.Stat()
	if err != nil {
		return nil, err
	}
	if judged.Mode().Perm()&forbidden != 0 {
		return nil, fmt.Errorf("%w: mode %04o", ErrDirMode, judged.Mode().Perm())
	}
	if err := o.judge(judged, ErrDirOwner); err != nil {
		return nil, fmt.Errorf("the directory: %w", err)
	}
	step(stepOpened)
	// A root is opened by path only. The trailing "." fails on anything but a
	// directory rather than wait on a pipe, and the identity check below
	// refuses whatever took the judged directory's place in between.
	root, err := os.OpenRoot(dir + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, missing(err)
	}
	rooted, err := root.Stat(".")
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	if !os.SameFile(judged, rooted) {
		return nil, errors.Join(fmt.Errorf("%w: %s", ErrDirChanged, dir), root.Close())
	}
	step(stepRooted)
	return root, nil
}
