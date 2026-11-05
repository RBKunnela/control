package gatewayconfig

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/guardana/control/internal/files"
)

// maxLinks bounds the links one path may pass, as the kernel bounds its own
// lookup, so a loop of links is refused rather than followed.
const maxLinks = 40

// resolveJudged resolves path a component at a time from the root of the
// file system, following each link it meets, and judges every entry it
// passes: each directory and each link has to be the plane's account's or
// root's, and no directory may let another account write it unless it is
// sticky or a directory of root's on a read-only mount. Whoever may change
// any of them could put a file of their own at the path. The path is walked
// as given, never cleaned first, so ".." after a link names the parent of
// what the link reached, as the kernel takes it. It returns the path the walk
// reached, which holds no link.
func resolveJudged(path string) (string, error) {
	return walkJudged(path, configJudge)
}

// walkJudge judges the entries a walk passes: dir the root and every
// directory the walk enters, link every link before it is followed. The entry
// the walk ends at, unless it is a directory, is the caller's to judge.
type walkJudge struct {
	dir  func(path string, info fs.FileInfo) error
	link func(path string, info fs.FileInfo) error
}

// configJudge is the configuration's: whoever may change a directory or a
// link on its path, other than the plane's account and root, is refused.
var configJudge = walkJudge{dir: judgeTraversed, link: judgeConfigLink}

// walkJudged walks path as resolveJudged describes, judging each entry it
// passes by judge, and returns the path it reached, which holds no link.
func walkJudged(path string, judge walkJudge) (string, error) {
	abs := path
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		abs = wd + separator + path
	}
	top, err := os.Lstat(separator)
	if err != nil {
		return "", err
	}
	if err := judge.dir(separator, top); err != nil {
		return "", err
	}
	w := &pathWalk{at: separator, isDir: true, pending: strings.Split(abs, separator), judge: judge}
	for len(w.pending) > 0 {
		if err := w.step(); err != nil {
			return "", err
		}
	}
	return w.at, nil
}

const separator = string(filepath.Separator)

// pathWalk is a walk under way: the path reached, which holds no link,
// whether it is a directory, the links passed, the names still to take, and
// how each entry passed is judged.
type pathWalk struct {
	at      string
	isDir   bool
	links   int
	pending []string
	judge   walkJudge
}

// step takes the next name.
func (w *pathWalk) step() error {
	name := w.pending[0]
	w.pending = w.pending[1:]
	switch {
	case !w.isDir:
		return fmt.Errorf("%s: %w", w.at, files.ErrNotDirectory)
	case name == "" || name == ".":
		return nil
	case name == "..":
		w.at = filepath.Dir(w.at)
		return nil
	}
	next := filepath.Join(w.at, name)
	info, err := os.Lstat(next)
	if err != nil {
		return err
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return w.follow(next, info)
	case info.IsDir():
		if err := w.judge.dir(next, info); err != nil {
			return err
		}
		w.at = next
	default:
		w.at, w.isDir = next, false
	}
	return nil
}

// follow puts the names link's target holds before the names still to take,
// from the root where the target is absolute.
func (w *pathWalk) follow(link string, info fs.FileInfo) error {
	if w.links++; w.links > maxLinks {
		return fmt.Errorf("%s: %w: more than %d", link, errTooManyLinks, maxLinks)
	}
	if err := w.judge.link(link, info); err != nil {
		return err
	}
	target, err := os.Readlink(link)
	if err != nil {
		return err
	}
	if filepath.IsAbs(target) {
		w.at = separator
	}
	w.pending = append(strings.Split(target, separator), w.pending...)
	return nil
}

// judgeConfigLink refuses a link on the configuration's path that an account
// other than the plane's or root owns: its owner may point it anywhere.
func judgeConfigLink(link string, info fs.FileInfo) error {
	if err := checkConfigOwner(info); err != nil {
		return fmt.Errorf("the link %s: %w", link, err)
	}
	return nil
}

// judgeTraversed judges a directory the path passes. A sticky directory lets
// nobody but an entry's owner replace the entry, and every entry the walk
// takes from it is judged by its owner in turn.
func judgeTraversed(dir string, info fs.FileInfo) error {
	if err := checkConfigOwner(info); err != nil {
		return fmt.Errorf("the directory %s: %w", dir, err)
	}
	if info.Mode()&fs.ModeSticky != 0 || othersMayWrite(info) == nil {
		return nil
	}
	configStep(stepDirLooked)
	d, err := files.OpenDir(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	opened, err := d.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, opened) {
		return fmt.Errorf("the directory %s %w", dir, errChanged)
	}
	if err := judgeDirMode(d, opened); err != nil {
		return fmt.Errorf("the directory %s: %w", dir, err)
	}
	return nil
}

// judgeDirMode refuses an opened directory another account may write, unless
// it is sticky, or root's and on a read-only mount, where no account may
// write it through this mount whatever its mode says. A read-only mount is
// taken as its owner's word: a directory of another account's mounted
// read-only could be written through another mount by that account. A mount
// whose flags cannot be read is refused.
func judgeDirMode(d *os.File, info fs.FileInfo) error {
	if info.Mode()&fs.ModeSticky != 0 {
		return nil
	}
	why := othersMayWrite(info)
	if why == nil {
		return nil
	}
	if uid, named := ownerOf(info); !named || uid != 0 {
		return fmt.Errorf("%w; it is not sticky, nor root's on a read-only mount", why)
	}
	ro, err := onReadOnlyMount(d)
	switch {
	case err != nil:
		return fmt.Errorf("%w, on a mount whose flags cannot be read: %w", why, err)
	case !ro:
		return fmt.Errorf("%w; it is not sticky, nor on a read-only mount", why)
	}
	return nil
}
