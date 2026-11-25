package files

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ReplaceJudged is ReplaceJudgedIn through a handle to dir.
func ReplaceJudged(ctx context.Context, dir, name string, body []byte, perm fs.FileMode, judged fs.FileInfo) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	return errors.Join(ReplaceJudgedIn(ctx, root, name, body, perm, judged), root.Close())
}

// ReplaceJudgedIn puts body under name in the directory root holds, with mode
// perm, only over the regular file judged describes, as an Lstat of name
// found it, and with a nil judged only where nothing stands at name, by a
// create that never replaces. Writers of this package serialise on an
// exclusive flock of the judged file itself, opened without following a
// link, and of the new file before it takes the name, both held until the
// exchange is settled; the directory is never locked, since callers hold
// their own lock on it. Any process that can read a file can hold a flock
// of it, so a lock still held when ctx ends refuses the write with
// ErrLockHeld, nothing written. Once the judged file's lock is held,
// the file and the name are judged again, so a writer that waited while
// another replaced the file is refused with ErrNotJudged and
// ErrNothingWritten. Another entry at the name, a file, a link or a
// directory, is refused the same way, and a judged entry that is not a
// regular file is refused with ErrNotRegular. It answers nil only while the
// name holds its new file once the exchange is settled.
//
// The locks bind the writers of this program only. Another program that
// writes the name takes no such lock; what it puts there between the second
// judgement and the exchange is exchanged back, but a reader of the name in
// that instant reads the new file. An exchange back that fails is
// ErrNotPutBack, naming where the entry is; one whose name changed again in
// between leaves what stood there under the temporary name the error names;
// a new file such a program replaced before the exchange settled is
// ErrNotKept. A platform or file system with no exchange refuses with
// ErrNoExchange.
func ReplaceJudgedIn(ctx context.Context, root *os.Root, name string, body []byte, perm fs.FileMode, judged fs.FileInfo) error {
	if !oneName(name) {
		return fmt.Errorf("%w: %q", ErrNotOneName, name)
	}
	if judged == nil {
		err := CreateNoReplaceIn(root, name, body, perm)
		if errors.Is(err, ErrExists) {
			return fmt.Errorf("%w: %q was absent when it was judged: %w", ErrNotJudged, name, err)
		}
		return err
	}
	if !judged.Mode().IsRegular() {
		return fmt.Errorf("%w: the entry judged at %q is %s, which no lock holds", ErrNotRegular, name, describe(judged.Mode()))
	}
	held, err := openJudged(root, name)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errLink) {
		return changed(name)
	}
	if err != nil {
		return err
	}
	beforeLocked(name)
	if err := lockNamed(ctx, held, strconv.Quote(name)); err != nil {
		return errors.Join(lockRefused(err, nil), held.Close())
	}
	return errors.Join(replaceHeld(ctx, root, held, name, body, perm, judged), held.Close())
}

// lockNamed takes f's lock as lockFile does, naming the file what describes
// in a refusal.
func lockNamed(ctx context.Context, f *os.File, what string) error {
	switch err := lockFile(ctx, f); {
	case errors.Is(err, ErrLockHeld):
		return fmt.Errorf("%w: %s; the wait for it ended (%w)", err, what, context.Cause(ctx))
	case err != nil:
		return fmt.Errorf("files: locking %s: %w", what, err)
	}
	return nil
}

// lockRefused adds to a lock refusal that nothing was written when removing
// the new file succeeded, and joins the removal's error otherwise.
func lockRefused(refusal, removed error) error {
	if removed != nil {
		return errors.Join(refusal, removed)
	}
	return fmt.Errorf("%w; nothing was written", refusal)
}

// replaceHeld is ReplaceJudgedIn once held, the file at name, is locked.
func replaceHeld(ctx context.Context, root *os.Root, held *os.File, name string, body []byte, perm fs.FileMode, judged fs.FileInfo) error {
	info, err := held.Stat()
	if err != nil {
		return err
	}
	if !SameEntry(info, judged) {
		return changed(name)
	}
	if err := stillJudged(root, name, judged); err != nil {
		return err
	}
	tmp, err := writeTemp(root, body, perm)
	if err != nil {
		return err
	}
	fresh, err := openJudged(root, tmp)
	if err != nil {
		return errors.Join(err, root.Remove(tmp))
	}
	beforeLocked(tmp)
	err = lockNamed(ctx, fresh, fmt.Sprintf("%q, the new file for %q", tmp, name))
	if err == nil {
		err = exchangeLocked(root, fresh, name, tmp, judged)
	} else {
		err = lockRefused(err, root.Remove(tmp))
	}
	return errors.Join(err, fresh.Close())
}

// exchangeLocked exchanges tmp, the new file fresh holds locked, with name,
// and settles the exchange or puts back what came out of name. A writer of
// this package that judged the new file once it took the name waits on
// fresh's lock until then, so it never replaces the new file before this
// writer judged that the name holds it.
func exchangeLocked(root *os.Root, fresh *os.File, name, tmp string, judged fs.FileInfo) error {
	written, err := fresh.Stat()
	if err != nil {
		return errors.Join(err, root.Remove(tmp))
	}
	if err := exchangeIn(root, tmp, name); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return unwritten(fmt.Errorf("%w: %q is gone since it was judged", ErrNotJudged, name), root.Remove(tmp))
		}
		return errors.Join(err, root.Remove(tmp))
	}
	betweenExchanges(root, tmp)
	out, err := root.Lstat(tmp)
	if err == nil && sameMoved(out, judged) {
		return settle(root, name, tmp, written)
	}
	return putBack(root, name, tmp, written)
}

// settle removes the judged file the exchange moved to tmp and answers nil
// only while the name holds the new file, written.
func settle(root *os.Root, name, tmp string, written fs.FileInfo) error {
	if err := errors.Join(root.Remove(tmp), syncRoot(root)); err != nil {
		return err
	}
	inSettle()
	if now, err := root.Lstat(name); err != nil || !os.SameFile(now, written) {
		return errors.Join(fmt.Errorf("%w: %q was replaced once the new file took it", ErrNotKept, name), err)
	}
	return nil
}

// stillJudged refuses with ErrNotJudged and ErrNothingWritten unless the
// entry at name is the one judged describes.
func stillJudged(root *os.Root, name string, judged fs.FileInfo) error {
	switch now, err := root.Lstat(name); {
	case errors.Is(err, fs.ErrNotExist):
		return changed(name)
	case err != nil:
		return err
	case !SameEntry(now, judged):
		return changed(name)
	}
	return nil
}

// changed is the refusal of a name that no longer holds the judged entry,
// before anything was written.
func changed(name string) error {
	return fmt.Errorf("%w: %q changed or is gone since it was judged: %w", ErrNotJudged, name, ErrNothingWritten)
}

// unwritten is refusal marked ErrNothingWritten when removed, the removal
// of the temporary file it wrote, succeeded, and joined with it otherwise.
func unwritten(refusal, removed error) error {
	if removed != nil {
		return errors.Join(refusal, removed)
	}
	return fmt.Errorf("%w: %w", refusal, ErrNothingWritten)
}

// putBack exchanges what came out of name, now at tmp, back under name and
// removes the new file, written, which the exchange returns to tmp.
func putBack(root *os.Root, name, tmp string, written fs.FileInfo) error {
	if err := exchangeIn(root, tmp, name); err != nil {
		return fmt.Errorf("%w: %q changed since it was judged, and the new file holds it; what stood there is at %q: %w", ErrNotPutBack, name, tmp, err)
	}
	refused := fmt.Errorf("%w: %q changed since it was judged; the new file stood under the name until what stood there was put back", ErrNotJudged, name)
	if back, err := root.Lstat(tmp); err != nil || !os.SameFile(back, written) {
		return errors.Join(refused, fmt.Errorf("%q changed again while it was put back; %q holds what stood there then", name, tmp))
	}
	return errors.Join(refused, root.Remove(tmp))
}

// betweenExchanges runs, in a test, once the new file took the name and
// before what came out is compared with the entry judged.
var betweenExchanges = func(*os.Root, string) {}

// inSettle runs, in a test, once settle removed the judged file and before
// it judges what the name holds.
var inSettle = func() {}

// beforeLocked runs, in a test, once the file a lock is taken of is open
// under name and before the lock is taken.
var beforeLocked = func(string) {}

// oneName reports whether name is one entry of a directory, which the raw
// exchange below takes as given, past the confinement os.Root keeps.
func oneName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsRune(name, '/') && filepath.Base(name) == name
}

// SameEntry reports whether a and b describe one file as it was: the same
// device and inode, type and mode, size, modification time and, where the
// platform keeps it, change time. Another entry at the name, and a file of a
// reused inode number, is another. A rewrite in place to the same size within
// one tick of the file system's clock is not seen; the writers of this
// package never write in place.
func SameEntry(a, b fs.FileInfo) bool {
	ac, aok := changeTime(a)
	bc, bok := changeTime(b)
	return sameMoved(a, b) && aok == bok && ac.Equal(bc)
}

// sameMoved is SameEntry without the change time, which renaming a file
// sets on some file systems.
func sameMoved(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// exchangeIn exchanges the entries at a and b in the directory root holds in
// one step. It refuses with fs.ErrNotExist when either is missing.
func exchangeIn(root *os.Root, a, b string) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(exchange(d, a, b), d.Close())
}
