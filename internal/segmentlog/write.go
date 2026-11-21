package segmentlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"time"
)

// usable refuses a call on a log that is closed or that a seal or a prune
// left part way.
func (l *segments) usable() error {
	switch {
	case l.closed:
		return ErrClosed
	case l.failed != nil:
		return l.failed
	}
	return nil
}

// Append writes lines to the live segment. Lines that would take a live
// segment holding a line past SegmentBytes seal it first; lines that would
// then take the log past MaxBytes are refused with ErrBudget and nothing of
// them is written. An append that leaves the live file other than the log
// counts it fails the log.
func (l *segments) Append(ctx context.Context, lines []byte) error {
	if len(lines) == 0 || lines[len(lines)-1] != '\n' {
		return ErrLines
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.usable(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.makeRoom(int64(len(lines))); err != nil {
		return err
	}
	if err := l.file.AppendLines(ctx, lines); err != nil {
		if errors.Is(err, ErrLiveChanged) {
			return l.fail(err)
		}
		return err
	}
	for line := range bytes.Lines(lines) {
		l.live.add(line)
	}
	return nil
}

// makeRoom seals a live segment holding a line that n bytes more would take
// past its bound, before it asks the log's own, so a log the bound refuses
// holds a sealed segment to prune; refuses n bytes past the log's bound; and
// opens the live segment when none is open.
func (l *segments) makeRoom(n int64) error {
	if l.cfg.MaxBytes == 0 {
		return fmt.Errorf("%w: the log was opened with no bound, so it takes no append", ErrBudget)
	}
	if l.live.lines > 0 && l.live.bytes > l.cfg.SegmentBytes-n {
		if err := l.seal(); err != nil {
			return err
		}
	}
	if l.retained() > l.cfg.MaxBytes-n {
		return fmt.Errorf("%w: %d bytes held, %d more asked, %d at most", ErrBudget, l.retained(), n, l.cfg.MaxBytes)
	}
	if l.file != nil {
		return nil
	}
	f, err := l.cfg.OpenLive(l.root, LiveName)
	if err != nil {
		return fmt.Errorf("%s: %w", LiveName, err)
	}
	l.file = f
	return nil
}

// Seal seals the live segment when it holds a line.
func (l *segments) Seal() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.usable(); err != nil {
		return err
	}
	return l.seal()
}

// seal names the live segment sealed in the manifest, then renames its file.
// A step that fails after the manifest changed leaves the log refusing until
// it is opened again, which completes the seal or finds it not begun.
func (l *segments) seal() error {
	if l.live.lines == 0 {
		return nil
	}
	dropped, kept := l.dropped, l.segs
	if len(kept) >= l.most {
		if kept[0].State != StatePruned {
			return fmt.Errorf("%w: %d sealed segments; prune some", ErrFull, l.most)
		}
		dropped, kept = dropped+1, kept[1:]
	}
	// The manifest names the file with the counts the log holds, so a file
	// changed under it fails the log before a manifest is written.
	if err := l.file.Check(); err != nil {
		return l.fail(err)
	}
	s := l.liveSegment()
	s.State, s.File, s.SealedAt = StateSealed, segmentFile(s.Seq), l.now()
	next := append(slices.Clone(kept), s)
	if err := l.writeManifest(dropped, next); err != nil {
		return err
	}
	err := l.file.Close()
	l.file = nil
	if err != nil {
		return l.fail(err)
	}
	if err := l.ops.rename(l.root, LiveName, s.File); err != nil {
		return l.fail(err)
	}
	if err := l.ops.sync(l.root); err != nil {
		return l.fail(err)
	}
	l.dropped, l.segs, l.live = dropped, next, stats{}
	return nil
}

// Prune prunes the sealed segments through the one numbered through. Each
// one's tombstone is in the manifest before its file is unlinked. A prefix
// already pruned, its tombstones dropped or not, is pruned again as nothing.
// A clock before a seal it would prune, and a file that no longer holds what
// the manifest names it with, are refused with nothing changed.
func (l *segments) Prune(through int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.usable(); err != nil {
		return err
	}
	last := l.dropped + len(l.segs)
	if through < 1 || through > last {
		return fmt.Errorf("%w: segment %d, and %d are sealed or pruned; the live one is %d",
			ErrPrune, through, last, last+1)
	}
	next := slices.Clone(l.segs)
	at := l.now()
	if err := sealedBy(next[:max(through-l.dropped, 0)], at); err != nil {
		return err
	}
	gone, err := l.tombstone(next[:max(through-l.dropped, 0)], at)
	if err != nil || len(gone) == 0 {
		return err
	}
	defer closeRead(gone)
	if err := l.writeManifest(l.dropped, next); err != nil {
		return err
	}
	for _, file := range gone {
		if err := l.removeRead(file); err != nil {
			return l.fail(err)
		}
	}
	if err := l.ops.sync(l.root); err != nil {
		return l.fail(err)
	}
	l.segs = next
	return nil
}

// readFile is a segment's file as a prune read it, held open until the
// prune has unlinked its name or left it.
type readFile struct {
	name string
	file *os.File
	info fs.FileInfo
}

// tombstone names each sealed segment of segs pruned at at, once its file
// is read again and holds what the manifest names it with, and returns the
// files to unlink, still open.
func (l *segments) tombstone(segs []Segment, at time.Time) ([]readFile, error) {
	var gone []readFile
	for i := range segs {
		if segs[i].State != StateSealed {
			continue
		}
		f, info, err := l.verified(segs[i], nil)
		if err != nil {
			closeRead(gone)
			return nil, err
		}
		gone = append(gone, readFile{name: segs[i].File, file: f, info: info})
		segs[i].State, segs[i].PrunedAt, segs[i].File = StatePruned, at, ""
	}
	return gone, nil
}

// closeRead closes the files a prune read. They were opened only to read,
// so a close that fails loses nothing the prune wrote.
func closeRead(files []readFile) {
	for _, f := range files {
		_ = f.file.Close()
	}
}

// removeRead unlinks file's name only while it still names the file the
// prune read. That file is held open, so no file put at the name since can
// carry its inode number. Between this check and the unlink another file
// can still be put at the name: no POSIX call unlinks a name only if it
// names one file.
func (l *segments) removeRead(file readFile) error {
	now, err := l.root.Lstat(file.name)
	switch {
	case err != nil:
		return err
	case !os.SameFile(now, file.info):
		return fmt.Errorf("%w: another file stands at %s since the prune read it, and is left", ErrMoved, file.name)
	}
	return l.ops.remove(l.root, file.name)
}

// sealedBy refuses a clock at before the seal of a sealed segment of segs:
// the manifest reader refuses a prune dated before its segment's seal.
func sealedBy(segs []Segment, at time.Time) error {
	for _, s := range segs {
		if s.State == StateSealed && at.Before(s.SealedAt) {
			return fmt.Errorf("%w: the clock reads %s, and segment %d was sealed at %s", ErrClock,
				at.Format(time.RFC3339), s.Seq, s.SealedAt.Format(time.RFC3339))
		}
	}
	return nil
}

// writeManifest replaces the manifest with one naming dropped and segs. A
// replace that fails with the manifest on disk still the one the log holds
// changed nothing, so its error is returned and the log goes on; any other
// failure fails the log, since the manifest may name what the log does not.
func (l *segments) writeManifest(dropped int, segs []Segment) error {
	body, err := encodeManifest(l.cfg.Tenant, l.cfg.Project, dropped, segs)
	if err != nil {
		return err
	}
	err = l.ops.replace(l.root, ManifestName, body)
	if err == nil {
		return nil
	}
	if l.manifestUnchanged() {
		return err
	}
	return l.fail(err)
}

// manifestUnchanged reports whether the manifest on disk is, byte for byte,
// the one naming what the log holds. The replace renames a whole file into
// place, so a failure before the rename leaves this one and a failure after
// it leaves the new one.
func (l *segments) manifestUnchanged() bool {
	held, err := encodeManifest(l.cfg.Tenant, l.cfg.Project, l.dropped, l.segs)
	if err != nil {
		return false
	}
	raw, ok, err := readManifest(l.root)
	return err == nil && ok && bytes.Equal(raw, held)
}

// now is the clock to the second, as the manifest spells a time.
func (l *segments) now() time.Time { return l.cfg.Now().UTC().Truncate(time.Second) }

func (l *segments) fail(err error) error {
	l.failed = fmt.Errorf("%w: %w", ErrFailed, err)
	return l.failed
}

// Locate answers for the segment key names.
func (l *segments) Locate(key Digest) SegmentAnswer {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.usable(); err != nil {
		return SegmentAnswer{cause: err.Error()}
	}
	return locate(l.segs, l.liveSegment(), key)
}

// Manifest is the log as it is now.
func (l *segments) Manifest() Manifest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.manifest()
}

// Close releases the live segment, the lock and the directory. A second
// Close does nothing.
func (l *segments) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.release()
}
