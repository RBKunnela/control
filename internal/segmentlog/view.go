package segmentlog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
)

// View is a log as a reader finds it, holding no lock and writing nothing: the
// manifest, and the live segment's whole lines when it was read. A writer may
// seal or prune while a view is held; Open notices a segment that moved.
type View struct {
	dir          string
	maxLineBytes int
	tenant       string
	project      string
	dropped      int
	segs         []Segment
	live         stats
}

// Inspect reads the log in dir as it is: a manifest is required, and a live
// segment is read to its last newline. Nothing is created, cut or removed.
func Inspect(dir string, maxLineBytes int) (*View, error) {
	if maxLineBytes < 1 {
		return nil, fmt.Errorf("%w: line bound %d", ErrConfig, maxLineBytes)
	}
	root, err := os.OpenRoot(dir + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	raw, ok, err := readManifest(root)
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, fmt.Errorf("%w: %s holds no %s, so it is no segment log", ErrManifest, dir, ManifestName)
	}
	m, err := decodeManifest(raw)
	if err != nil {
		return nil, err
	}
	v := &View{dir: dir, maxLineBytes: maxLineBytes, tenant: m.tenant, project: m.project, dropped: m.dropped, segs: m.segs}
	f, err := openRead(root, LiveName)
	if errors.Is(err, fs.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if v.live, err = scan(f, maxLineBytes, nil); err != nil {
		return nil, fmt.Errorf("%s: %w", LiveName, err)
	}
	return v, nil
}

// sealPending refuses, as moved, the live file of a view read after a seal
// named the live segment sealed and before it renamed the file: the newest
// sealed segment has no file, and the live file begins with that segment's
// first line, or the file opened is that segment's now. Only an open of the
// live file is refused, so a reader of the manifest alone, and the writer
// that completes the seal, still read it.
func (v *View) sealPending(root *os.Root, f *os.File) error {
	if len(v.segs) == 0 || v.live.lines == 0 {
		return nil
	}
	s := v.segs[len(v.segs)-1]
	if s.State != StateSealed || v.live.first != s.First {
		return nil
	}
	at, err := root.Lstat(s.File)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: segment %d is sealed and its file not yet renamed", ErrMoved, s.Seq)
	case err != nil:
		return err
	}
	held, err := f.Stat()
	switch {
	case err != nil:
		return err
	case os.SameFile(held, at):
		return fmt.Errorf("%w: the live file opened was renamed segment %d", ErrMoved, s.Seq)
	}
	return nil
}

// openRead opens name in root to read it, refusing anything but a regular
// file, a link at the name included, without waiting on a named pipe.
func openRead(root *os.Root, name string) (*os.File, error) {
	before, err := root.Lstat(name)
	switch {
	case err != nil:
		return nil, err
	case !before.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrDirectory, name)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return nil, err
	}
	if after, err := f.Stat(); err != nil || !os.SameFile(before, after) {
		return nil, errors.Join(fmt.Errorf("%w: %s", ErrMoved, name), err, f.Close())
	}
	return f, nil
}

func (v *View) liveSegment() Segment {
	s := v.live.segment(StateLive)
	s.Seq, s.File = v.dropped+len(v.segs)+1, LiveName
	return s
}

// Manifest is the log as the view found it.
func (v *View) Manifest() Manifest {
	m := Manifest{Tenant: v.tenant, Project: v.project, Dropped: v.dropped, Segments: slices.Clone(v.segs),
		Live: v.liveSegment(), Retained: v.live.bytes}
	for _, s := range v.segs {
		if s.State == StateSealed {
			m.Retained += s.Bytes
		}
	}
	return m
}

// Tail is the bytes after the live segment's last newline when it was read.
func (v *View) Tail() int64 { return v.live.tail }

// Locate answers for the segment key names.
func (v *View) Locate(key Digest) SegmentAnswer {
	return locate(v.segs, v.liveSegment(), key)
}

// After is the segment that follows seq, sealed or live; Unknown when there is
// none, and Pruned when it was pruned.
func (v *View) After(seq int) SegmentAnswer {
	i := seq - v.dropped
	switch {
	case i < 0:
		return SegmentAnswer{cause: fmt.Sprintf("segment %d was dropped", seq)}
	case i < len(v.segs):
		s := v.segs[i]
		return SegmentAnswer{state: s.State, seg: s}
	case i == len(v.segs):
		return SegmentAnswer{state: StateLive, seg: v.liveSegment()}
	default:
		return SegmentAnswer{cause: fmt.Sprintf("no segment follows %d", seq)}
	}
}

// First is the first segment not pruned: the first sealed one, or the live
// one when every sealed one was pruned.
func (v *View) First() SegmentAnswer {
	for _, s := range v.segs {
		if s.State == StateSealed {
			return SegmentAnswer{state: StateSealed, seg: s}
		}
	}
	return SegmentAnswer{state: StateLive, seg: v.liveSegment()}
}

// Open opens the file of a sealed or the live segment s and returns it with
// the length a reader takes. A sealed segment is read whole first and refused
// unless it holds what the manifest names it with. A live segment that no
// longer begins with the line it began with when the view was read, or whose
// manifest, read again once the file is open, names a segment the view did
// not, was sealed since, and is ErrMoved; so is one a seal named sealed and
// has not yet renamed, and a sealed segment pruned since.
func (v *View) Open(s Segment) (*os.File, int64, error) {
	if s.State != StateSealed && s.State != StateLive {
		return nil, 0, fmt.Errorf("%w: segment %d is %s", ErrPrune, s.Seq, s.State)
	}
	root, err := os.OpenRoot(v.dir + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = root.Close() }()
	f, err := openRead(root, s.File)
	if errors.Is(err, fs.ErrNotExist) {
		if s.State == StateLive {
			if moved := v.stillLive(root); moved != nil {
				return nil, 0, moved
			}
		}
		return nil, 0, fmt.Errorf("%w: %s: %w", ErrMoved, s.File, err)
	}
	if err != nil {
		return nil, 0, err
	}
	size, err := v.check(f, s)
	if err == nil && s.State == StateLive {
		err = errors.Join(v.stillLive(root), v.sealPending(root, f))
	}
	if err != nil {
		return nil, 0, errors.Join(err, f.Close())
	}
	return f, size, nil
}

// stillLive refuses, as moved, a manifest that names more segments than the
// view's. A seal names the live segment in the manifest before it renames the
// file, so a live file opened while the manifest still names no more is the
// view's live segment.
func (v *View) stillLive(root *os.Root) error {
	raw, ok, err := readManifest(root)
	switch {
	case err != nil:
		return err
	case !ok:
		return fmt.Errorf("%w: %s is gone", ErrMoved, ManifestName)
	}
	m, err := decodeManifest(raw)
	if err != nil {
		return err
	}
	if m.dropped+len(m.segs) != v.dropped+len(v.segs) {
		return fmt.Errorf("%w: a segment was sealed since the view was read", ErrMoved)
	}
	return nil
}

// check reads what it must of the open file of s to know it is s.
func (v *View) check(f *os.File, s Segment) (int64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	st, err := scan(f, v.maxLineBytes, nil)
	switch {
	case err != nil:
		return 0, fmt.Errorf("%s: %w", s.File, err)
	case s.State == StateSealed && !st.matches(s):
		return 0, fmt.Errorf("%w: %s does not hold what the manifest names it with", ErrManifest, s.File)
	case s.State == StateLive && s.Lines > 0 && (st.lines == 0 || st.first != s.First):
		return 0, fmt.Errorf("%w: %s no longer begins with the line it began with", ErrMoved, s.File)
	}
	return info.Size(), nil
}

// Held reports whether a writer holds the log's directory.
func (v *View) Held() (bool, error) {
	root, err := os.OpenRoot(v.dir + string(os.PathSeparator) + ".")
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	f, err := openRead(root, LockName)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	return HeldByWriter(f)
}
