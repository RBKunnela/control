package segmentlog

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"

	"github.com/guardana/control/internal/files"
)

// fsOps are the steps a seal and a prune take on the directory, so a test
// can stop either after any one of them, as a crash would.
type fsOps struct {
	replace func(root *os.Root, name string, body []byte) error
	rename  func(root *os.Root, from, to string) error
	remove  func(root *os.Root, name string) error
	sync    func(root *os.Root) error
}

var osOps = fsOps{
	replace: func(root *os.Root, name string, body []byte) error { return files.ReplaceIn(root, name, body, 0o600) },
	rename:  (*os.Root).Rename,
	remove:  (*os.Root).Remove,
	sync:    syncRoot,
}

func syncRoot(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// segments is the default kind: the directory held under its lock file, the
// manifest as last written, and the live segment.
type segments struct {
	mu   sync.Mutex
	cfg  Config
	root *os.Root
	lock *os.File
	// dropped is how many segments before segs were pruned and their
	// tombstones dropped.
	dropped int
	segs    []Segment
	// live is the live segment's whole lines; file is its open file, nil
	// until the first append when no live segment was found.
	live   stats
	file   LiveFile
	failed error
	closed bool
	ops    fsOps
	// most is MaxSegments, the entries a seal keeps the manifest within; a
	// test lowers it to reach the bound with few segment files.
	most int
}

// check refuses a configuration no log opens with.
func (cfg Config) check() error {
	switch {
	case cfg.OpenLive == nil || cfg.Now == nil:
		return fmt.Errorf("%w: no live segment opener or no clock", ErrConfig)
	case cfg.MaxLineBytes < 1:
		return fmt.Errorf("%w: line bound %d", ErrConfig, cfg.MaxLineBytes)
	case cfg.SegmentBytes == 0 && cfg.MaxBytes == 0:
	case cfg.SegmentBytes < 1 || cfg.MaxBytes/2 < cfg.SegmentBytes:
		return fmt.Errorf("%w: a segment bound of %d and a log bound of %d; the log bound is at least twice the segment's",
			ErrConfig, cfg.SegmentBytes, cfg.MaxBytes)
	}
	if err := checkBinding(cfg.Tenant, cfg.Project); err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	return nil
}

func openSegments(cfg Config) (*segments, error) { return openWith(cfg, osOps) }

func openWith(cfg Config, ops fsOps) (*segments, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if !files.PermissionBits {
		return nil, ErrNoPermissionBits
	}
	root, err := openDir(cfg.Dir)
	if err != nil {
		return nil, err
	}
	l := &segments{cfg: cfg, root: root, ops: ops, most: MaxSegments}
	if err := l.claim(); err != nil {
		return nil, errors.Join(err, l.release())
	}
	return l, nil
}

// release closes what the log holds, writing nothing.
func (l *segments) release() error {
	var errs []error
	if l.file != nil {
		errs = append(errs, l.file.Close())
		l.file = nil
	}
	if l.lock != nil {
		errs = append(errs, l.lock.Close())
		l.lock = nil
	}
	if l.root != nil {
		errs = append(errs, l.root.Close())
		l.root = nil
	}
	return errors.Join(errs...)
}

// found is what a directory holds besides its lock file.
type found struct {
	manifest, live bool
	sealed         map[int]bool
}

// claim locks the directory, reads its names and its manifest, completes a
// seal or a prune a crash left part way, checks every segment against the
// manifest, and opens the live segment.
func (l *segments) claim() error {
	var err error
	if l.lock, err = openJudged(l.root, LockName, os.O_RDWR|os.O_CREATE); err != nil {
		return err
	}
	if err := Lock(l.lock); err != nil {
		return err
	}
	have, err := l.survey()
	if err != nil {
		return err
	}
	if err := l.loadManifest(have); err != nil {
		return err
	}
	if err := l.completePrunes(have); err != nil {
		return err
	}
	if err := l.completeSeal(&have); err != nil {
		return err
	}
	for _, s := range l.segs {
		if s.State == StateSealed {
			if err := l.verify(s, l.cfg.Visit); err != nil {
				return err
			}
		}
	}
	return l.openLive(have)
}

// survey sorts the directory's names. A temporary file is what a crash left
// of a manifest being written, and is removed; any name no writer of this
// package leaves is refused.
func (l *segments) survey() (found, error) {
	all, err := names(l.root)
	if err != nil {
		return found{}, err
	}
	have := found{sealed: map[int]bool{}}
	for _, name := range all {
		seq, sealed := segmentSeq(name)
		switch {
		case name == LockName:
		case name == ManifestName:
			have.manifest = true
		case name == LiveName:
			have.live = true
		case sealed:
			have.sealed[seq] = true
		case files.IsTemp(name):
			if err := l.root.Remove(name); err != nil {
				return found{}, fmt.Errorf("removing a manifest a crash left part written: %w", err)
			}
		default:
			return found{}, fmt.Errorf("%w: %q is no name a writer of this log leaves", ErrDirectory, name)
		}
	}
	return have, nil
}

// loadManifest reads the manifest, or writes the first one to a directory
// that holds no segment, and refuses a log bound to another tenant or
// project.
func (l *segments) loadManifest(have found) error {
	if !have.manifest {
		if have.live || len(have.sealed) > 0 {
			return fmt.Errorf("%w: the directory holds segments and no manifest names them", ErrManifest)
		}
		body, err := encodeManifest(l.cfg.Tenant, l.cfg.Project, 0, nil)
		if err != nil {
			return err
		}
		return l.ops.replace(l.root, ManifestName, body)
	}
	raw, _, err := readManifest(l.root)
	if err != nil {
		return err
	}
	m, err := decodeManifest(raw)
	if err != nil {
		return err
	}
	if m.tenant != l.cfg.Tenant || m.project != l.cfg.Project {
		return fmt.Errorf("%w: it is bound to tenant %q and project %q", ErrBinding, m.tenant, m.project)
	}
	for seq := range have.sealed {
		if seq <= m.dropped || seq > m.dropped+len(m.segs) {
			return fmt.Errorf("%w: it does not name %s", ErrManifest, segmentFile(seq))
		}
	}
	l.dropped, l.segs = m.dropped, m.segs
	return nil
}

// completePrunes unlinks each pruned segment a crash left after its
// tombstone, once its file is the one the tombstone names.
func (l *segments) completePrunes(have found) error {
	removed := false
	for _, s := range l.segs {
		if s.State != StatePruned || !have.sealed[s.Seq] {
			continue
		}
		if err := l.verify(Segment{Seq: s.Seq, State: StateSealed, Lines: s.Lines, Bytes: s.Bytes, First: s.First,
			Last: s.Last, File: segmentFile(s.Seq)}, nil); err != nil {
			return err
		}
		if err := l.ops.remove(l.root, segmentFile(s.Seq)); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return l.ops.sync(l.root)
	}
	return nil
}

// completeSeal renames the live segment to the last sealed one when a crash
// left the manifest naming it and the file still live. Any other sealed
// segment without its file is refused.
func (l *segments) completeSeal(have *found) error {
	for i, s := range l.segs {
		if s.State != StateSealed || have.sealed[s.Seq] {
			continue
		}
		if i != len(l.segs)-1 || !have.live {
			return fmt.Errorf("%w: %s is named sealed and is not there", ErrManifest, s.File)
		}
		st, err := l.scanFile(LiveName, nil)
		if err != nil {
			return err
		}
		if !st.matches(s) {
			return fmt.Errorf("%w: %s is named sealed and the live segment is not what it names", ErrManifest, s.File)
		}
		if err := l.ops.rename(l.root, LiveName, s.File); err != nil {
			return err
		}
		have.live = false
		if err := l.ops.sync(l.root); err != nil {
			return err
		}
	}
	return nil
}

// verify reads a sealed segment whole and refuses it unless it holds what
// the manifest names it with, handing each line to the visitor.
func (l *segments) verify(s Segment, visit func([]byte) error) error {
	st, err := l.scanFile(s.File, visit)
	if err != nil {
		return fmt.Errorf("%s: %w", s.File, err)
	}
	if !st.matches(s) {
		return fmt.Errorf("%w: %s does not hold what the manifest names it with", ErrManifest, s.File)
	}
	return nil
}

func (l *segments) scanFile(name string, visit func([]byte) error) (stats, error) {
	f, err := openJudged(l.root, name, os.O_RDONLY)
	if err != nil {
		return stats{}, err
	}
	st, err := scan(f, l.cfg.MaxLineBytes, visit)
	return st, errors.Join(err, f.Close())
}

// openLive opens a live segment the directory holds, through the consumer,
// which cuts what a crash left of its last line, then reads its lines.
func (l *segments) openLive(have found) error {
	if !have.live {
		return nil
	}
	f, err := l.cfg.OpenLive(l.root, LiveName)
	if err != nil {
		return fmt.Errorf("%s: %w", LiveName, err)
	}
	l.file = f
	st, err := l.scanFile(LiveName, l.cfg.Visit)
	if err != nil {
		return fmt.Errorf("%s: %w", LiveName, err)
	}
	if st.tail != 0 {
		return fmt.Errorf("%w: %s ends in %d bytes after its last newline once opened", ErrManifest, LiveName, st.tail)
	}
	l.live = st
	return nil
}

// retained is the bytes of every segment not pruned.
func (l *segments) retained() int64 {
	n := l.live.bytes
	for _, s := range l.segs {
		if s.State == StateSealed {
			n += s.Bytes
		}
	}
	return n
}

// liveSegment is the live segment as the manifest view shows it.
func (l *segments) liveSegment() Segment {
	s := l.live.segment(StateLive)
	s.Seq, s.File = l.dropped+len(l.segs)+1, LiveName
	return s
}

// manifest is the log now.
func (l *segments) manifest() Manifest {
	return Manifest{Tenant: l.cfg.Tenant, Project: l.cfg.Project, Dropped: l.dropped, Segments: slices.Clone(l.segs),
		Live: l.liveSegment(), Retained: l.retained()}
}
