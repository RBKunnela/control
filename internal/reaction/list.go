package reaction

import (
	"crypto/sha256"
	"maps"
	"slices"
	"time"
)

// Prefix is the part of a stop list a judge accepted: its length, its
// SHA-256 and the SHA-256 of its header line. The zero value accepts
// nothing. Only a judge makes another, and a later judge takes only a list
// that begins with it, so what a plane accepted never shrinks.
type Prefix struct {
	length int64
	sum    [sha256.Size]byte
	header [sha256.Size]byte
}

// Length is the prefix's length in bytes.
func (p Prefix) Length() int64 { return p.length }

// Sum is the prefix's SHA-256.
func (p Prefix) Sum() [sha256.Size]byte { return p.sum }

// Usage is how much of its bounds a stop list uses.
type Usage struct {
	Bytes, Lines int64
}

// Degraded reports whether the list is past nine tenths of either bound.
func (u Usage) Degraded() bool {
	return u.Bytes*10 > MaxListBytes*9 || u.Lines*10 > MaxListLines*9
}

// Entry is a stop that no lift ended, and the line that holds it.
type Entry struct {
	Line int64
	Stop
}

// List is a stop list a judge accepted whole, with what judging its lines
// learned, so JudgeFrom judges only the lines after it. Nothing writes a List
// once a judge returns it.
type List struct {
	header  Header
	signer  Signer
	prefix  Prefix
	usage   Usage
	entries []Entry
	seen    *seen
}

// Header is the list's header.
func (l List) Header() Header { return l.header }

// Signer is who signed a 2.0 or 3.0 list's header, and the zero Signer in a
// 1.0 list.
func (l List) Signer() Signer { return l.signer }

// Prefix is what the judge accepted, to hand the next judge.
func (l List) Prefix() Prefix { return l.prefix }

// Usage is how much of its bounds the accepted list uses.
func (l List) Usage() Usage { return l.usage }

// Entries is a copy of the stops no lift ended, in the order of their lines,
// expired ones among them.
func (l List) Entries() []Entry { return slices.Clone(l.entries) }

// Ends reports whether a lift of target through line through would end a
// stop of l.
func (l List) Ends(target Target, through int64) bool {
	return slices.ContainsFunc(l.entries, func(e Entry) bool { return endedBy(e, target, through) })
}

// endedBy reports whether a lift of target through line through ends e: a
// stop of a run is never ended by a lift of its agent, nor a stop of an agent
// by a lift of the run its finding was about.
func endedBy(e Entry, target Target, through int64) bool {
	return e.Target() == target && e.Line <= through
}

// Names reports whether a stop or covered line names findingID.
func (l List) Names(findingID string) bool { return l.seen != nil && l.seen.findings[findingID] }

// liftKey is one lift: the scope and subject it ends and its last line.
type liftKey struct {
	target Target
	line   int64
}

// seen is what the lines a judge accepted tell the judge of a later line.
type seen struct {
	stops    []Entry
	findings map[string]bool
	lifts    map[liftKey]bool
	// through is the last line a lift ended for each scope and subject.
	through map[Target]int64
	// latest is the latest created_at a line names, and latestLine its line:
	// a clock read behind it refuses the list, as judging every line would.
	latest     time.Time
	latestLine int64
	// vouched is the signed documents a judge of a signed list asks the
	// voucher about again: the header and one lift of each signer.
	vouched []vouchedDoc
}

// fork is a copy of s that a judge may add to without writing s.
func (s *seen) fork() seen {
	if s == nil {
		return seen{findings: map[string]bool{}, lifts: map[liftKey]bool{}, through: map[Target]int64{}}
	}
	return seen{
		stops: slices.Clip(s.stops), findings: maps.Clone(s.findings), lifts: maps.Clone(s.lifts),
		through: maps.Clone(s.through), latest: s.latest, latestLine: s.latestLine, vouched: slices.Clip(s.vouched),
	}
}
