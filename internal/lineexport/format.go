package lineexport

import (
	"fmt"
	"slices"
)

// Error is a refusal by this package, matched with errors.Is.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// ErrInvalid is a format, a query, a source or a verdict no export can be
// written from. A format checks its own query first, with its own refusals.
const ErrInvalid Error = "lineexport: the export cannot be written as asked"

// Record types and gap reasons this package writes whatever the format.
const (
	Gap            = "gap"
	Duplicate      = "duplicate"
	GapTooLong     = "too_long"
	GapPartialTail = "partial_tail"
)

// Refusals are the errors an export wraps, so a format refuses with its own
// errors and texts. Every one is required.
type Refusals struct {
	// CursorMalformed is a cursor not spelled v1:<first>:<offset>:<line>.
	CursorMalformed error
	// CursorOtherFile is a cursor whose first line is not this file's.
	CursorOtherFile error
	// CursorPastEnd is a cursor past where the export ends: the last
	// newline, or the end of the last committed write.
	CursorPastEnd error
	// CursorOffLine is a cursor whose offset does not follow a newline.
	CursorOffLine error
	// CursorChanged is a cursor whose line is not the line ending there.
	CursorChanged error
	// ShortRead is a file that no longer holds what it held when the export
	// opened it.
	ShortRead error
	// ByteBound is a next line longer than the byte bound, which no export
	// under that bound can pass.
	ByteBound error
}

// Format is what one export format names and bounds.
type Format struct {
	// Name and Version are the header's format and version.
	Name, Version string
	// Lines are the types of the records that carry a line, in the order the
	// trailer counts them. Such a record carries the line under a member
	// named as its type.
	Lines []string
	// IDMember names the id a duplicate record carries.
	IDMember string
	// Conflict is the gap reason for a line whose id this export read
	// earlier with other content.
	Conflict string
	// MaxLineBytes bounds a line before its newline; a longer one is a gap.
	MaxLineBytes int
	Refusals     Refusals
}

// reserved are the names a record type or the duplicate's id member may not
// take: the other record types, and the members a record already has.
var reserved = []string{"header", "trailer", Gap, Duplicate, "type", "offset", "cursor", "first_offset"}

// check refuses a format whose records could not be written as one JSON
// object each with one member per name, or that wraps no error of its own.
func (f Format) check() error {
	switch {
	case f.Name == "" || f.Version == "" || f.Conflict == "" || f.MaxLineBytes < 1:
		return fmt.Errorf("%w: a format needs a name, a version, a conflict reason and a line bound", ErrInvalid)
	case !f.Refusals.complete():
		return fmt.Errorf("%w: a format names every refusal", ErrInvalid)
	case len(f.Lines) == 0:
		return fmt.Errorf("%w: a format names a record type that carries a line", ErrInvalid)
	}
	return f.names()
}

// names refuses a name JSON would escape, one a record already uses for
// something else, and a record type named twice.
func (f Format) names() error {
	if !plainName(f.IDMember) || slices.Contains(reserved, f.IDMember) {
		return fmt.Errorf("%w: %q cannot name the id member", ErrInvalid, f.IDMember)
	}
	for i, t := range f.Lines {
		if !plainName(t) || slices.Contains(reserved, t) || slices.Contains(f.Lines[:i], t) {
			return fmt.Errorf("%w: %q cannot name a record type", ErrInvalid, t)
		}
	}
	return nil
}

func (r Refusals) complete() bool {
	return r.CursorMalformed != nil && r.CursorOtherFile != nil && r.CursorPastEnd != nil && r.CursorOffLine != nil &&
		r.CursorChanged != nil && r.ShortRead != nil && r.ByteBound != nil
}

// plainName is a name JSON spells as it stands: a lowercase letter, then
// lowercase letters and underscores.
func plainName(s string) bool {
	for i, r := range s {
		if (r < 'a' || r > 'z') && (r != '_' || i == 0) {
			return false
		}
	}
	return s != ""
}

func (f Format) carries(t string) bool { return slices.Contains(f.Lines, t) }

// zeroCounts is a count for every record type, each zero.
func (f Format) zeroCounts() map[string]int {
	c := map[string]int{Gap: 0, Duplicate: 0}
	for _, t := range f.Lines {
		c[t] = 0
	}
	return c
}
