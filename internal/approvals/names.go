package approvals

import (
	"fmt"
	"strings"
)

// state is how far a record has travelled: held by the plane, then answered
// by an approver. The order is total, and it is what resolves a crash between
// linking the answered name and unlinking the held one: a reader takes the
// furthest-along name present. What became of an answer after that is not the
// directory's to say: the plane keeps it in its own ledger.
type state uint8

const (
	stateHeld state = iota
	stateAnswered
)

// byRank holds the states furthest along first, which is the order a reader
// probes the names in.
var byRank = [...]state{stateAnswered, stateHeld}

// suffix is the file name a record in this state takes after its approval id.
// The rank leads the word so that the order is legible in a directory listing
// and in a refusal.
func (s state) suffix() string {
	switch s {
	case stateHeld:
		return ".0-held.rec"
	case stateAnswered:
		return ".1-answered.rec"
	}
	return ""
}

// String names the state in a refusal.
func (s state) String() string {
	if name := strings.TrimSuffix(s.suffix(), ".rec"); name != "" {
		return name[3:]
	}
	return fmt.Sprintf("state(%d)", uint8(s))
}

const (
	// markerFile says the directory is an approvals store. A directory that
	// is not empty and does not hold it is refused rather than read as empty.
	markerFile = "store.meta"
	// viewSuffix names the projection beside a record.
	viewSuffix = ".view.json"
	// tmpPrefix and tmpSuffix bracket a file a writer has not linked into
	// place yet. No record name can look like one: a record's suffix follows
	// its approval id and is never ".part".
	tmpPrefix = "tmp."
	tmpSuffix = ".part"
)

// MaxApprovalIDBytes bounds an approval id, which is also a file name.
const MaxApprovalIDBytes = 128

// kind is what a name under the directory is.
type kind uint8

const (
	kindForeign kind = iota
	kindMarker
	kindTemp
	kindRecord
	kindView
)

// classify says what a directory entry is, and for a record or a projection
// the approval id and the state it names. A name this package did not write is
// kindForeign, which the caller refuses: the store owns its directory and does
// not guess what else is in it.
func classify(name string) (kind, string, state) {
	switch {
	case name == markerFile:
		return kindMarker, "", 0
	case strings.HasPrefix(name, tmpPrefix) && strings.HasSuffix(name, tmpSuffix):
		return kindTemp, "", 0
	}
	for _, s := range byRank {
		if id, ok := strings.CutSuffix(name, s.suffix()); ok && checkApprovalID(id) == nil {
			return kindRecord, id, s
		}
	}
	if id, ok := strings.CutSuffix(name, viewSuffix); ok && checkApprovalID(id) == nil {
		return kindView, id, 0
	}
	return kindForeign, "", 0
}

// CheckApprovalID refuses, with ErrRecordName, an approval id no record of
// this store can be filed under, as Answer refuses it.
func CheckApprovalID(id string) error { return checkApprovalID(id) }

// checkApprovalID holds an approval id to what may name a file here: ASCII
// letters, digits, "_" and "-", beginning with a letter or a digit. The rule
// is deliberately narrower than the contract's identifier rule, because this
// value becomes a path element: no separator, no ".." and no leading dot can
// pass it, so no record can be written outside the directory or hide from a
// listing.
func checkApprovalID(id string) error {
	if id == "" || len(id) > MaxApprovalIDBytes {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrRecordName, len(id), MaxApprovalIDBytes)
	}
	for i := range len(id) {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case (c == '_' || c == '-') && i > 0:
		default:
			return fmt.Errorf("%w: byte %d is %q", ErrRecordName, i, c)
		}
	}
	return nil
}
