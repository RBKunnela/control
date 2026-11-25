package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// header is what the header says about where the export came from and what
// it was asked for.
type header struct {
	source, after string
	// filtered is a query that names any filter, which cuts the links
	// between a request's events.
	filtered bool
	// splits is a query that names a filter other than requests: one that
	// may leave out some of a request's events and keep the others.
	splits bool
	// prunedBefore counts the segments of a log before the exported one that
	// are gone.
	prunedBefore uint64
}

// wholeRequestMembers are the query members that never leave out part of a
// request: a request filter selects whole requests.
var wholeRequestMembers = map[string]bool{"after": true, "limit": true, "max_bytes": true, "request": true}

// splitsRequests reports whether the header's query states a member that is
// not one of wholeRequestMembers, whatever its value, null or empty included.
func splitsRequests(b []byte) bool {
	var h struct {
		Query map[string]json.RawMessage `json:"query"`
	}
	if json.Unmarshal(b, &h) != nil {
		return true
	}
	for name := range h.Query {
		if !wholeRequestMembers[name] {
			return true
		}
	}
	return false
}

func checkHeader(l rawLine) (header, error) {
	if l.tooLong || l.unterminated {
		return header{}, errors.New("the first record is not a whole header")
	}
	if err := strictHeader(l.b); err != nil {
		return header{}, err
	}
	var h struct {
		Type    string          `json:"type"`
		Format  *string         `json:"format"`
		Version *string         `json:"version"`
		File    *string         `json:"file"`
		Source  json.RawMessage `json:"source"`
		// PrunedBefore, from 1.1, counts the segments of a log before the
		// exported one that are gone; a 1.0 header has none.
		PrunedBefore json.RawMessage `json:"pruned_before"`
		Query        *headerQuery    `json:"query"`
	}
	if err := json.Unmarshal(l.b, &h); err != nil {
		return header{}, errors.New("the first record is not a header: a member is of another type")
	}
	switch {
	case h.Type != "header":
		return header{}, errors.New("the first record is not the header")
	case h.Format == nil || *h.Format != exportFormat:
		return header{}, fmt.Errorf("the header names another format than %s, which this reader reads", exportFormat)
	}
	minor, err := minorOf(h.Version)
	if err != nil {
		return header{}, err
	}
	source, err := sourceOf(h.Source)
	if err != nil {
		return header{}, err
	}
	pruned, err := prunedOf(h.PrunedBefore, minor)
	if err != nil {
		return header{}, err
	}
	facts := h.Query.facts(source)
	facts.splits = splitsRequests(l.b)
	facts.prunedBefore = pruned
	return facts, nil
}

// minorOf reads the header's version, refused unless it is MAJOR.MINOR of the
// major this reader reads, and returns its minor.
func minorOf(version *string) (uint64, error) {
	if version == nil {
		return 0, errors.New("the header names no version")
	}
	major, minor, ok := versionOf(*version)
	switch {
	case !ok:
		return 0, errors.New("the header's version is not MAJOR.MINOR")
	case major != exportMajor:
		return 0, fmt.Errorf("the header's version is of major %d, and this reader reads major %d", major, exportMajor)
	}
	return minor, nil
}

// prunedOf reads the header's pruned_before, a count. A header of minor 0
// has none, which is 0; a writer of a later minor always names it, so a
// header of one without it is refused rather than read as the most trusting
// count.
func prunedOf(raw json.RawMessage, minor uint64) (uint64, error) {
	if raw == nil {
		if minor > 0 {
			return 0, errors.New("the header names no pruned_before, which every header of minor 1 or later names")
		}
		return 0, nil
	}
	var n uint64
	if string(raw) == "null" || json.Unmarshal(raw, &n) != nil {
		return 0, errors.New("the header's pruned_before is not a count")
	}
	return n, nil
}

// prunedGap reports whether the export begins a reading of a log with
// segments before it gone. One naming no cursor follows nothing that read
// them; one after a state's cursor follows segments the state read before
// they were pruned, and a cursor into a pruned segment is refused as expired.
func (h header) prunedGap() bool { return h.after == "" && h.prunedBefore > 0 }

// sourceOf reads the header's source: the SHA-256 of the file's first line,
// or for a segment of a log its key, absent while the file holds no whole
// line.
func sourceOf(raw json.RawMessage) (string, error) {
	if raw == nil {
		return "", nil
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || !isSum(s) {
		return "", errors.New("the header's source is not the SHA-256 of a first line in 64 lowercase hex digits")
	}
	return s, nil
}

type headerQuery struct {
	After                               *string
	Limit                               *int
	MaxBytes                            *int64 `json:"max_bytes"`
	Request, Run, Tenant, Project, Kind []string
}

// facts is what a state follows of the header: the file's identity, the
// cursor the export starts after, and whether it names a filter.
func (q *headerQuery) facts(source string) header {
	h := header{source: source}
	if q != nil {
		if q.After != nil {
			h.after = *q.After
		}
		h.filtered = q.Request != nil || q.Run != nil || q.Tenant != nil || q.Project != nil || q.Kind != nil
	}
	return h
}

// majorOf reads MAJOR.MINOR as the wire contracts spell a version: two
// unsigned decimals. A higher minor is read like its major.
func majorOf(version string) (uint64, bool) {
	major, _, ok := versionOf(version)
	return major, ok
}

// versionOf reads a "major.minor" version as two numbers. The major is
// spelled as its number alone, as the contracts compare it: 01.0 is no
// version of major 1.
func versionOf(version string) (major, minor uint64, ok bool) {
	a, b, ok := strings.Cut(version, ".")
	major, errMajor := strconv.ParseUint(a, 10, 32)
	minor, errMinor := strconv.ParseUint(b, 10, 32)
	return major, minor, ok && errMajor == nil && errMinor == nil && strconv.FormatUint(major, 10) == a
}

type trailerRecord struct {
	NextCursor   *string `json:"next_cursor"`
	EndReached   *bool   `json:"end_reached"`
	TailBytes    *int64  `json:"tail_bytes"`
	WriterHeld   *bool   `json:"writer_held"`
	ScannedBytes *int64  `json:"scanned_bytes"`
	DedupScope   *string `json:"dedup_scope"`
	Counts       *struct {
		Event     *int `json:"event"`
		Gap       *int `json:"gap"`
		Duplicate *int `json:"duplicate"`
	} `json:"counts"`
}

func (x *export) readTrailer(b []byte, ms []member) {
	if counts, ok := valueOf(ms, "counts"); ok {
		if err := strictObject(counts, countMembers); err != nil {
			x.refuse("a trailer whose counts the contract does not give: " + err.Error())
			return
		}
	}
	var r trailerRecord
	if err := json.Unmarshal(b, &r); err != nil {
		x.refuse("a trailer whose members are of another type")
		return
	}
	if why := trailerDefect(r); why != "" {
		x.refuse(why)
		return
	}
	if why := x.countsDefect(r); why != "" {
		x.refuse(why)
		return
	}
	x.trailer = &trailerState{endReached: *r.EndReached, tailBytes: *r.TailBytes, writerHeld: *r.WriterHeld}
	if r.NextCursor != nil {
		x.trailer.nextCursor = *r.NextCursor
	}
}

// trailerDefect names what keeps a trailer from saying where the export
// stopped and what follows it.
func trailerDefect(r trailerRecord) string {
	switch {
	case r.EndReached == nil:
		return "a trailer without end_reached"
	case r.TailBytes == nil:
		return "a trailer without a tail_bytes count"
	case *r.TailBytes < 0:
		return fmt.Sprintf("a trailer whose tail_bytes is %d", *r.TailBytes)
	case r.WriterHeld == nil:
		return "a trailer without writer_held"
	case r.NextCursor != nil && !isCursor(*r.NextCursor):
		return "a trailer whose next_cursor is not a v1 cursor"
	case !*r.EndReached && r.NextCursor == nil:
		return "a trailer that stops before the file's end and names no next_cursor"
	}
	return scanDefect(r)
}

// scanDefect names what keeps a trailer from saying how much of the file it
// read and that it compared duplicates within this export only.
func scanDefect(r trailerRecord) string {
	switch {
	case r.ScannedBytes == nil:
		return "a trailer without a scanned_bytes count"
	case *r.ScannedBytes < 0:
		return fmt.Sprintf("a trailer whose scanned_bytes is %d", *r.ScannedBytes)
	case r.DedupScope == nil:
		return "a trailer without dedup_scope"
	case *r.DedupScope != "export":
		return `a trailer whose dedup_scope is not "export"`
	}
	return ""
}

// countsDefect names trailer counts that are missing or not the records read.
func (x *export) countsDefect(r trailerRecord) string {
	c := r.Counts
	switch {
	case c == nil || c.Event == nil || c.Gap == nil || c.Duplicate == nil:
		return "a trailer without its counts"
	case *c.Event != x.seenEvents || *c.Gap != x.seenGaps || *c.Duplicate != x.seenDuplicates:
		return fmt.Sprintf("the trailer counts %d event, %d gap and %d duplicate record(s), and the export held %d, %d and %d",
			*c.Event, *c.Gap, *c.Duplicate, x.seenEvents, x.seenGaps, x.seenDuplicates)
	}
	return ""
}
