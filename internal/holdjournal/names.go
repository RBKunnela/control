package holdjournal

import (
	"encoding/base32"
	"fmt"
	"io/fs"
	"strings"
)

// MaxRequestIDBytes bounds a request id, which becomes part of a file name.
// The encoded name is longer than the id, and the bound keeps it well inside
// what a file system takes.
const MaxRequestIDBytes = 128

const (
	// entrySuffix follows the encoded request id.
	entrySuffix = ".hold"
	// markerFile says the directory is a hold journal.
	markerFile = "journal.meta"
	// tmpPrefix and tmpSuffix bracket a file no writer has put in place yet.
	// No entry name can look like one: an encoded name holds no dot.
	tmpPrefix = "tmp."
	tmpSuffix = ".part"
)

// nameEncoding is what a request id travels through to become a file name. It
// is single-case, so two ids cannot collide on a case-insensitive file system,
// and it holds no separator, no dot and no leading dot, so no id can name a
// file outside the directory or hide from a listing.
var nameEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// encodeName is the file name of requestID. The id is never trusted to be a
// safe file name: it is encoded, decoded again, and refused unless it comes
// back identical, so nothing is ever filed under a name that reads back as
// another request.
func encodeName(requestID string) (string, error) {
	switch {
	case requestID == "":
		return "", fmt.Errorf("%w: the request id is empty", ErrRequestName)
	case len(requestID) > MaxRequestIDBytes:
		return "", fmt.Errorf("%w: %d bytes, limit %d", ErrRequestName, len(requestID), MaxRequestIDBytes)
	}
	name := nameEncoding.EncodeToString([]byte(requestID)) + entrySuffix
	back, ok := decodeName(name)
	if !ok || back != requestID {
		return "", fmt.Errorf("%w: %q does not come back from its name", ErrRequestName, cause(requestID))
	}
	return name, nil
}

// decodeName reads the request id back out of a file name. A name whose
// encoding is not the one this package writes is not an entry's, whatever it
// decodes to.
func decodeName(name string) (string, bool) {
	body, ok := strings.CutSuffix(name, entrySuffix)
	if !ok {
		return "", false
	}
	raw, err := nameEncoding.DecodeString(body)
	if err != nil || len(raw) == 0 || len(raw) > MaxRequestIDBytes {
		return "", false
	}
	if nameEncoding.EncodeToString(raw) != body {
		return "", false
	}
	return string(raw), true
}

// kind is what a name under the directory is.
type kind uint8

const (
	kindForeign kind = iota
	kindMarker
	kindTemp
	kindEntry
	// kindLedger is the ledger's directory, the one name in the journal's
	// directory that is not a regular file.
	kindLedger
)

// classify says what a directory entry is, and for an entry file the request
// id it names. A name this package did not write is kindForeign, which the
// caller refuses: the journal owns its directory and does not guess what else
// is in it.
func classify(name string) (kind, string) {
	switch {
	case name == markerFile:
		return kindMarker, ""
	case strings.HasPrefix(name, tmpPrefix) && strings.HasSuffix(name, tmpSuffix):
		return kindTemp, ""
	}
	if id, ok := decodeName(name); ok {
		return kindEntry, id
	}
	return kindForeign, ""
}

// classifyEntry says what one file of a directory listing is. Anything that is
// not a regular file is foreign whatever it is named: opening a named pipe, a
// device or a symlink to one waits for a writer that never comes, under the
// lock every other caller needs, so what a file is has to be settled from the
// listing and never from the name alone.
func classifyEntry(e fs.DirEntry) kind {
	if e.Name() == ledgerDir && e.Type().IsDir() {
		return kindLedger
	}
	if !e.Type().IsRegular() {
		return kindForeign
	}
	named, _ := classify(e.Name())
	return named
}

// maxCauseBytes bounds how much of another writer's bytes travel with a
// refusal that may end up in an operator's log.
const maxCauseBytes = 120

// cause bounds and neutralises text a refusal quotes: it comes from a file
// this process may not have written, and a refusal is read on a terminal.
func cause(s string) string {
	if len(s) > maxCauseBytes {
		s = s[:maxCauseBytes] + "..."
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
