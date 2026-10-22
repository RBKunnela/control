package lineexport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Digest is the SHA-256 of a line, its newline included.
type Digest = [sha256.Size]byte

// chunkBytes is how much a search for a newline reads at a time.
const chunkBytes = 64 << 10

// cursor names the end of one line of one file: the digest of the file's
// first line, the offset right after the line's newline and the digest of the
// line.
type cursor struct {
	First  Digest
	Offset int64
	Line   Digest
}

// String spells the cursor v1:<first>:<offset>:<line>.
func (c cursor) String() string {
	return "v1:" + hex.EncodeToString(c.First[:]) + ":" + strconv.FormatInt(c.Offset, 10) + ":" + hex.EncodeToString(c.Line[:])
}

// parseCursor reads a cursor in its one spelling: each digest 64 lowercase
// hex digits and the offset a decimal above zero with no sign or leading
// zero. Any other string is r.CursorMalformed.
func parseCursor(s string, r Refusals) (cursor, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 4 || parts[0] != "v1" {
		return cursor{}, r.CursorMalformed
	}
	var c cursor
	var ok bool
	if c.First, ok = parseSum(parts[1]); !ok {
		return cursor{}, r.CursorMalformed
	}
	if c.Line, ok = parseSum(parts[3]); !ok {
		return cursor{}, r.CursorMalformed
	}
	// A line ends at least one byte into the file, so zero is never an offset.
	digits := parts[2]
	if digits == "" || digits[0] < '1' || digits[0] > '9' {
		return cursor{}, r.CursorMalformed
	}
	offset, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return cursor{}, r.CursorMalformed
	}
	c.Offset = offset
	return c, nil
}

// parseSum reads 64 lowercase hex digits; hex.DecodeString alone would also
// take capitals, and one digest would have two spellings.
func parseSum(s string) (Digest, bool) {
	var out Digest
	if len(s) != 2*sha256.Size || strings.ContainsFunc(s, func(r rune) bool { return (r < '0' || r > '9') && (r < 'a' || r > 'f') }) {
		return out, false
	}
	if _, err := hex.Decode(out[:], []byte(s)); err != nil {
		return out, false
	}
	return out, true
}

// file is what an export reads, and the refusals its reads wrap.
type file struct {
	r  io.ReaderAt
	rf Refusals
}

// check refuses a cursor that does not name the end of a line the file holds
// before end, where the export ends. first is the file's first line's digest,
// absent when the file has no whole line.
func (f file) check(c cursor, end int64, first Digest, hasFirst bool) error {
	switch {
	case !hasFirst || c.First != first:
		return f.rf.CursorOtherFile
	case c.Offset > end:
		return fmt.Errorf("%w: offset %d, the export ends at %d", f.rf.CursorPastEnd, c.Offset, end)
	}
	var before [1]byte
	if err := f.readFull(before[:], c.Offset-1); err != nil {
		return err
	}
	if before[0] != '\n' {
		return fmt.Errorf("%w: offset %d", f.rf.CursorOffLine, c.Offset)
	}
	start, err := f.lastNewline(c.Offset - 1)
	if err != nil {
		return err
	}
	got, err := f.sumRange(start, c.Offset)
	if err != nil {
		return err
	}
	if got != c.Line {
		return fmt.Errorf("%w: offset %d", f.rf.CursorChanged, c.Offset)
	}
	return nil
}

// lastNewline is the offset right after the last newline in r's first limit
// bytes, 0 when there is none. It reads backwards a chunk at a time, so what
// it costs is the distance to that newline.
func (f file) lastNewline(limit int64) (int64, error) {
	buf := make([]byte, min(limit, chunkBytes))
	for at := limit; at > 0; {
		n := min(at, int64(len(buf)))
		chunk := buf[:n]
		if err := f.readFull(chunk, at-n); err != nil {
			return 0, err
		}
		if i := bytes.LastIndexByte(chunk, '\n'); i >= 0 {
			return at - n + int64(i) + 1, nil
		}
		at -= n
	}
	return 0, nil
}

// firstLineDigest is the digest of the file's first line, its newline
// included, when a newline ends one before end. The newline is looked for in
// the first look bytes only, and a first line that does not end in them is
// f.rf.ByteBound.
func (f file) firstLineDigest(end, look int64) (Digest, bool, error) {
	if end == 0 {
		return Digest{}, false, nil
	}
	buf := make([]byte, min(look, chunkBytes))
	for at := int64(0); at < look; {
		chunk := buf[:min(look-at, int64(len(buf)))]
		if err := f.readFull(chunk, at); err != nil {
			return Digest{}, false, err
		}
		if i := bytes.IndexByte(chunk, '\n'); i >= 0 {
			s, err := f.sumRange(0, at+int64(i)+1)
			return s, err == nil, err
		}
		at += int64(len(chunk))
	}
	if look < end {
		return Digest{}, false, fmt.Errorf("%w: the first line is longer than the bound %d", f.rf.ByteBound, look)
	}
	return Digest{}, false, fmt.Errorf("%w: no newline before offset %d", f.rf.ShortRead, end)
}

func (f file) sumRange(from, to int64) (Digest, error) {
	h := sha256.New()
	if n, err := io.Copy(h, io.NewSectionReader(f.r, from, to-from)); err != nil || n != to-from {
		return Digest{}, f.shortRead(n, to-from, from, err)
	}
	var out Digest
	h.Sum(out[:0])
	return out, nil
}

// readFull reads len(p) bytes at off. A short read is the file cut under the
// export, never the end of what it holds.
func (f file) readFull(p []byte, off int64) error {
	n, err := f.r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	return f.shortRead(int64(n), int64(len(p)), off, err)
}

func (f file) shortRead(n, want, off int64, err error) error {
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("%w: read %d of %d bytes at offset %d: %w", f.rf.ShortRead, n, want, off, err)
}
