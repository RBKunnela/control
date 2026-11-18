package otelgenai

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
)

// MaxLineBytes bounds one input line, its newline excluded. A longer line is
// refused without being held in memory.
const MaxLineBytes = 16 << 20

// lines reads complete lines. The bytes after the last newline are not a
// line: a file exporter may still be writing them, so they are neither read
// nor refused, and input_bytes stops before them.
type lines struct {
	br        *bufio.Reader
	consumed  uint64
	first     hash.Hash
	firstDone bool
}

func newLines(r io.Reader) *lines {
	return &lines{br: bufio.NewReaderSize(r, 64<<10), first: sha256.New()}
}

// next returns the next line without its newline. tooLong reports a line
// over MaxLineBytes, whose bytes are dropped; ok is false at the end.
func (l *lines) next() (line []byte, tooLong, ok bool, err error) {
	var n, raw int
	var parts [][]byte
	for {
		chunk, err := l.br.ReadSlice('\n')
		if err != nil && err != bufio.ErrBufferFull { //nolint:errorlint // identity: ReadSlice returns the sentinel itself; a source error matching it is a failure
			if err == io.EOF {
				return nil, false, false, nil
			}
			return nil, false, false, err
		}
		raw += len(chunk)
		body := chunk
		if err == nil {
			body = chunk[:len(chunk)-1]
		}
		n += len(body)
		if !l.firstDone {
			l.first.Write(body)
		}
		if n <= MaxLineBytes {
			parts = append(parts, bytes.Clone(body))
		} else {
			parts = nil
		}
		if err == nil {
			l.consumed += uint64(raw)
			l.firstDone = true
			return join(parts), n > MaxLineBytes, true, nil
		}
	}
}

// join copies a long line once, where growing it chunk by chunk would copy
// it several times over.
func join(parts [][]byte) []byte {
	if len(parts) == 1 {
		return parts[0]
	}
	return bytes.Join(parts, nil)
}

// firstLineSHA256 is the digest of the first complete line, or "" when the
// input held none.
func (l *lines) firstLineSHA256() string {
	if !l.firstDone {
		return ""
	}
	return hex.EncodeToString(l.first.Sum(nil))
}
