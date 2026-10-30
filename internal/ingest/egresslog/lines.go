package egresslog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
)

// MaxLineBytes bounds one input line, its newline excluded. A longer line is
// refused without being held in memory.
const MaxLineBytes = 64 << 10

// readChunk is how much of a line is held at once while its length is
// unknown.
const readChunk = 4 << 10

// lines reads complete lines. The bytes after the last newline are not a
// line: the proxy may still be writing them, so they are neither read nor
// refused, and input_bytes stops before them.
type lines struct {
	br        *bufio.Reader
	consumed  uint64
	first     hash.Hash
	firstDone bool
}

func newLines(r io.Reader) *lines {
	return &lines{br: bufio.NewReaderSize(r, readChunk), first: sha256.New()}
}

// next returns the next line without its newline. tooLong reports a line
// over MaxLineBytes, whose bytes are dropped; ok is false at the end.
func (l *lines) next() (line []byte, tooLong, ok bool, err error) {
	var n, raw int
	var buf []byte
	for {
		chunk, err := l.br.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			if errors.Is(err, io.EOF) {
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
			buf = append(buf, body...)
		} else {
			buf = nil
		}
		if err == nil {
			l.consumed += uint64(raw)
			l.firstDone = true
			return buf, n > MaxLineBytes, true, nil
		}
	}
}

// firstLineSHA256 is the digest of the first complete line, or "" when the
// input held none.
func (l *lines) firstLineSHA256() string {
	if !l.firstDone {
		return ""
	}
	return hex.EncodeToString(l.first.Sum(nil))
}
