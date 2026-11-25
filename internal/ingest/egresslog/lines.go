package egresslog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	return &lines{br: bufio.NewReaderSize(sourceReader{r}, readChunk), first: sha256.New()}
}

// sourceReader wraps each error of the input but io.EOF, so one that is
// bufio.ErrBufferFull itself is not read as a line longer than the buffer.
type sourceReader struct{ r io.Reader }

func (s sourceReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && err != io.EOF { //nolint:errorlint // identity: only io.EOF itself ends the input
		err = fmt.Errorf("reading the input: %w", err)
	}
	return n, err
}

// next returns the next line without its newline. tooLong reports a line
// over MaxLineBytes, whose bytes are dropped; ok is false at the end.
func (l *lines) next() (line []byte, tooLong, ok bool, err error) {
	var n, raw int
	var buf []byte
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
