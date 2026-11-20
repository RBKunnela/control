package attempts

import (
	"bytes"
	"fmt"
)

// The bounds of a victim's journal.
const (
	MaxJournalBytes = 8 << 20
	MaxJournalDepth = 64
)

// Line is one call a victim received: the tool's name and its arguments, or
// nil when the call carried none.
type Line struct {
	Call string
	Args *Value
}

// Journal is every line of one victim's journal, in the order received.
type Journal struct {
	Lines []Line
}

// ReadJournal reads the journal at path, which must be a regular file with
// one name, of this account, that no other account may read or write, of at
// most MaxJournalBytes, whose every line parses and whose last byte ends a
// line. Any error says why the journal cannot be judged.
func ReadJournal(path string) (*Journal, error) {
	raw, err := readJournalFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJournal, err)
	}
	return ParseJournal(raw)
}

// ParseJournal reads raw as journal lines. An empty journal is a victim that
// received nothing.
func ParseJournal(raw []byte) (*Journal, error) {
	if len(raw) > MaxJournalBytes {
		return nil, fmt.Errorf("%w: %d bytes, the bound is %d", ErrJournal, len(raw), MaxJournalBytes)
	}
	j := &Journal{}
	if len(raw) == 0 {
		return j, nil
	}
	if raw[len(raw)-1] != '\n' {
		return nil, fmt.Errorf("%w: the last line is not whole", ErrJournal)
	}
	for n, body := range bytes.Split(raw[:len(raw)-1], []byte("\n")) {
		l, err := parseLine(body)
		if err != nil {
			return nil, fmt.Errorf("%w: line %d: %w", ErrJournal, n+1, err)
		}
		j.Lines = append(j.Lines, l)
	}
	return j, nil
}

func parseLine(body []byte) (Line, error) {
	v, noted, fatal := parse(body, MaxJournalDepth)
	switch {
	case fatal != nil:
		return Line{}, fatal
	case noted != nil:
		return Line{}, noted
	}
	f, err := closed(v, "", "call", "?", "args")
	if err != nil {
		return Line{}, err
	}
	call, err := text(f["call"], "call")
	if err != nil {
		return Line{}, err
	}
	if call == "" {
		return Line{}, refuse(ErrValue, "call", "empty")
	}
	return Line{Call: call, Args: f["args"]}, nil
}
