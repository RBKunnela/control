package main

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

func initState(path string, stderr io.Writer) int {
	if err := makeStateDir(path); err != nil {
		say(stderr, "the state directory is refused: "+err.Error())
		return 2
	}
	return 0
}

func printCursor(path string, stdout, stderr io.Writer) int {
	c, code := openCheckpoint(path, stderr)
	if c == nil {
		return code
	}
	if _, err := io.WriteString(stdout, c.state.cursor+"\n"); err != nil {
		say(stderr, "the cursor could not be written: "+err.Error())
		return 2
	}
	return 0
}

func openCheckpoint(path string, stderr io.Writer) (*checkpoint, int) {
	d, err := openStateDir(path)
	if err != nil {
		say(stderr, "the state directory is refused: "+err.Error())
		return nil, 2
	}
	defer d.close()
	c, err := d.load()
	if err != nil {
		say(stderr, "the state is refused: "+err.Error())
		return nil, 2
	}
	return c, 0
}

// follow reads one export after the state's cursor, holding the state
// directory's lock: it appends the alerts the export calls for to the log,
// syncs it and says them on stderr, prints the rows of the requests that
// ended, then replaces the state. A crash or a failed write after the append
// leaves state.json as it was and the alerts past its checkpoint, which no
// later run raises again; the rows, which are not kept, may print again.
func follow(path string, stdin io.Reader, stdout, stderr io.Writer) int {
	d, err := openStateDir(path)
	if err != nil {
		say(stderr, "the state directory is refused: "+err.Error())
		return 2
	}
	defer d.close()
	held, err := d.lock()
	if err != nil {
		say(stderr, "the state directory is refused: "+err.Error())
		return 2
	}
	defer func() { _ = held.Close() }()
	c, err := d.load()
	if err != nil {
		say(stderr, "the state is refused: "+err.Error())
		return 2
	}
	x, err := readExport(stdin)
	if err == nil {
		err = c.state.accepts(x)
	}
	f := newFollower(c.state, c.pending)
	var lines, state []byte
	if err == nil {
		f.take(x)
		lines, state, err = f.checkpoint(c)
	}
	if err != nil {
		say(stderr, "the export is refused: "+err.Error())
		return 2
	}
	if err := f.commit(d, c, lines, state, x, stdout, stderr); err != nil {
		say(stderr, err.Error())
		return 2
	}
	if len(f.alerts) > 0 {
		return 1
	}
	return 0
}

// checkpoint is the alert lines and the state this run would save, refused
// when the state would be over its bound or the alerts more than the log may
// hold past its checkpoint, which a crash would leave there for good.
func (f *follower) checkpoint(c *checkpoint) ([]byte, []byte, error) {
	lines, err := f.alertLines()
	if err != nil {
		return nil, nil, err
	}
	if past := c.logBytes - c.saved + int64(len(lines)); past > maxPendingBytes {
		return nil, nil, fmt.Errorf("its alerts would leave %d bytes in the log past the state's checkpoint, over %d: "+
			"export again with a smaller --limit", past, maxPendingBytes)
	}
	state, err := encodeState(f.s.file(c.logBytes + int64(len(lines))))
	return lines, state, err
}

// accepts refuses an export the state cannot take on from its cursor. An
// export of another file than the state's is taken only as the next segment
// of a log: one asked after the state's own cursor that starts at its file's
// first line, which an export after a cursor in the same file never does. An
// export naming no source is of a file holding no whole line yet, such as a
// log's live segment a writer has only begun: the state keeps its cursor and
// source, and the file is exported again later.
func (s *followState) accepts(x *export) error {
	if err := x.whole(); err != nil {
		return err
	}
	if x.header.after != s.cursor {
		return fmt.Errorf("its query.after is %s, and the state's cursor %s", shownCursor(x.header.after), shownCursor(s.cursor))
	}
	if x.header.source == "" {
		return x.holdsNoLine()
	}
	moved := s.movedOn(x)
	if s.source != "" && x.header.source != s.source && !moved {
		return fmt.Errorf("its source is not the state's, %s: another file", s.source)
	}
	return s.leadsOn(x, moved)
}

// leadsOn refuses a trailer whose next_cursor is not of the export's file, is
// missing after records, or, in the state's own file, is behind its cursor.
func (s *followState) leadsOn(x *export, moved bool) error {
	next := x.trailer.nextCursor
	switch {
	case next != "" && !strings.HasPrefix(next, "v1:"+x.header.source+":"):
		return errors.New("its trailer's next_cursor is not of the file its header names")
	case next == "" && (s.cursor != "" || len(x.events) > 0):
		return errors.New("its trailer names no next_cursor after records it read")
	case !moved && next != "" && cursorOffset(next) < cursorOffset(s.cursor):
		return fmt.Errorf("its trailer's next_cursor, at offset %d, is behind the cursor it starts after, at %d", cursorOffset(next), cursorOffset(s.cursor))
	}
	return nil
}

// movedOn reports whether x is the next segment of the state's log: another
// source, asked after the state's cursor, its first record at offset 0.
func (s *followState) movedOn(x *export) bool {
	if s.source == "" || s.cursor == "" || x.header.source == s.source || x.header.after != s.cursor {
		return false
	}
	at, ok := x.firstOffset()
	return ok && at == 0
}

// holdsNoLine refuses an export naming no source that holds what only a file
// with a whole line gives: an event, a gap a newline ends, or a next_cursor.
func (x *export) holdsNoLine() error {
	ended := slices.ContainsFunc(x.gapRecords, func(g gapRecord) bool { return g.cursor != "" })
	if len(x.events) > 0 || ended || x.trailer.nextCursor != "" {
		return errors.New("its header names no source, and it holds a whole line")
	}
	return nil
}

// whole refuses an export a state cannot take whatever its cursor: one
// holding a refused record, cut short, or filtered.
func (x *export) whole() error {
	switch {
	case x.refused > 0:
		return fmt.Errorf("%d record(s) refused, the first at %s", x.refused, x.firstRefusal)
	case x.trailer == nil:
		return errors.New("it has no trailer: it was cut short")
	case x.header.filtered:
		return errors.New("its query names a filter, which cuts the links between a request's events: export the whole file")
	}
	return nil
}

// shownCursor names a cursor in a refusal only when it is spelled as one.
func shownCursor(c string) string {
	switch {
	case c == "":
		return "none"
	case isCursor(c):
		return c
	}
	return "a value that is not a cursor"
}

func (f *follower) alertLines() ([]byte, error) {
	var lines []byte
	for _, a := range f.alerts {
		b, err := encodeAlert(a)
		if err != nil {
			return nil, err
		}
		lines = append(append(lines, b...), '\n')
	}
	return lines, nil
}

// commit appends the new alerts to the log, syncs it and says them on
// stderr, prints the rows, then replaces the state. Its error is the line
// to say.
func (f *follower) commit(d *stateDir, c *checkpoint, lines, state []byte, x *export, stdout, stderr io.Writer) error {
	if _, err := d.appendAlerts(c, lines); err != nil {
		return fmt.Errorf("the alerts could not be logged: %w", err)
	}
	for _, l := range strings.SplitAfter(string(lines), "\n") {
		if l != "" {
			say(stderr, "alert "+strings.TrimSuffix(l, "\n"))
		}
	}
	if err := crash("alerts"); err != nil {
		return err
	}
	if err := f.print(x, stdout); err != nil {
		return fmt.Errorf("the report could not be written, so the state is not saved: %w", err)
	}
	if err := d.writeState(state); err != nil {
		return fmt.Errorf("the state could not be saved: %w", err)
	}
	return nil
}

// print writes the rows of the requests that ended and the totals, which
// count the requests still open among the requests.
func (f *follower) print(x *export, stdout io.Writer) error {
	var t totals
	lines := []string{"tenant\tproject\trequest\trun\taction\tverdict\treasons\tblock\theld\tapproval\tend\tnote"}
	for _, r := range f.rows {
		t.add(r)
		lines = append(lines, r.String())
	}
	t.requests += len(f.s.open)
	t.open += len(f.s.open)
	x.duplicates += f.duplicates
	x.conflicting += f.conflicting
	lines = append(lines, t.line(x))
	_, err := io.WriteString(stdout, strings.Join(lines, "\n")+"\n")
	return err
}
