package stopwrite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// Carried is what a carry wrote.
type Carried struct {
	// Header is the new list's header.
	Header reaction.Header
	// Stops is how many stops the new list holds.
	Stops int
	// Covered is how many covered lines it holds.
	Covered int
	// LeftOut is how many lines of the old list, from the first one the
	// plane's judge refuses to its end, the carry left out; zero when it took
	// the whole list.
	LeftOut int64
	// Refused is the first line left out and why; nil when none was.
	Refused error
}

// carrying, when a test sets it, runs once a carry read the old list and
// before it writes the new one.
var carrying func()

// Carry starts a stop list in dir, judged against route, from the list in
// from, judged against fromRoute, which alone may name a rule version a later
// one superseded (reaction.CheckCarrySource). The new list keeps every stop of
// the old one no lift ended, expired or not, since the writer's clock may be
// one a plane would not trust, and a covered line for every other finding the
// old list names, so none of them stops a run again. A list a plane refuses at
// one of its lines is carried up to that line (acceptedPart). The old list
// stays locked until the new one is written, whole or not at all, so no write
// to it falls between the two; a dir that already holds a list is ErrExists.
func Carry(ctx context.Context, from string, fromRoute reaction.Route, dir string, route reaction.Route, now time.Time) (Carried, error) {
	var out Carried
	err := locked(ctx, from, func(root *os.Root) error {
		same, err := sameDir(root, dir)
		if err != nil {
			return err
		}
		if same {
			return fmt.Errorf("%w: %s", ErrExists, dir)
		}
		old, err := readList(root)
		if err != nil {
			return err
		}
		part, err := acceptedPart(fromRoute, old, now)
		if err != nil {
			return err
		}
		list := part.list
		h, err := newHeader(route)
		if err != nil {
			return err
		}
		header, err := h.Marshal()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrRefused, err)
		}
		out = Carried{Header: h, LeftOut: part.leftOut, Refused: part.refused}
		lines := [][]byte{header}
		kept := map[string]bool{}
		for _, e := range list.Entries() {
			line, err := e.Marshal()
			if err != nil {
				return fmt.Errorf("%w: %w", ErrRefused, err)
			}
			lines = append(lines, line)
			kept[e.FindingID] = true
			out.Stops++
		}
		covered, err := coveredLines(part.accepted, kept)
		if err != nil {
			return err
		}
		out.Covered = len(covered)
		if carrying != nil {
			carrying()
		}
		return create(ctx, dir, route, now, append(lines, covered...))
	})
	if err != nil {
		return Carried{}, err
	}
	return out, nil
}

// part is what a carry takes of an old list: the list a plane accepts, its
// bytes, and how many lines after them it leaves out and why.
type part struct {
	list     reaction.List
	accepted []byte
	leftOut  int64
	refused  error
}

// acceptedPart judges old against route as a plane does. A list it accepts is
// taken whole. One it refuses at a line is taken up to that line, which
// repairs a list someone broke by appending a line the route refuses, but
// only where nothing left out could be a stop the old list was meant to hold:
// a refused header, a line refused for a created_at past the writer's clock,
// which another writer whose clock runs ahead wrote in good faith, and a stop
// or covered line after the refused line each refuse the carry, as does a
// route naming a rule that may not stop a run and was never superseded.
func acceptedPart(route reaction.Route, old []byte, now time.Time) (part, error) {
	if err := reaction.CheckCarrySource(route); err != nil {
		return part{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	list, err := reaction.JudgeCarrySource(route, old, now)
	if err == nil {
		return part{list: list, accepted: old}, nil
	}
	var at *reaction.LineError
	if !errors.As(err, &at) || at.Line < 2 || errors.Is(err, reaction.ErrDatedAhead) {
		return part{}, fmt.Errorf("the list carried from: %w", refusal(err))
	}
	complete := old[:bytes.LastIndexByte(old, '\n')+1]
	lines := bytes.SplitAfter(complete, []byte{'\n'})
	lines = lines[:len(lines)-1]
	for i, raw := range lines[at.Line:] {
		l, perr := reaction.ParseLine(bytes.TrimSuffix(raw, []byte{'\n'}))
		if perr == nil && (l.Kind == reaction.KindStop || l.Kind == reaction.KindCovered) {
			return part{}, fmt.Errorf("the list carried from: %w: line %d names a finding after line %d, which is refused: %w",
				ErrRefused, at.Line+int64(i)+1, at.Line, at.Err)
		}
	}
	accepted := bytes.Join(lines[:at.Line-1], nil)
	if list, err = reaction.JudgeCarrySource(route, accepted, now); err != nil {
		return part{}, fmt.Errorf("the list carried from: %w", refusal(err))
	}
	return part{list: list, accepted: accepted, leftOut: int64(len(lines)) - at.Line + 1, refused: at}, nil
}

// sameDir reports whether dir names the directory root holds. A dir that
// cannot be read is not that directory; the write into it reports why.
func sameDir(root *os.Root, dir string) (bool, error) {
	held, err := root.Stat(".")
	if err != nil {
		return false, err
	}
	named, err := os.Stat(dir)
	return err == nil && os.SameFile(held, named), nil
}

// coveredLines is a covered line for each finding a stop or covered line of
// old names that kept does not.
func coveredLines(old []byte, kept map[string]bool) ([][]byte, error) {
	var covered [][]byte
	complete := old[:bytes.LastIndexByte(old, '\n')+1]
	for raw := range bytes.Lines(complete) {
		l, err := reaction.ParseLine(bytes.TrimSuffix(raw, []byte{'\n'}))
		if err != nil {
			return nil, fmt.Errorf("the list carried from: %w", refusal(err))
		}
		var c reaction.Covered
		switch l.Kind {
		case reaction.KindStop:
			c = reaction.Covered{FindingID: l.Stop.FindingID, TenantID: l.Stop.TenantID, RunID: l.Stop.RunID, CreatedAt: l.Stop.CreatedAt}
		case reaction.KindCovered:
			c = l.Covered
		default:
			continue
		}
		if kept[c.FindingID] {
			continue
		}
		line, err := c.Marshal()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		covered = append(covered, line)
	}
	return covered, nil
}

// readList reads the list root holds, with every check a plane's read makes;
// the caller holds the lock.
func readList(root *os.Root) ([]byte, error) {
	named, err := stoplist.Named(root)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(stoplist.FileName, os.O_RDONLY|stoplist.OpenFlags, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if err := stoplist.CheckOpened(named, f); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, reaction.MaxListBytes+1))
}
