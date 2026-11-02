package trailfile

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
)

// DefaultMaxLines bounds the lines a read takes, a repeated line included.
// What a read holds is at most this many events of at most
// evidence.MaxLineBytes each.
const DefaultMaxLines = 100_000

// Verdict is what the chain check made of one trail.
type Verdict int

const (
	// Passed is a trail whose chain has its shape and whose action closed:
	// completed, failed or blocked.
	Passed Verdict = iota + 1
	// StillOpen is a trail whose chain has its shape so far and no closing
	// event: a request still in flight, one held for an approval, or one
	// whose closing record has not arrived.
	StillOpen
	// Failed is a trail whose chain is broken.
	Failed
	// Indeterminate is a trail holding a kind or a mode this build cannot
	// place, so the check could not read it either way. It is not a pass.
	Indeterminate
)

// String names the verdict as the trail command prints it.
func (v Verdict) String() string {
	switch v {
	case Passed:
		return "ok"
	case StillOpen:
		return "open"
	case Failed:
		return "failed"
	case Indeterminate:
		return "indeterminate"
	default:
		return "unknown"
	}
}

// Trail is one request's events in a file and what the check made of them.
// A request id is unique within a project, so a trail is one tenant's,
// project's and request's.
type Trail struct {
	TenantID, ProjectID, RequestID string
	// Events is how many events the trail holds, a repeated line once.
	Events int
	// Last is the kind of the trail's last event.
	Last    controlv1.EventKind
	Verdict Verdict
	// Reason is the chain check's refusal, for Failed and Indeterminate.
	Reason error
}

// Report is what a read found.
type Report struct {
	// Trails are in the order their first event appears in the file.
	Trails []Trail
	// Lines is the whole lines read, and Duplicates the ones among them that
	// repeated a line read before, byte for byte.
	Lines      int
	Duplicates int
	// Unread is the bytes after the last newline, which a writer has not
	// finished and the read does not take.
	Unread int64
	// Held is a writer holding the file when ReadFile had read it, so the
	// bytes after the last newline are a line it is still writing. ReadFile
	// asks only when there are such bytes, and Read never does.
	Held bool
	// Log is a read of a log's segments, and Pruned the segments of it gone
	// before the read: pruned, their tombstones dropped or not.
	Log    bool
	Pruned int
}

type scope struct{ tenant, project, request string }

// seenLine is the first line that carried an event id: its number and a
// digest of its bytes.
type seenLine struct {
	number int
	sum    [sha256.Size]byte
}

// Read reads the evidence lines of r up to its last newline, at most maxLines
// of them, and checks each request's trail with evidence.ValidateChain.
//
// A line longer than evidence.MaxLineBytes, one that is not one event, and a
// line past maxLines refuse the whole read, as the codec refuses them. A line
// that repeats, byte for byte, one read before under the same event id is
// what a sender resending leaves, and is counted and dropped; one event id
// carrying a different line is not, and the read is refused as ErrDamaged. An
// event with no id is never collapsed, and its trail fails the check. An
// event evidence.CheckEventVersion refuses leaves its trail Indeterminate, as
// one of a kind this build cannot place does. Each trail is checked in the
// order its links give, which need not be the file's.
//
// The verdict is the chain check's and no more: a trail that passed has the
// shape of one, and nothing here detects a record altered to keep that shape.
func Read(r io.Reader, maxLines int) (Report, error) {
	if maxLines < 0 {
		return Report{}, fmt.Errorf("%w: %d", ErrLimit, maxLines)
	}
	reader := bufio.NewReaderSize(struct{ io.Reader }{r}, evidence.MaxLineBytes+1)
	var rep Report
	seen := map[string]seenLine{}
	groups := map[scope][]*controlv1.Event{}
	unread := map[scope]error{}
	var order []scope
	for number := 1; ; number++ {
		line, err := reader.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			return Report{}, fmt.Errorf("line %d: %w: over %d bytes", number, evidence.ErrLineTooLong, evidence.MaxLineBytes)
		case err == io.EOF: //nolint:errorlint // bufio returns io.EOF itself; a wrapped one is a failure
			rep.Unread = int64(len(line))
			rep.Trails = judge(order, groups, unread)
			return rep, nil
		case err != nil:
			return Report{}, fmt.Errorf("line %d: %w", number, err)
		}
		if rep.Lines >= maxLines {
			return Report{}, fmt.Errorf("line %d: %w: limit %d", number, evidence.ErrTooManyEvents, maxLines)
		}
		rep.Lines++
		events, err := evidence.DecodeJSONL(bytes.NewReader(line), 1)
		if err != nil {
			return Report{}, fmt.Errorf("line %d: %w", number, err)
		}
		ev := events[0]
		if id := ev.GetEventId(); id != "" {
			sum := sha256.Sum256(line)
			if first, ok := seen[id]; ok {
				if first.sum != sum {
					return Report{}, fmt.Errorf("%w: line %d carries the event id of line %d with other content",
						ErrDamaged, number, first.number)
				}
				rep.Duplicates++
				continue
			}
			seen[id] = seenLine{number: number, sum: sum}
		}
		key := scope{ev.GetTenantId(), ev.GetProjectId(), ev.GetRequestId()}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], ev)
		noteVersion(unread, key, number, ev)
	}
}

// noteVersion keeps the first refusal of an event's version in each trail.
func noteVersion(unread map[scope]error, key scope, number int, ev *controlv1.Event) {
	if err := evidence.CheckEventVersion(ev); err != nil && unread[key] == nil {
		unread[key] = fmt.Errorf("line %d: %w", number, err)
	}
}

// judge gives each trail its verdict. A trail holding an event of a version
// this build does not read is Indeterminate before its chain is checked,
// since the chain check would read that event's fields as this build's.
func judge(order []scope, groups map[scope][]*controlv1.Event, unread map[scope]error) []Trail {
	trails := make([]Trail, 0, len(order))
	for _, key := range order {
		events := linked(groups[key])
		tr := Trail{TenantID: key.tenant, ProjectID: key.project, RequestID: key.request,
			Events: len(events), Last: events[len(events)-1].GetKind()}
		err := evidence.ValidateChain(events)
		switch {
		case unread[key] != nil:
			tr.Verdict, tr.Reason = Indeterminate, unread[key]
		case errors.Is(err, evidence.ErrChainIndeterminate):
			tr.Verdict, tr.Reason = Indeterminate, err
		case err != nil:
			tr.Verdict, tr.Reason = Failed, err
		case closed(events):
			tr.Verdict = Passed
		default:
			tr.Verdict = StillOpen
		}
		trails = append(trails, tr)
	}
	return trails
}

// linked returns events in the order their links give: the one event that
// links to nothing, then the one linking to it, and so on. An exporter with
// more than one request in flight can land a later batch first, so the file's
// order is not the trail's. Events whose links do not make one chain, a gap,
// a fork or no head, come back in the file's order, and the chain check
// refuses them there.
func linked(events []*controlv1.Event) []*controlv1.Event {
	next := make(map[string]*controlv1.Event, len(events))
	var head *controlv1.Event
	for _, ev := range events {
		if prev := ev.GetPrevEventId(); prev != "" {
			next[prev] = ev
		} else {
			head = ev
		}
	}
	// A second head or a second event on one link leaves an event the walk
	// never reaches, which the length below catches.
	out := make([]*controlv1.Event, 0, len(events))
	for ev := head; ev != nil && len(out) < len(events); ev = next[ev.GetEventId()] {
		out = append(out, ev)
	}
	if len(out) != len(events) {
		return events
	}
	return out
}

// closed reports whether the trail holds the event that closes its action.
// The chain check lets at most one of them in, and only findings after it.
func closed(events []*controlv1.Event) bool {
	for _, ev := range events {
		switch ev.GetKind() {
		case controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED,
			controlv1.EventKind_EVENT_KIND_ACTION_FAILED,
			controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED:
			return true
		}
	}
	return false
}

// ReadFile reads the file at path as Read does. It holds no lock while it
// reads, so it reads a file a collector is writing, up to the last line the
// collector finished. When bytes follow the last newline it then asks whether
// a writer holds the file, and says so in Report.Held. Anything that is not a
// regular file is refused, without waiting on a named pipe, and so is a file
// in a log's directory, through a link or not, as ErrSegmentFile.
func ReadFile(path string, maxLines int) (Report, error) {
	f, _, err := openTrail(path, "trail")
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = f.Close() }()
	rep, err := Read(f, maxLines)
	if err != nil || rep.Unread == 0 {
		return rep, err
	}
	if rep.Held, err = heldByWriter(f); err != nil {
		return Report{}, err
	}
	return rep, nil
}
