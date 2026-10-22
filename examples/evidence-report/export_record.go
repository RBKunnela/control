package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func (x *export) event(b []byte) {
	var r struct {
		Offset *int64          `json:"offset"`
		Cursor *string         `json:"cursor"`
		Event  json.RawMessage `json:"event"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		x.refuse("an event record whose members are of another type")
		return
	}
	if r.Offset == nil || r.Cursor == nil || len(r.Event) == 0 || string(r.Event) == "null" {
		x.refuse("an event record without its offset, cursor or event")
		return
	}
	if why := x.cursorDefect(*r.Offset, *r.Cursor); why != "" {
		x.refuse("an event record whose cursor " + why)
		return
	}
	if !x.inOrder(*r.Offset) {
		return
	}
	ev := &controlv1.Event{}
	if err := protojson.Unmarshal(r.Event, ev); err != nil {
		x.refuse("an event the contract does not read")
		return
	}
	if major, ok := majorOf(ev.GetSchemaVersion()); !ok || strconv.FormatUint(major, 10) != eventMajor {
		x.refuse(fmt.Sprintf("event %s has a schema_version of another major than %s, which this reader reads", safe(ev.GetEventId()), eventMajor))
		return
	}
	x.add(*r.Offset, *r.Cursor, r.Event, ev)
}

// cursorDefect names what keeps c from being the cursor of a line that starts
// at offset in the file the header names: the cursor names where it ends.
func (x *export) cursorDefect(offset int64, c string) string {
	switch {
	case !isCursor(c):
		return "is not a v1 cursor"
	case x.header.source == "" || !strings.HasPrefix(c, "v1:"+x.header.source+":"):
		return "is not of the file the header names"
	case cursorOffset(c) <= offset:
		return fmt.Sprintf("does not end after its offset, %d", offset)
	}
	return ""
}

// add keeps an event once. The same line twice is a duplicate; one id with
// two lines is a conflict, and every request holding either is unknown.
func (x *export) add(offset int64, cursor string, raw []byte, ev *controlv1.Event) {
	e := &event{ev: ev, raw: raw, offset: offset, cursor: cursor}
	k := eventKey{ev.GetTenantId(), ev.GetProjectId(), ev.GetEventId()}
	if first, seen := x.byKey[k]; seen && k.id != "" {
		if bytes.Equal(first.raw, raw) {
			x.duplicates++
			return
		}
		x.conflicting++
		first.conflicting, e.conflicting = true, true
		x.problems = append(x.problems, fmt.Sprintf("line %d: event %s is held twice with different content", x.line, safe(k.id)))
	} else {
		x.byKey[k] = e
	}
	x.atOffset[offset] = e
	x.events = append(x.events, e)
}

func (x *export) gap(b []byte) {
	var r struct {
		Offset *int64  `json:"offset"`
		Cursor *string `json:"cursor"`
		Reason *string `json:"reason"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.Offset == nil || r.Reason == nil {
		x.refuse("a gap record without its offset or reason")
		return
	}
	if r.Cursor != nil {
		if why := x.cursorDefect(*r.Offset, *r.Cursor); why != "" {
			x.refuse("a gap record whose cursor " + why)
			return
		}
	}
	if !x.inOrder(*r.Offset) {
		return
	}
	g := gapRecord{offset: *r.Offset, reason: *r.Reason}
	if r.Cursor != nil {
		g.cursor = *r.Cursor
	}
	x.gapRecords = append(x.gapRecords, g)
	x.gaps++
	reason := "a reason this reader does not know"
	if slices.Contains(gapReasons, *r.Reason) {
		reason = *r.Reason
	}
	x.problems = append(x.problems, fmt.Sprintf("line %d: a gap at offset %d: %s", x.line, *r.Offset, reason))
}

// duplicate accepts a duplicate only of an event this export wrote at the
// offset it names, so a duplicate record cannot stand in for a missing event.
func (x *export) duplicate(b []byte) {
	var r struct {
		Offset      *int64  `json:"offset"`
		EventID     *string `json:"event_id"`
		FirstOffset *int64  `json:"first_offset"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.Offset == nil || r.EventID == nil || r.FirstOffset == nil {
		x.refuse("a duplicate record without its offset, event_id or first_offset")
		return
	}
	if !x.inOrder(*r.Offset) {
		return
	}
	if first, ok := x.atOffset[*r.FirstOffset]; !ok || first.ev.GetEventId() != *r.EventID {
		x.refuse(fmt.Sprintf("a duplicate of event %s at offset %d, where this export wrote no such event",
			safe(*r.EventID), *r.FirstOffset))
		return
	}
	x.duplicates++
}
