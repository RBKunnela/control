package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// The alert codes, a closed set. A policy DENY is reported, never alerted.
const (
	codeGap          = "evidence_gap"
	codeConflict     = "conflicting_event"
	codeUnknown      = "lifecycle_unknown"
	codeUncertain    = "effect_uncertain"
	codeUndecided    = "indeterminate"
	codePlaneBlock   = "plane_block"
	codeExpired      = "approval_expired"
	codeOpenBound    = "open_bound"
	alertLineVersion = 1
)

var codes = []string{codeGap, codeConflict, codeUnknown, codeUncertain, codeUndecided, codePlaneBlock, codeExpired, codeOpenBound}

// gapReasons are the reasons the export gives a gap; an alert says no other.
var gapReasons = []string{"malformed", "too_long", "unsupported_version", "conflicting_event_id", "carriage_return", "partial_tail"}

// alert is one line of the alert log, with only the members that apply. Its
// times are the events', never this program's clock.
type alert struct {
	V          int      `json:"v"`
	Alert      string   `json:"alert"`
	Tenant     string   `json:"tenant,omitempty"`
	Project    string   `json:"project,omitempty"`
	Request    string   `json:"request,omitempty"`
	Run        string   `json:"run,omitempty"`
	Event      string   `json:"event,omitempty"`
	Offset     *int64   `json:"offset,omitempty"`
	Cursor     string   `json:"cursor,omitempty"`
	OccurredAt string   `json:"occurred_at,omitempty"`
	Verdict    string   `json:"verdict,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`
	Block      string   `json:"block,omitempty"`
	Note       string   `json:"note,omitempty"`
}

// key is what makes two alerts one: a rerun after a crash does not raise an
// alert whose key the log holds past its checkpoint. The note is part of it,
// since two gaps at one offset, before and after a writer ended the line
// there, are two alerts.
func (a alert) key() string {
	at := a.Event
	if at == "" && a.Offset != nil {
		at = "@" + strconv.FormatInt(*a.Offset, 10)
	}
	return strings.Join([]string{strconv.Quote(a.Alert), strconv.Quote(a.Tenant), strconv.Quote(a.Project),
		strconv.Quote(a.Request), strconv.Quote(at), strconv.Quote(a.Note)}, " ")
}

// eventAlert is an alert about the event e carries, without an id over the
// bound.
func eventAlert(code string, e *event) alert {
	ev := e.ev
	offset := e.offset
	a := alert{V: alertLineVersion, Alert: code, Tenant: bounded(ev.GetTenantId()), Project: bounded(ev.GetProjectId()),
		Request: bounded(ev.GetRequestId()), Run: bounded(ev.GetRunId()), Event: bounded(ev.GetEventId()), Offset: &offset}
	if isCursor(e.cursor) {
		a.Cursor = e.cursor
	}
	if t := ev.GetOccurredAt(); t != nil && t.IsValid() {
		a.OccurredAt = t.AsTime().UTC().Format(time.RFC3339Nano)
	}
	return a
}

// bounded is an id an alert can carry, none when it is longer than any this
// reader keeps.
func bounded(id string) string {
	if !fits(id) {
		return ""
	}
	return id
}

func gapAlertOf(g gapRecord) alert {
	offset := g.offset
	a := alert{V: alertLineVersion, Alert: codeGap, Offset: &offset, Note: "a reason this reader does not know"}
	if slices.Contains(gapReasons, g.reason) {
		a.Note = g.reason
	}
	if isCursor(g.cursor) {
		a.Cursor = g.cursor
	}
	return a
}

// readAlert reads one line of the alert log as this program writes it.
func readAlert(b []byte) (alert, error) {
	if _, err := object(b); err != nil {
		return alert{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var a alert
	if err := dec.Decode(&a); err != nil {
		return alert{}, errors.New("a line that is not an alert this program writes")
	}
	switch {
	case a.V != alertLineVersion:
		return alert{}, fmt.Errorf("an alert of version %d, and this program writes %d", a.V, alertLineVersion)
	case !slices.Contains(codes, a.Alert):
		return alert{}, errors.New("an alert code this program does not raise")
	case a.Offset == nil:
		return alert{}, errors.New("an alert naming no offset")
	}
	return a, nil
}

// encodeAlert is the alert's line without its newline. A control, format or
// separator character is written as a \u escape, which encoding/json leaves
// raw for most of them, so a terminal shows the line as it is.
func encodeAlert(a alert) ([]byte, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if !bytes.ContainsFunc(b, unprintable) {
		return b, nil
	}
	var out []byte
	for _, r := range string(b) {
		if !unprintable(r) {
			out = utf8.AppendRune(out, r)
			continue
		}
		for _, unit := range utf16.Encode([]rune{r}) {
			out = fmt.Appendf(out, `\u%04x`, unit)
		}
	}
	return out, nil
}
