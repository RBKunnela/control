package main

import (
	"cmp"
	"slices"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

const (
	stateVersion = "1.1"
	// legacyStateVersion is the state before closed requests held their mode.
	legacyStateVersion = "1.0"
	stateMajor         = 1
	dedupScope         = "consumer-window"
	// maxOpen is the most requests followed at once; past it the oldest is
	// dropped with an alert.
	maxOpen = 10_000
	// windowSize is how many events the dedup window keeps, the newest.
	windowSize = 20_000
	// maxValueBytes and maxReasons bound each value a request keeps, so the
	// state the other bounds allow stays under maxStateBytes.
	maxValueBytes = 64
	maxReasons    = 16
)

// stateFile is state.json: every member required, none defaulted. It holds
// identifiers, kinds, modes, verdicts, codes and digests, and no other field
// of an event.
type stateFile struct {
	SchemaVersion string `json:"schema_version"`
	DedupScope    string `json:"dedup_scope"`
	Cursor        string `json:"cursor"`
	Source        string `json:"source"`
	// AlertsBytes is the alert log's length at this checkpoint.
	AlertsBytes int64 `json:"alerts_bytes"`
	// TailGap is the gap after the file's last newline last alerted, which
	// the cursor cannot pass and is not alerted again.
	TailGap *tailGapJSON `json:"tail_gap"`
	// Pending are alerts a run logged and then stopped before saving, that
	// no run since has reached: each is not raised again until the cursor
	// passes its offset.
	Pending []pendingJSON `json:"pending"`
	Open    []openJSON    `json:"open"`
	Window  []seenJSON    `json:"window"`
	Closed  []closedJSON  `json:"closed"`
}

type seenJSON struct {
	Tenant  string `json:"tenant"`
	Project string `json:"project"`
	Request string `json:"request"`
	Event   string `json:"event"`
	Hash    string `json:"hash"`
}

type closedJSON struct {
	Tenant  string `json:"tenant"`
	Project string `json:"project"`
	Request string `json:"request"`
	Tail    string `json:"tail"`
	Unknown bool   `json:"unknown"`
	// Kernel is the decision_id of the kernel's decision, which tells a
	// later block of the plane's own from the kernel's.
	Kernel string `json:"kernel"`
	// Mode is the request's enforcement mode, which a finding or a reload
	// after its end has to name; empty when not known. A 1.0 state has no
	// such member.
	Mode string `json:"mode" added:"1.1"`
}

type tailGapJSON struct {
	Offset int64  `json:"offset"`
	Reason string `json:"reason"`
}

type pendingJSON struct {
	Key    string `json:"key"`
	Offset int64  `json:"offset"`
}

type openJSON struct {
	Tenant      string        `json:"tenant"`
	Project     string        `json:"project"`
	Request     string        `json:"request"`
	FirstOffset int64         `json:"first_offset"`
	Head        string        `json:"head"`
	Tail        string        `json:"tail"`
	TailOffset  int64         `json:"tail_offset"`
	Run         string        `json:"run"`
	Action      string        `json:"action"`
	Kernel      *decisionJSON `json:"kernel"`
	Blocked     bool          `json:"blocked"`
	Block       *decisionJSON `json:"block"`
	Held        bool          `json:"held"`
	Approval    string        `json:"approval"`
	Walk        walkJSON      `json:"walk"`
}

type decisionJSON struct {
	Decision string   `json:"decision"`
	Verdict  string   `json:"verdict"`
	Reasons  []string `json:"reasons"`
}

type walkJSON struct {
	Stage    string `json:"stage"`
	Previous string `json:"previous"`
	Mode     string `json:"mode"`
	Verdict  string `json:"verdict"`
	Answer   string `json:"answer"`
	Running  string `json:"running"`
	Note     string `json:"note"`
}

// stageNames names the stages an open request can be at.
var stageNames = []string{"start", "proposed", "decided", "approval_requested", "approval_decided", "approval_expired", "started"}

const startOfRequest = "the start of the request"

// followState is the state in memory: the requests followed, the requests
// that ended while their last event is in the window, and the window.
type followState struct {
	cursor, source string
	tailGap        *gapRecord
	// carried maps the key of each alert carried forward to its offset.
	carried map[string]int64
	open    map[requestKey]*openRequest
	// queue holds the open requests by first offset, oldest first; an entry
	// whose request is no longer open there is passed over.
	queue  []queued
	closed map[requestKey]*closedRequest
	// window is the newest events, oldest first, and seen the line digest of
	// each.
	window []seenEvent
	seen   map[eventKey]string
}

type openRequest struct {
	key                     requestKey
	firstOffset, tailOffset int64
	head, tail              string
	desc                    description
	walk                    walker
}

type seenEvent struct {
	key           eventKey
	request, hash string
}

type closedRequest struct {
	tail, kernel string
	unknown      bool
	// mode is the request's enforcement mode, unspecified when not known.
	mode controlv1.EnforcementMode
}

type queued struct {
	key         requestKey
	firstOffset int64
}

func emptyState() *followState {
	return &followState{carried: map[string]int64{}, open: map[requestKey]*openRequest{}, closed: map[requestKey]*closedRequest{},
		seen: map[eventKey]string{}}
}

// file is the state to write, the alert log's length aside.
func (s *followState) file(alertsBytes int64) stateFile {
	f := stateFile{SchemaVersion: stateVersion, DedupScope: dedupScope, Cursor: s.cursor, Source: s.source, AlertsBytes: alertsBytes,
		Pending: []pendingJSON{}, Open: []openJSON{}, Window: make([]seenJSON, 0, len(s.window)), Closed: []closedJSON{}}
	if g := s.tailGap; g != nil {
		f.TailGap = &tailGapJSON{g.offset, g.reason}
	}
	for k, offset := range s.carried {
		f.Pending = append(f.Pending, pendingJSON{k, offset})
	}
	slices.SortFunc(f.Pending, func(a, b pendingJSON) int { return cmp.Or(cmp.Compare(a.Offset, b.Offset), cmp.Compare(a.Key, b.Key)) })
	opens := make([]*openRequest, 0, len(s.open))
	for _, o := range s.open {
		opens = append(opens, o)
	}
	slices.SortFunc(opens, func(a, b *openRequest) int { return cmp.Compare(a.firstOffset, b.firstOffset) })
	for _, o := range opens {
		f.Open = append(f.Open, o.file())
	}
	for _, e := range s.window {
		f.Window = append(f.Window, seenJSON{e.key.tenant, e.key.project, e.request, e.key.id, e.hash})
		k := requestKey{e.key.tenant, e.key.project, e.request}
		if c := s.closed[k]; c != nil && c.tail == e.key.id {
			f.Closed = append(f.Closed, closedJSON{k.tenant, k.project, k.request, c.tail, c.unknown, c.kernel, modeFile(c.mode)})
		}
	}
	return f
}

func (o *openRequest) file() openJSON {
	return openJSON{Tenant: o.key.tenant, Project: o.key.project, Request: o.key.request, FirstOffset: o.firstOffset, Head: o.head, Tail: o.tail,
		TailOffset: o.tailOffset, Run: o.desc.run, Action: o.desc.action, Kernel: decisionFile(o.desc.kernel), Blocked: o.desc.blocked,
		Block: decisionFile(o.desc.block), Held: o.desc.held, Approval: o.desc.approval,
		Walk: walkJSON{Stage: stageNames[o.walk.at], Previous: o.walk.prevKind, Mode: o.walk.mode.String(), Verdict: o.walk.verdict.String(),
			Answer: o.walk.answer, Running: o.walk.running, Note: o.walk.note}}
}

// modeFile spells a closed request's mode, empty when it is not known.
func modeFile(m controlv1.EnforcementMode) string {
	if m == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
		return ""
	}
	return m.String()
}

func decisionFile(d *decisionFacts) *decisionJSON {
	if d == nil {
		return nil
	}
	return &decisionJSON{Decision: d.id, Verdict: d.verdict, Reasons: d.codes}
}
