package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

func init() {
	for _, t := range []reflect.Type{reflect.TypeFor[stateFile](), reflect.TypeFor[alert]()} {
		addTags(t)
	}
}

// addTags adds the member names of t and of the types it holds to the
// vocabulary a diagnostic may name.
func addTags(t reflect.Type) {
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice:
		addTags(t.Elem())
	case reflect.Struct:
		for i := range t.NumField() {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			vocabulary[name] = true
			addTags(t.Field(i).Type)
		}
	}
}

// decodeState reads state.json strictly: a member it does not name, one
// missing, one held twice or in another case, or another major is refused. A
// 1.0 state lacks the members added in 1.1 and is read without them.
func decodeState(b []byte) (*stateFile, error) {
	var v struct {
		SchemaVersion string `json:"schema_version"`
	}
	legacy := json.Unmarshal(b, &v) == nil && v.SchemaVersion == legacyStateVersion
	if err := exactMembers(b, reflect.TypeFor[stateFile](), "state", legacy); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f stateFile
	if err := dec.Decode(&f); err != nil {
		return nil, errors.New("a member is of another type")
	}
	if major, ok := majorOf(f.SchemaVersion); !ok || major != stateMajor {
		return nil, fmt.Errorf("its schema_version is not of major %d, which this program reads", stateMajor)
	}
	if f.DedupScope != dedupScope {
		return nil, fmt.Errorf("its dedup_scope is not %q", dedupScope)
	}
	return &f, nil
}

// exactMembers holds the JSON value b to the members of type t's json tags,
// every one of them and no other, through nested objects and arrays. In a
// legacy state a member tagged as added later may be missing.
func exactMembers(b []byte, t reflect.Type, at string, legacy bool) error {
	switch t.Kind() {
	case reflect.Pointer:
		if string(bytes.TrimSpace(b)) == "null" {
			return nil
		}
		return exactMembers(b, t.Elem(), at, legacy)
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(b, &items); err != nil {
			return fmt.Errorf("%s: not an array", at)
		}
		for i, item := range items {
			if err := exactMembers(item, t.Elem(), fmt.Sprintf("%s[%d]", at, i), legacy); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		return exactObject(b, t, at, legacy)
	}
	return nil
}

func exactObject(b []byte, t reflect.Type, at string, legacy bool) error {
	ms, err := object(b)
	if err != nil {
		return fmt.Errorf("%s: %w", at, err)
	}
	names := make([]string, t.NumField())
	for i := range names {
		names[i], _, _ = strings.Cut(t.Field(i).Tag.Get("json"), ",")
	}
	if err := only(ms, names); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	}
	for i, n := range names {
		v, ok := valueOf(ms, n)
		if !ok && legacy && t.Field(i).Tag.Get("added") != "" {
			continue
		}
		if !ok {
			return fmt.Errorf("%s: member %q is missing", at, n)
		}
		if err := exactMembers(v, t.Field(i).Type, at+"."+n, legacy); err != nil {
			return err
		}
	}
	return nil
}

// load builds the state in memory from the file, refusing one whose parts
// do not agree.
func (f *stateFile) load() (*followState, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	s := emptyState()
	s.cursor, s.source = f.Cursor, f.Source
	if err := s.loadTail(f.TailGap, f.Pending); err != nil {
		return nil, err
	}
	for i, o := range f.Open {
		if err := s.loadOpen(o); err != nil {
			return nil, fmt.Errorf("open[%d]: %w", i, err)
		}
	}
	slices.SortStableFunc(s.queue, func(a, b queued) int { return cmp.Compare(a.firstOffset, b.firstOffset) })
	inWindow := make(map[eventKey]string, len(f.Window))
	for i, w := range f.Window {
		k := eventKey{w.Tenant, w.Project, w.Event}
		if w.Request == "" {
			return nil, fmt.Errorf("window[%d]: an event of no request", i)
		}
		if err := s.remember(k, w.Hash); err != nil {
			return nil, fmt.Errorf("window[%d]: %w", i, err)
		}
		s.window = append(s.window, seenEvent{key: k, request: w.Request, hash: w.Hash})
		inWindow[k] = w.Request
	}
	for i, c := range f.Closed {
		if err := s.loadClosed(c, inWindow); err != nil {
			return nil, fmt.Errorf("closed[%d]: %w", i, err)
		}
	}
	return s, nil
}

// check refuses a state whose cursor, source, log length or sizes do not
// hold together.
func (f *stateFile) check() error {
	switch {
	case f.Source != "" && !isSum(f.Source):
		return errors.New("its source is not a SHA-256 in lowercase hex")
	case f.Cursor != "" && !isCursor(f.Cursor):
		return errors.New("its cursor is not a v1 cursor")
	case f.Cursor != "" && !strings.HasPrefix(f.Cursor, "v1:"+f.Source+":"):
		return errors.New("the cursor is not of the source the state names")
	case f.AlertsBytes < 0:
		return fmt.Errorf("alerts_bytes is %d", f.AlertsBytes)
	case len(f.Open) > maxOpen:
		return fmt.Errorf("%d open requests, over the bound of %d", len(f.Open), maxOpen)
	case len(f.Window) > windowSize:
		return fmt.Errorf("%d events in the window, over its %d", len(f.Window), windowSize)
	}
	return nil
}

// loadTail takes the gap after the last newline last alerted and the alerts
// carried forward.
func (s *followState) loadTail(g *tailGapJSON, pending []pendingJSON) error {
	if g != nil {
		if g.Offset < 0 || !slices.Contains(gapReasons, g.Reason) {
			return errors.New("its tail_gap is not a gap the export gives")
		}
		s.tailGap = &gapRecord{offset: g.Offset, reason: g.Reason}
	}
	for i, p := range pending {
		if _, twice := s.carried[p.Key]; twice || p.Key == "" || p.Offset < 0 {
			return fmt.Errorf("pending[%d]: an alert key empty, held twice or at a negative offset", i)
		}
		s.carried[p.Key] = p.Offset
	}
	return nil
}

func (s *followState) remember(k eventKey, hash string) error {
	switch {
	case k.tenant == "" || k.project == "" || k.id == "":
		return errors.New("an event without its tenant, project or id")
	case !isSum(hash):
		return errors.New("a hash that is not a SHA-256 in lowercase hex")
	case s.seen[k] != "":
		return fmt.Errorf("event %s is held twice", safe(k.id))
	}
	s.seen[k] = hash
	return nil
}

func (s *followState) loadOpen(o openJSON) error {
	k := requestKey{o.Tenant, o.Project, o.Request}
	if err := o.check(); err != nil {
		return err
	}
	if s.open[k] != nil {
		return fmt.Errorf("request %s is open twice", safe(k.request))
	}
	r := &openRequest{key: k, firstOffset: o.FirstOffset, tailOffset: o.TailOffset, head: o.Head, tail: o.Tail}
	var err error
	if r.desc, err = loadDescription(o); err != nil {
		return err
	}
	if r.walk, err = loadWalk(o.Walk); err != nil {
		return err
	}
	s.open[k] = r
	s.queue = append(s.queue, queued{k, o.FirstOffset})
	return nil
}

func (o openJSON) check() error {
	switch {
	case o.Tenant == "" || o.Project == "" || o.Request == "":
		return errors.New("a request without its tenant, project or id")
	case o.Head == "" || o.Tail == "":
		return errors.New("a request without its first or last event")
	case o.FirstOffset < 0 || o.TailOffset < o.FirstOffset:
		return fmt.Errorf("offsets %d and %d", o.FirstOffset, o.TailOffset)
	}
	return nil
}

// loadClosed takes a request that ended. inWindow names each event of the
// window's request.
func (s *followState) loadClosed(c closedJSON, inWindow map[eventKey]string) error {
	k := requestKey{c.Tenant, c.Project, c.Request}
	switch {
	case s.closed[k] != nil || s.open[k] != nil:
		return fmt.Errorf("request %s is held twice", safe(k.request))
	case inWindow[eventKey{k.tenant, k.project, c.Tail}] != k.request:
		return fmt.Errorf("its tail %s is not in the window", safe(c.Tail))
	}
	r := &closedRequest{tail: c.Tail, kernel: c.Kernel, unknown: c.Unknown}
	if c.Mode != "" {
		mode, ok := controlv1.EnforcementMode_value[c.Mode]
		if !ok || mode == 0 {
			return errors.New("a mode this program does not write")
		}
		r.mode = controlv1.EnforcementMode(mode)
	}
	s.closed[k] = r
	return nil
}

var approvals = []string{"", "pending", "approved", "rejected", "expired", "unknown"}

func loadDescription(o openJSON) (description, error) {
	d := description{run: o.Run, action: o.Action, blocked: o.Blocked, held: o.Held, approval: o.Approval}
	if !slices.Contains(approvals, o.Approval) {
		return d, errors.New("an approval state this program does not write")
	}
	var err error
	if d.kernel, err = loadDecision(o.Kernel); err != nil {
		return d, err
	}
	d.block, err = loadDecision(o.Block)
	return d, err
}

func loadDecision(j *decisionJSON) (*decisionFacts, error) {
	if j == nil {
		return nil, nil
	}
	if _, ok := controlv1.Verdict_value["VERDICT_"+j.Verdict]; !ok {
		return nil, errors.New("a verdict the contract does not declare")
	}
	return &decisionFacts{id: j.Decision, verdict: j.Verdict, codes: j.Reasons}, nil
}

func loadWalk(j walkJSON) (walker, error) {
	at := slices.Index(stageNames, j.Stage)
	mode, modeOK := controlv1.EnforcementMode_value[j.Mode]
	verdict, verdictOK := controlv1.Verdict_value[j.Verdict]
	_, kindOK := controlv1.EventKind_value["EVENT_KIND_"+j.Previous]
	switch {
	case at < 0:
		return walker{}, errors.New("a walk whose stage this program does not write")
	case !modeOK || mode == 0:
		return walker{}, errors.New("a walk whose mode this program does not write")
	case !verdictOK:
		return walker{}, errors.New("a walk whose verdict this program does not write")
	case j.Previous != startOfRequest && !kindOK:
		return walker{}, errors.New("a walk whose previous this program does not write")
	case !slices.Contains([]string{"", "approved", "rejected", "unknown"}, j.Answer):
		return walker{}, errors.New("a walk whose answer this program does not write")
	}
	return walker{at: stage(at), prevKind: j.Previous, mode: controlv1.EnforcementMode(mode), verdict: controlv1.Verdict(verdict),
		answer: j.Answer, running: j.Running, end: endOpen, note: j.Note}, nil
}
