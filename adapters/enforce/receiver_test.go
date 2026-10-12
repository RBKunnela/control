package enforce_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// exchange is one case being run: what was captured, and every way the
// receiver departed from the case.
type exchange struct {
	t        *testing.T
	r        *rig
	d        defect
	tokens   map[string]string
	mu       sync.Mutex
	captured map[string]any
	miss     []string
}

func (x *exchange) missf(format string, args ...any) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.miss = append(x.miss, fmt.Sprintf(format, args...))
}

// runReceiverCase runs one case against a rig built from its setup with the
// defect d, and returns every departure; none means it passed.
func runReceiverCase(t *testing.T, id string, d defect) []string {
	t.Helper()
	dir := filepath.Join(casesDir, "receiver", id)
	var setup setupFile
	readJSON(t, filepath.Join(dir, "setup.json"), &setup)
	var trail trailFile
	readJSON(t, filepath.Join(dir, "trail.json"), &trail)
	steps := loadSteps(t, dir)

	r, tokens := buildFromSetup(t, setup, d)
	x := &exchange{t: t, r: r, d: d, tokens: tokens, captured: map[string]any{}}
	for i, s := range steps {
		x.step(i+1, s)
	}
	x.compareTrail(trail)
	return x.miss
}

func (x *exchange) step(line int, s step) {
	switch {
	case s.Advance != "":
		d, err := time.ParseDuration(s.Advance)
		if err != nil {
			x.t.Fatalf("line %d: advance %q", line, s.Advance)
		}
		x.r.clock.advance(d)
	case s.Sweep != nil:
		n := 0
		if !x.d.noSweep {
			n = x.r.a.Sweep(x.t.Context(), x.r.clock.read())
		}
		if n != *s.Sweep {
			x.missf("line %d: sweep abandoned %d, want %d", line, n, *s.Sweep)
		}
	case s.Approve != "":
		id, ok := x.captured[s.Approve].(string)
		if !ok {
			x.missf("line %d: nothing captured as %q", line, s.Approve)
			return
		}
		if err := x.r.store.Answer(id, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", x.r.clock.read()); err != nil {
			x.missf("line %d: approving: %v", line, err)
		}
	case s.Together != nil:
		x.together(line, s.Together)
	default:
		status, answer := x.send(line, s.request)
		x.expect(line, expected{s.Status, s.Answer}, status, answer)
	}
}

// send posts one request as the case and the defect write it.
func (x *exchange) send(line int, req request) (int, []byte) {
	body := ""
	switch {
	case req.Raw != nil:
		body = *req.Raw
	case req.Body != nil:
		var v any
		if err := json.Unmarshal(req.Body, &v); err != nil {
			x.t.Fatalf("line %d: body: %v", line, err)
		}
		out, err := json.Marshal(x.substitute(line, v))
		if err != nil {
			x.t.Fatal(err)
		}
		body = string(out)
	}
	token := ""
	if req.As != "" {
		var ok bool
		if token, ok = x.tokens[req.As]; !ok {
			x.t.Fatalf("line %d: no run %q", line, req.As)
		}
	}
	path := req.Post
	if x.d.request != nil {
		path, token, body = x.d.request(path, token, body, x.tokens)
	}
	return x.r.post(x.t, token, path, body)
}

// substitute replaces {"$b64": text} with the base64 of text and
// {"$same": name} with what was captured as name.
func (x *exchange) substitute(line int, v any) any {
	switch c := v.(type) {
	case map[string]any:
		if text, ok := c["$b64"].(string); ok && len(c) == 1 {
			return base64.StdEncoding.EncodeToString([]byte(text))
		}
		if name, ok := c["$same"].(string); ok && len(c) == 1 {
			x.mu.Lock()
			defer x.mu.Unlock()
			got, ok := x.captured[name]
			if !ok {
				x.miss = append(x.miss, fmt.Sprintf("line %d: nothing captured as %q", line, name))
			}
			return got
		}
		for k, e := range c {
			c[k] = x.substitute(line, e)
		}
	case []any:
		for i, e := range c {
			c[i] = x.substitute(line, e)
		}
	}
	return v
}

func (x *exchange) expect(line int, want expected, status int, answer []byte) {
	for _, m := range x.matches(want, status, answer, true) {
		x.missf("line %d: %s", line, m)
	}
}

// matches lists how an answer departs from want; with capture set, the
// values it names are captured.
func (x *exchange) matches(want expected, status int, answer []byte, capture bool) []string {
	var miss []string
	if status != want.Status {
		miss = append(miss, fmt.Sprintf("status %d, want %d: %s", status, want.Status, answer))
	}
	if want.Answer == nil {
		return miss
	}
	var got, exp any
	if err := json.Unmarshal(answer, &got); err != nil {
		return append(miss, fmt.Sprintf("answer %q is not JSON", answer))
	}
	if err := json.Unmarshal(want.Answer, &exp); err != nil {
		x.t.Fatal(err)
	}
	return append(miss, x.match("answer", exp, got, capture)...)
}

func (x *exchange) match(at string, exp, got any, capture bool) []string {
	if s, ok := exp.(string); ok && s == "*" {
		if got == nil {
			return []string{at + " absent"}
		}
		return nil
	}
	if m, ok := exp.(map[string]any); ok && len(m) == 1 {
		if out, special := x.matcher(at, m, got, capture); special {
			return out
		}
	}
	switch e := exp.(type) {
	case map[string]any:
		return x.matchObject(at, e, got, capture)
	case []any:
		return x.matchArray(at, e, got, capture)
	}
	if fmt.Sprint(exp) != fmt.Sprint(got) {
		return []string{fmt.Sprintf("%s = %v, want %v", at, got, exp)}
	}
	return nil
}

// matchArray holds got to exp element by element.
func (x *exchange) matchArray(at string, exp []any, got any, capture bool) []string {
	g, ok := got.([]any)
	if !ok || len(g) != len(exp) {
		return []string{fmt.Sprintf("%s = %v, want %d elements", at, got, len(exp))}
	}
	var miss []string
	for i := range exp {
		miss = append(miss, x.match(fmt.Sprintf("%s[%d]", at, i), exp[i], g[i], capture)...)
	}
	return miss
}

// matchObject holds got to every member exp names, and to no other.
func (x *exchange) matchObject(at string, exp map[string]any, got any, capture bool) []string {
	g, ok := got.(map[string]any)
	if !ok {
		return []string{fmt.Sprintf("%s = %v, want an object", at, got)}
	}
	var miss []string
	for k := range g {
		if _, named := exp[k]; !named {
			miss = append(miss, fmt.Sprintf("%s.%s present and not named", at, k))
		}
	}
	for k, v := range exp {
		miss = append(miss, x.match(at+"."+k, v, g[k], capture)...)
	}
	return miss
}

// matcher applies {"$capture": name}, {"$same": name} and {"$b64": text}.
func (x *exchange) matcher(at string, m map[string]any, got any, capture bool) ([]string, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if name, ok := m["$capture"].(string); ok {
		if got == nil {
			return []string{at + " absent"}, true
		}
		if capture {
			x.captured[name] = got
		}
		return nil, true
	}
	if name, ok := m["$same"].(string); ok {
		if want, seen := x.captured[name]; !seen || fmt.Sprint(want) != fmt.Sprint(got) {
			return []string{fmt.Sprintf("%s = %v, want %s (%v)", at, got, name, want)}, true
		}
		return nil, true
	}
	if text, ok := m["$b64"].(string); ok {
		s, _ := got.(string)
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil || string(decoded) != text {
			return []string{fmt.Sprintf("%s = %q, want the bytes %q", at, decoded, text)}, true
		}
		return nil, true
	}
	return nil, false
}

// together sends every request at once and matches the answers to the
// expectations in whichever order they came.
func (x *exchange) together(line int, tg *together) {
	if len(tg.Requests) != len(tg.Answers) {
		x.t.Fatalf("line %d: %d requests, %d answers", line, len(tg.Requests), len(tg.Answers))
	}
	statuses := make([]int, len(tg.Requests))
	answers := make([][]byte, len(tg.Requests))
	var wg sync.WaitGroup
	for i, req := range tg.Requests {
		wg.Go(func() { statuses[i], answers[i] = x.send(line, req) })
	}
	wg.Wait()
	for _, perm := range permutations(len(tg.Answers)) {
		ok := true
		for i, j := range perm {
			if len(x.matches(tg.Answers[j], statuses[i], answers[i], false)) > 0 {
				ok = false
				break
			}
		}
		if ok {
			for i, j := range perm {
				x.matches(tg.Answers[j], statuses[i], answers[i], true)
			}
			return
		}
	}
	x.missf("line %d: no order of the answers %d %q matches the expected ones", line, statuses, answers)
}

func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var out [][]int
	for _, p := range permutations(n - 1) {
		for i := 0; i <= len(p); i++ {
			out = append(out, slices.Insert(slices.Clone(p), i, n-1))
		}
	}
	return out
}

// compareTrail holds every event the sink kept to the case's trail: its kind,
// a decision's reason codes, a result's status and protocol status.
func (x *exchange) compareTrail(want trailFile) {
	var got []string
	for _, e := range x.r.sink.Events() {
		got = append(got, summarize(e))
	}
	var exp []string
	for _, e := range want.Events {
		text, err := json.Marshal(e)
		if err != nil {
			x.t.Fatal(err)
		}
		exp = append(exp, string(text))
	}
	if want.Unordered {
		slices.Sort(got)
		slices.Sort(exp)
	}
	if !slices.Equal(got, exp) {
		x.missf("trail\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(exp, "\n      "))
	}
}

func summarize(e *controlv1.Event) string {
	s := trailedEvent{Kind: e.GetKind().String()}
	switch {
	case e.GetDecision() != nil:
		codes := append([]string{}, e.GetDecision().GetReasonCodes()...)
		s.Codes = &codes
	case e.GetResult() != nil:
		code := e.GetResult().GetToolProtocolStatus()
		s.Status, s.Code = e.GetResult().GetStatus().String(), &code
	}
	text, err := json.Marshal(s)
	if err != nil {
		return err.Error()
	}
	return string(text)
}
