package enforceclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/enforceclient"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The one call every vector runs under.
const (
	vectorTool      = "refund"
	vectorArguments = `{"amount":10,"to":"acct-7"}`
	vectorToken     = "run-token-1"
)

var operationPaths = map[string]string{
	"admit":    enforceclient.PathAdmit,
	"complete": enforceclient.PathComplete,
	"abort":    enforceclient.PathAbort,
}

// vector is one line of answers/vectors.jsonl: an answer to one operation
// and how a client reads it.
type vector struct {
	ID        string       `json:"id"`
	For       string       `json:"for"`
	Status    int          `json:"status"`
	Raw       *string      `json:"raw"`
	RawRepeat []rawPart    `json:"raw_repeat"`
	Class     string       `json:"class"`
	Expect    vectorExpect `json:"expect"`
}

// rawPart is one piece of a body written as its pieces: a text and how many
// times it stands, so a body at the bound is a line and not a megabyte.
type rawPart struct {
	Text  string `json:"text"`
	Times int    `json:"times"`
}

// maxVectorBody bounds a body a vector spells out by repetition.
const maxVectorBody = 1 << 20

// body returns the vector's answer body: raw, or raw_repeat's parts joined.
// Exactly one of the two is allowed.
func (v vector) body() (string, error) {
	switch {
	case (v.Raw == nil) == (v.RawRepeat == nil):
		return "", errors.New("needs exactly one of raw and raw_repeat")
	case v.Raw != nil:
		return *v.Raw, nil
	}
	var b strings.Builder
	for _, p := range v.RawRepeat {
		if p.Text == "" || p.Times < 1 || b.Len()+len(p.Text)*p.Times > maxVectorBody {
			return "", fmt.Errorf("raw_repeat part %q times %d", p.Text, p.Times)
		}
		b.WriteString(strings.Repeat(p.Text, p.Times))
	}
	return b.String(), nil
}

type vectorExpect struct {
	ToolReached  *bool    `json:"tool_reached"`
	ToolReceived *string  `json:"tool_received"`
	Requests     []string `json:"requests"`
	Returns      string   `json:"returns"`
	Code         string   `json:"code"`
	Ending       string   `json:"ending"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(casesDir, "answers", "vectors.jsonl")))
	if err != nil {
		t.Fatalf("reading the vectors: %v", err)
	}
	var out []vector
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		var v vector
		if err := strictJSON(line, &v); err != nil {
			t.Fatalf("vector %d: %v", i+1, err)
		}
		body, err := v.body()
		if err != nil || v.Expect.ToolReached == nil {
			t.Fatalf("vector %d (%s): needs a body and expect.tool_reached: %v", i+1, v.ID, err)
		}
		v.Raw, v.RawRepeat = &body, nil
		out = append(out, v)
	}
	return out
}

func findVector(t *testing.T, vectors []vector, id string) vector {
	t.Helper()
	i := slices.IndexFunc(vectors, func(v vector) bool { return v.ID == id })
	if i < 0 {
		t.Fatalf("no vector %s", id)
	}
	return vectors[i]
}

// vectorScript is the receiver's script for v: the vector itself, after the
// admit answer of the case that leads a client to v's operation.
func vectorScript(t *testing.T, v vector) []scripted {
	t.Helper()
	own := answer(operationPaths[v.For], v.Status, *v.Raw)
	switch v.For {
	case "admit":
		return []scripted{own}
	case "complete":
		return []scripted{loadAnswers(t, filepath.Join(casesDir, "client", "execute-plain"))[0], own}
	case "abort":
		return []scripted{loadAnswers(t, filepath.Join(casesDir, "client", "unknown-obligation"))[0], own}
	}
	t.Fatalf("%s: for %q", v.ID, v.For)
	return nil
}

// scaffold serves a vector's script. A redirect carries a Location, so that
// a client that follows one is seen to; and what a client sends after an
// admit vector is answered as recorded, so that a client that wrongly goes
// on is not stopped by the receiver.
type scaffold struct {
	*receiver
	own      int
	redirect bool
	goesOn   bool
}

func (s *scaffold) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	n := s.next
	if s.goesOn && n == len(s.answers) {
		s.answers = append(s.answers, answer(req.URL.Path, http.StatusOK, recorded))
	}
	s.mu.Unlock()
	if s.redirect && n == s.own {
		w.Header().Set("Location", enforceclient.PathAdmit)
	}
	s.receiver.ServeHTTP(w, req)
}

// runVector makes the vectors' call through mk and returns every way the
// client departed from v's expectation; none means it read v as expected.
func runVector(t *testing.T, mk newCaller, v vector) []string {
	t.Helper()
	script := vectorScript(t, v)
	r := &receiver{answers: script, cancel: func() {}}
	s := &scaffold{receiver: r, own: len(script) - 1, redirect: v.Status/100 == 3, goesOn: v.For == "admit"}
	c := mk(t, serve(t, s), vectorToken)

	var reached bool
	var received []byte
	a, err := c(context.Background(), vectorTool, []byte(vectorArguments), func(_ context.Context, authorized []byte) (enforceclient.Result, error) {
		reached, received = true, slices.Clone(authorized)
		return enforceclient.Result{Status: enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS}, nil
	})

	e := v.Expect
	var miss []string
	if reached != *e.ToolReached {
		miss = append(miss, fmt.Sprintf("tool reached %v, want %v", reached, *e.ToolReached))
	}
	if e.ToolReceived != nil && string(received) != *e.ToolReceived {
		miss = append(miss, fmt.Sprintf("tool received %q, want %q", received, *e.ToolReceived))
	}
	miss = append(miss, sentMisses(r.requests(), e.Requests)...)
	return append(miss, returnMisses(a, err, e)...)
}

func sentMisses(got []gotRequest, want []string) []string {
	var miss, sent []string
	for i, g := range got {
		op := g.path
		for name, path := range operationPaths {
			if path == g.path {
				op = name
			}
		}
		sent = append(sent, op)
		if g.token != vectorToken {
			miss = append(miss, fmt.Sprintf("request %d presented another run token", i+1))
		}
	}
	if !slices.Equal(sent, want) {
		miss = append(miss, fmt.Sprintf("sent %v, want %v", sent, want))
	}
	return miss
}

// declared is the name of enum number n, or nothing for UNSPECIFIED and for
// a number the contract does not declare: a vector names only what a client
// in any language can.
func declared(names map[int32]string, n int32) string {
	if n == 0 {
		return ""
	}
	return names[n]
}

// vectorKind is what the call told its caller, in expect.json's words, and
// the refusal's code. An abort stays an abort when the receiver refuses it.
func vectorKind(err error) (string, string) {
	kind, _ := errorKind(err)
	if kind == "refused" && errors.Is(err, enforceclient.ErrAborted) {
		kind = "aborted"
	}
	var refusal *enforceclient.RefusalError
	if !errors.As(err, &refusal) {
		return kind, ""
	}
	return kind, declared(enforcev1alpha1.ErrorCode_name, int32(refusal.Code))
}

func returnMisses(a enforceclient.Answer, err error, e vectorExpect) []string {
	var miss []string
	kind, code := vectorKind(err)
	if kind != e.Returns {
		miss = append(miss, fmt.Sprintf("returned %s (%v), want %s", kind, err, e.Returns))
	}
	if code != e.Code {
		miss = append(miss, fmt.Sprintf("code %q, want %q", code, e.Code))
	}
	if ending := declared(enforcev1alpha1.Ending_name, int32(a.Ending)); ending != e.Ending {
		miss = append(miss, fmt.Sprintf("ending %q, want %q", ending, e.Ending))
	}
	return miss
}

var vectorID = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// shapeProblems holds a vector to the format: known words, and the requests
// its operation allows.
func shapeProblems(v vector) []string {
	var p []string
	e := v.Expect
	if !vectorID.MatchString(v.ID) {
		p = append(p, fmt.Sprintf("id %q is not kebab-case", v.ID))
	}
	if !slices.Contains([]string{"read", "refused", "may_refuse"}, v.Class) {
		p = append(p, fmt.Sprintf("class %q", v.Class))
	}
	if !slices.Contains([]string{"none", "blocked", "pending", "refused", "aborted", "not_recorded", "malformed_answer", "tool_error"}, e.Returns) {
		p = append(p, fmt.Sprintf("returns %q", e.Returns))
	}
	if v.Status < 100 || v.Status > 599 {
		p = append(p, fmt.Sprintf("status %d", v.Status))
	}
	allowed := map[string][][]string{
		"admit":    {{"admit"}, {"admit", "complete"}, {"admit", "abort"}},
		"complete": {{"admit", "complete"}},
		"abort":    {{"admit", "abort"}},
	}
	sequences, known := allowed[v.For]
	if !known {
		return append(p, fmt.Sprintf("for %q", v.For))
	}
	if !slices.ContainsFunc(sequences, func(s []string) bool { return slices.Equal(s, e.Requests) }) {
		p = append(p, fmt.Sprintf("requests %v do not follow an answer to %s", e.Requests, v.For))
	}
	return p
}

// senseProblems holds a vector's expectation to what a call can do: the tool
// is reached exactly when a complete follows, and a refused answer is a
// malformed one that stops the call.
func senseProblems(v vector) []string {
	var p []string
	e := v.Expect
	reached := *e.ToolReached
	if reached != slices.Contains(e.Requests, "complete") {
		p = append(p, "the tool is reached exactly when a complete is sent")
	}
	if reached != (e.ToolReceived != nil) {
		p = append(p, "tool_received goes with a reached tool, and only with one")
	}
	if (v.Class == "refused") != (e.Returns == "malformed_answer") {
		p = append(p, "class refused and returns malformed_answer go together")
	}
	if e.Returns == "malformed_answer" && len(e.Requests) > 0 && e.Requests[len(e.Requests)-1] != v.For {
		p = append(p, "a malformed answer is the last one the call asks for")
	}
	return p
}

// nameProblems holds a code and an ending to a declared name, on an outcome
// that can carry it.
func nameProblems(v vector) []string {
	var p []string
	e := v.Expect
	if e.Code != "" && (enforcev1alpha1.ErrorCode_value[e.Code] == 0 || !slices.Contains([]string{"refused", "aborted"}, e.Returns)) {
		p = append(p, fmt.Sprintf("code %q on returns %s", e.Code, e.Returns))
	}
	if e.Ending != "" && (enforcev1alpha1.Ending_value[e.Ending] == 0 || len(e.Requests) < 2) {
		p = append(p, fmt.Sprintf("ending %q after requests %v", e.Ending, e.Requests))
	}
	return p
}

func TestTheAnswerVectorsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	held := map[string]int{}
	for _, v := range loadVectors(t) {
		if seen[v.ID] {
			t.Errorf("%s: listed twice", v.ID)
		}
		seen[v.ID] = true
		held[v.For+" "+v.Class]++
		for _, p := range slices.Concat(shapeProblems(v), senseProblems(v), nameProblems(v)) {
			t.Errorf("%s: %s", v.ID, p)
		}
	}
	for _, kind := range []string{
		"admit read", "admit refused", "admit may_refuse",
		"complete read", "complete refused", "complete may_refuse",
		"abort read", "abort refused", "abort may_refuse",
	} {
		if held[kind] == 0 {
			t.Errorf("no vector of kind %q", kind)
		}
	}
}

func TestTheReferenceClientReadsTheAnswerVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			for _, m := range runVector(t, referenceClient, v) {
				t.Error(m)
			}
		})
	}
}

func TestTheMutantWithoutADefectReadsTheAnswerVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			for _, m := range runVector(t, newMutant(""), v) {
				t.Error(m)
			}
		})
	}
}

func TestTheMutantThatDecodesLenientlyFailsAVector(t *testing.T) {
	vectors := loadVectors(t)
	for id, want := range map[string]string{
		"admit-undeclared-member":               "tool reached true, want false",
		"admit-undeclared-member-in-execution":  "tool reached true, want false",
		"admit-undeclared-member-in-decision":   "tool reached true, want false",
		"admit-undeclared-member-in-obligation": "sent [admit abort], want [admit]",
		"admit-undeclared-member-in-pending":    "returned pending",
		"admit-outcome-undeclared-name":         "returned blocked",
		"complete-undeclared-member":            "returned none",
		"abort-undeclared-member":               "returned aborted",
	} {
		t.Run(id, func(t *testing.T) {
			v := findVector(t, vectors, id)
			if v.Class != "refused" {
				t.Fatalf("class %s, want a refused vector", v.Class)
			}
			miss := runVector(t, newMutant("lenient-decoding"), v)
			if !slices.ContainsFunc(miss, func(m string) bool { return strings.HasPrefix(m, want) }) {
				t.Fatalf("a client that discards members it does not know departs by %q, want %q", miss, want)
			}
		})
	}
}

func TestTheMutantThatReadsAnyDecisionVersionFailsAVector(t *testing.T) {
	vectors := loadVectors(t)
	for _, id := range []string{"admit-execute-decision-of-another-major", "admit-execute-decision-of-an-unread-version", "admit-execute-decision-with-no-version"} {
		t.Run(id, func(t *testing.T) {
			v := findVector(t, vectors, id)
			if v.Class != "refused" {
				t.Fatalf("class %s, want a refused vector", v.Class)
			}
			miss := runVector(t, newMutant("reads-any-decision-version"), v)
			if !slices.ContainsFunc(miss, func(m string) bool { return strings.HasPrefix(m, "tool reached true, want false") }) {
				t.Fatalf("a client that reads a decision of any version departs by %q", miss)
			}
		})
	}
}

func at(t *testing.T, text string) *timestamppb.Timestamp {
	t.Helper()
	when, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		t.Fatal(err)
	}
	return timestamppb.New(when)
}

// fullDecision is a Decision with every member set.
func fullDecision(t *testing.T, verdict controlv1.Verdict, reasons ...string) *controlv1.Decision {
	t.Helper()
	return &controlv1.Decision{
		SchemaVersion:      "1.0",
		DecisionId:         "d-1",
		RequestId:          "req-1",
		ActionDigest:       "sha256:9f2c",
		PolicyBundleDigest: "sha256:41d0",
		PolicyRuleIds:      []string{"refunds.small", "refunds.audited"},
		Verdict:            verdict,
		ReasonCodes:        reasons,
		Obligations:        []*controlv1.Obligation{{Type: "emit_alert", Params: map[string]string{"channel": "ops"}, Advisory: true}},
		ExpiresAt:          at(t, "2026-10-11T12:05:00Z"),
		DecisionLatencyUs:  1234,
		PdpType:            "builtin",
		PdpInstance:        "pdp-0",
		PdpVersion:         "0.11.0",
		EnforcementMode:    controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		PolicyFreshness:    controlv1.PolicyFreshness_POLICY_FRESHNESS_FRESH,
		PolicyLoadedAt:     at(t, "2026-10-11T11:00:00.123456789Z"),
		DecidedAt:          at(t, "2026-10-11T12:00:00.987654321Z"),
	}
}

func fullExecution(t *testing.T, obligations ...*controlv1.Obligation) *enforcev1alpha1.Execution {
	t.Helper()
	return &enforcev1alpha1.Execution{
		Handle:              "h-1",
		ExpiresAt:           at(t, "2026-10-11T12:05:00Z"),
		AuthorizedArguments: []byte(vectorArguments),
		Obligations:         obligations,
	}
}

// unset names every member that m, or a message of this contract inside it,
// leaves unpopulated.
func unset(m protoreflect.Message, prefix string) []string {
	var out []string
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		name := prefix + fd.JSONName()
		if !m.Has(fd) {
			out = append(out, name)
			continue
		}
		if fd.Message() == nil || fd.IsMap() || strings.HasPrefix(string(fd.Message().FullName()), "google.protobuf.") {
			continue
		}
		if !fd.IsList() {
			out = append(out, unset(m.Get(fd).Message(), name+".")...)
			continue
		}
		list := m.Get(fd).List()
		for j := range list.Len() {
			out = append(out, unset(list.Get(j).Message(), name+".")...)
		}
	}
	return out
}

func TestTheFullAnswerVectorsAreWhatTheReceiverMarshals(t *testing.T) {
	vectors := loadVectors(t)
	for id, tc := range map[string]struct {
		answer *enforcev1alpha1.AdmitResponse
		unset  []string
	}{
		"admit-execute-full": {
			answer: &enforcev1alpha1.AdmitResponse{
				Outcome:   enforcev1alpha1.Outcome_OUTCOME_EXECUTE,
				Decision:  fullDecision(t, controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS, "RULE_ALLOW", "OBLIGATIONS_ATTACHED"),
				Execution: fullExecution(t),
			},
			unset: []string{"execution.obligations", "pending"},
		},
		"admit-execute-full-with-an-obligation": {
			answer: &enforcev1alpha1.AdmitResponse{
				Outcome:   enforcev1alpha1.Outcome_OUTCOME_EXECUTE,
				Decision:  fullDecision(t, controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS, "RULE_ALLOW", "OBLIGATIONS_ATTACHED"),
				Execution: fullExecution(t, &controlv1.Obligation{Type: "shorten_timeout", Params: map[string]string{"ms": "500"}, Advisory: true}),
			},
			unset: []string{"pending"},
		},
		"admit-pending-full": {
			answer: &enforcev1alpha1.AdmitResponse{
				Outcome:  enforcev1alpha1.Outcome_OUTCOME_PENDING,
				Decision: fullDecision(t, controlv1.Verdict_VERDICT_REQUIRE_APPROVAL, "APPROVAL_REQUIRED"),
				Pending: &enforcev1alpha1.Pending{
					ApprovalId:   "ap-1",
					ActionDigest: "sha256:9f2c",
					ExpiresAt:    at(t, "2026-10-11T13:00:00.250Z"),
					RetryAfter:   durationpb.New(1500 * time.Millisecond),
				},
			},
			unset: []string{"execution"},
		},
		"admit-block-full": {
			answer: &enforcev1alpha1.AdmitResponse{
				Outcome:  enforcev1alpha1.Outcome_OUTCOME_BLOCK,
				Decision: fullDecision(t, controlv1.Verdict_VERDICT_DENY, "RULE_DENY", "ACTION_UNCLASSIFIED"),
			},
			unset: []string{"execution", "pending"},
		},
	} {
		t.Run(id, func(t *testing.T) {
			if got := unset(tc.answer.ProtoReflect(), ""); !slices.Equal(got, tc.unset) {
				t.Fatalf("the answer leaves %v unset, want %v", got, tc.unset)
			}
			out, err := protojson.Marshal(tc.answer)
			if err != nil {
				t.Fatal(err)
			}
			var marshalled, raw any
			if err := json.Unmarshal(out, &marshalled); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(*findVector(t, vectors, id).Raw), &raw); err != nil {
				t.Fatalf("the vector's raw: %v", err)
			}
			if !reflect.DeepEqual(marshalled, raw) {
				t.Fatalf("the vector's raw is not what the marshaller writes:\n%s", out)
			}
		})
	}
}
