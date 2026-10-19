package hookbridge_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/guardana/control/adapters/enforce"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/enforceclient"
	"github.com/guardana/control/internal/hookbridge"
	"github.com/guardana/control/internal/policy/strictjson"
)

// profileSuite is a built-in profile with the expectations its cases.json
// states for each of its fixtures, written apart from the profile so a wrong
// member, phase or bound in the profile fails a case.
type profileSuite struct {
	dir                string
	profile            *hookbridge.Profile
	BlockExitCode      int         `json:"block_exit_code"`
	ProblemExitCode    int         `json:"problem_exit_code"`
	HookTimeoutSeconds int         `json:"hook_timeout_seconds"`
	MaxEventBytes      int64       `json:"max_event_bytes"`
	BoundFrom          string      `json:"bound_from"`
	Tools              []suiteTool `json:"tools"`
	Cases              casesByName `json:"cases"`
}

type suiteTool struct {
	Name         string `json:"name"`
	Effect       string `json:"effect"`
	ResourceType string `json:"resource_type"`
	ResourceFrom string `json:"resource_from"`
}

// fixtureCase is what one fixture must come to: a refusal by ReadEvent, an
// admit under a policy, or a completion after the admit it names.
type fixtureCase struct {
	Refused  string `json:"refused"`
	Input    string `json:"input"`
	Policy   string `json:"policy"`
	Allow    bool   `json:"allow"`
	Reason   string `json:"reason"`
	After    string `json:"after"`
	Closing  string `json:"closing"`
	Status   string `json:"status"`
	Protocol string `json:"protocol"`
}

type casesByName map[string]fixtureCase

// UnmarshalJSON refuses a case named twice, which a map would keep only once.
func (c *casesByName) UnmarshalJSON(raw []byte) error {
	o, err := strictjson.ReadObject(raw)
	if err != nil {
		return err
	}
	*c = casesByName{}
	for name, v := range o {
		var fc fixtureCase
		dec := json.NewDecoder(bytes.NewReader(v))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fc); err != nil {
			return errors.New(name + ": " + err.Error())
		}
		(*c)[name] = fc
	}
	return nil
}

var refusals = map[string]error{
	"malformed":        hookbridge.ErrEventMalformed,
	"encoding":         hookbridge.ErrEventEncoding,
	"unknown-event":    hookbridge.ErrUnknownEvent,
	"no-call-id":       hookbridge.ErrNoCallID,
	"no-session":       hookbridge.ErrNoSession,
	"no-input":         hookbridge.ErrNoInput,
	"input-not-object": hookbridge.ErrInputNotObject,
}

var closings = map[string]controlv1.EventKind{"completed": kindDone, "failed": kindFailed}

var statuses = map[string]controlv1.ResultStatus{"success": statusSuccess, "failure": statusFailure, "unknown": statusUnknown}

// suites returns every built-in profile that keeps a cases.json, and fails
// when there is none, so the suite never passes over nothing.
func suites(t *testing.T) []*profileSuite {
	t.Helper()
	paths, err := filepath.Glob("profiles/*/cases.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no built-in profile keeps cases: %v", err)
	}
	var out []*profileSuite
	for _, path := range paths {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: a file this package keeps
		if err != nil {
			t.Fatal(err)
		}
		s := &profileSuite{dir: filepath.Dir(path)}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(s); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if s.profile, err = hookbridge.LoadProfile(filepath.Base(s.dir)); err != nil {
			t.Fatalf("%s: %v", s.dir, err)
		}
		out = append(out, s)
	}
	return out
}

func (s *profileSuite) fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.dir, "fixtures", name+".json")) //nolint:gosec // G304: a fixture this package keeps
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEveryFixtureHasACase(t *testing.T) {
	for _, s := range suites(t) {
		paths, err := filepath.Glob(filepath.Join(s.dir, "fixtures", "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		var names, cases []string
		for _, p := range paths {
			names = append(names, strings.TrimSuffix(filepath.Base(p), ".json"))
		}
		for name := range s.Cases {
			cases = append(cases, name)
		}
		slices.Sort(names)
		slices.Sort(cases)
		if len(names) == 0 || !slices.Equal(names, cases) {
			t.Errorf("%s: fixtures %v\ncases %v", s.dir, names, cases)
		}
	}
}

func TestEachFixtureReadsAsItsCaseSays(t *testing.T) {
	for _, s := range suites(t) {
		for name, tc := range s.Cases {
			raw := s.fixture(t, name)
			ev, err := hookbridge.ReadEvent(s.profile, bytes.NewReader(raw))
			want, known := refusals[tc.Refused]
			switch {
			case tc.Refused != "":
				if !known || !errors.Is(err, want) {
					t.Errorf("%s/%s: %v, want refusal %q", s.dir, name, err, tc.Refused)
				}
			case err != nil:
				t.Errorf("%s/%s: %v", s.dir, name, err)
			case !bytes.Contains(raw, []byte(tc.Input)) || string(ev.Input) != tc.Input:
				t.Errorf("%s/%s: read the input %s", s.dir, name, ev.Input)
			case (ev.Phase == hookbridge.PhaseAdmit) != (tc.After == ""):
				t.Errorf("%s/%s: read as phase %s", s.dir, name, ev.Phase)
			}
		}
	}
}

// argSpy keeps the bytes each admit proposed.
type argSpy struct {
	hookbridge.Client
	mu       sync.Mutex
	proposed [][]byte
}

func (a *argSpy) Admit(ctx context.Context, tool string, args []byte, key string, carry enforceclient.Carry) (enforceclient.Answer, enforceclient.Admission, enforcev1alpha1.AbortCause, error) {
	a.mu.Lock()
	a.proposed = append(a.proposed, bytes.Clone(args))
	a.mu.Unlock()
	return a.Client.Admit(ctx, tool, args, key, carry)
}

// plane serves the suite's tools under policy: allow lets every tool run,
// deny blocks tool and approve holds it for approval.
func (s *profileSuite) plane(t *testing.T, policy, tool string) (*env, *argSpy) {
	t.Helper()
	o := planeOptions{}
	var names []string
	for _, st := range s.Tools {
		effect, ok := controlv1.EffectClass_value["EFFECT_CLASS_"+st.Effect]
		if !ok {
			t.Fatalf("%s: tool %s has no effect class %q", s.dir, st.Name, st.Effect)
		}
		o.tools = append(o.tools, enforce.Tool{Name: st.Name, Effect: controlv1.EffectClass(effect), Provider: "runtime", ResourceType: st.ResourceType, ResourceFrom: st.ResourceFrom})
		names = append(names, st.Name)
	}
	quoted, err := json.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	switch policy {
	case "allow":
		o.rules = []string{`{"id":"allow-tools","effect":"ALLOW","when":{"action":{"name":` + string(quoted) + `}}}`}
	case "deny":
		o.rules = []string{`{"id":"deny-tool","effect":"DENY","when":{"action":{"name":["` + tool + `"]}}}`}
	case "approve":
		o.mode = controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE
		o.rules = []string{`{"id":"hold-tool","effect":"REQUIRE_APPROVAL","when":{"action":{"name":["` + tool + `"]}}}`}
	default:
		t.Fatalf("%s: no policy %q", s.dir, policy)
	}
	e := setup(t, reference(), o)
	e.p = s.profile
	spy := &argSpy{Client: e.c.inner}
	e.c.inner = spy
	return e, spy
}

func TestEachAdmitFixtureAgainstThePlane(t *testing.T) {
	for _, s := range suites(t) {
		for name, tc := range s.Cases {
			if tc.Refused == "" && tc.After == "" {
				for _, m := range s.admitMisses(t, name, tc) {
					t.Errorf("%s/%s: %s", s.dir, name, m)
				}
			}
		}
	}
}

// admitMisses runs the admit fixture name under its case's policy and
// returns every way the outcome, the bytes proposed or the trail departed
// from the case.
func (s *profileSuite) admitMisses(t *testing.T, name string, tc fixtureCase) []string {
	raw := s.fixture(t, name)
	ev, err := hookbridge.ReadEvent(s.profile, bytes.NewReader(raw))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	e, spy := s.plane(t, tc.Policy, ev.Tool)
	out, err := e.pre(string(raw))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	check(&miss, out.Allow != tc.Allow || !strings.HasPrefix(out.Reason, tc.Reason) || out.Allow && out.Reason != "",
		"%+v, want allow %v and a reason starting %q", out, tc.Allow, tc.Reason)
	check(&miss, len(spy.proposed) != 1 || string(spy.proposed[0]) != tc.Input, "proposed %q, want the fixture's tool input", spy.proposed)
	started := slices.Contains(e.pl.kinds(), kindStarted)
	check(&miss, started != tc.Allow || (e.entries() == 1) != tc.Allow, "started %v with %d entries, want allow %v", started, e.entries(), tc.Allow)
	return miss
}

func TestEachCompletionFixtureAgainstThePlane(t *testing.T) {
	for _, s := range suites(t) {
		for name, tc := range s.Cases {
			if tc.After != "" {
				for _, m := range s.completionMisses(t, name, tc) {
					t.Errorf("%s/%s: %s", s.dir, name, m)
				}
			}
		}
	}
}

// completionMisses runs the admit the completion fixture name follows, then
// the completion, and returns every way what was sent or the closing record
// departed from the case.
func (s *profileSuite) completionMisses(t *testing.T, name string, tc fixtureCase) []string {
	kind, okKind := closings[tc.Closing]
	status, okStatus := statuses[tc.Status]
	if !okKind || !okStatus {
		return []string{fmt.Sprintf("no closing %q or status %q", tc.Closing, tc.Status)}
	}
	e, _ := s.plane(t, "allow", "")
	if out, err := e.pre(string(s.fixture(t, tc.After))); err != nil || !out.Allow {
		return []string{fmt.Sprintf("the admit %s: %v %+v", tc.After, err, out)}
	}
	out, err := e.post(string(s.fixture(t, name)))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	_, completes, aborts := e.c.sent()
	check(&miss, out.Result != hookbridge.PostRecorded || completes != 1 || len(aborts) != 0 || e.entries() != 0,
		"%+v, %d completes, aborts %v, %d entries", out, completes, aborts, e.entries())
	return append(miss, e.wantClosing(kind, status, tc.Protocol)...)
}
