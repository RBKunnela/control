package enforce_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/guardana/control/adapters/enforce"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// defect is a receiver that breaks one rule of the contract: a different
// mode, configuration, run directory, tool table or pipeline behind the same
// adapter, or a transport that alters a request before the adapter reads it.
// Each case's negative control names one, and the case has to fail under it.
type defect struct {
	mode     controlv1.EnforcementMode
	adapter  func(*enforce.Config)
	pipeline func(enforce.Pipeline) enforce.Pipeline
	resolver func(gateway.RunResolver) gateway.RunResolver
	tools    func([]enforce.Tool) []enforce.Tool
	request  func(path, token, body string, tokens map[string]string) (string, string, string)
	noSweep  bool
}

// mutant is a pipeline whose operations a defect replaces one at a time.
type mutant struct {
	enforce.Pipeline
	admit    func(context.Context, gateway.Admission) gateway.Disposition
	closeRep func(context.Context, gateway.Disposition, []byte, *controlv1.ActionResult) error
	abort    func(context.Context, gateway.Disposition, gateway.AbortCause) error
}

func (m *mutant) Admit(ctx context.Context, a gateway.Admission) gateway.Disposition {
	if m.admit != nil {
		return m.admit(ctx, a)
	}
	return m.Pipeline.Admit(ctx, a)
}

func (m *mutant) CloseReported(ctx context.Context, d gateway.Disposition, sent []byte, res *controlv1.ActionResult) error {
	if m.closeRep != nil {
		return m.closeRep(ctx, d, sent, res)
	}
	return m.Pipeline.CloseReported(ctx, d, sent, res)
}

func (m *mutant) Abort(ctx context.Context, d gateway.Disposition, cause gateway.AbortCause) error {
	if m.abort != nil {
		return m.abort(ctx, d, cause)
	}
	return m.Pipeline.Abort(ctx, d, cause)
}

func mutate(edit func(m *mutant)) func(enforce.Pipeline) enforce.Pipeline {
	return func(p enforce.Pipeline) enforce.Pipeline {
		m := &mutant{Pipeline: p}
		edit(m)
		return m
	}
}

// recordAs closes every reported execution with its status replaced.
func recordAs(from, to controlv1.ResultStatus) func(enforce.Pipeline) enforce.Pipeline {
	return mutate(func(m *mutant) {
		m.closeRep = func(ctx context.Context, d gateway.Disposition, sent []byte, res *controlv1.ActionResult) error {
			if res.GetStatus() == from {
				res = proto.CloneOf(res)
				res.Status = to
			}
			return m.Pipeline.CloseReported(ctx, d, sent, res)
		}
	})
}

// replayer hands a blocked admit the execution another admit of the same
// bytes was handed, waiting a moment for one when the block came first.
type replayer struct {
	mu   sync.Mutex
	cond *sync.Cond
	last map[string]gateway.Disposition
}

func replaysExecute() func(enforce.Pipeline) enforce.Pipeline {
	rp := &replayer{last: map[string]gateway.Disposition{}}
	rp.cond = sync.NewCond(&rp.mu)
	return mutate(func(m *mutant) {
		m.admit = func(ctx context.Context, a gateway.Admission) gateway.Disposition {
			d := m.Pipeline.Admit(ctx, a)
			key := string(a.Arguments)
			rp.mu.Lock()
			defer rp.mu.Unlock()
			if d.Action == core.Execute {
				rp.last[key] = d
				rp.cond.Broadcast()
				return d
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				if prior, ok := rp.last[key]; ok {
					return prior
				}
				if time.Now().After(deadline) {
					return d
				}
				go func() { time.Sleep(10 * time.Millisecond); rp.cond.Broadcast() }()
				rp.cond.Wait()
			}
		}
	})
}

// anyIdentity resolves a token whoever its run is for, closed or not, as a
// directory that checks neither would.
type anyIdentity struct {
	runs        *fakeRuns
	checkClosed bool
}

func (a anyIdentity) Resolve(_ context.Context, token string, _ gateway.RunIdentity, _ time.Time) (gateway.OpenedRun, error) {
	a.runs.mu.Lock()
	defer a.runs.mu.Unlock()
	r, ok := a.runs.tokens[token]
	if !ok || (a.checkClosed && r.closed) {
		return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunUnknown}
	}
	run := r.run
	run.Who = listenerWho()
	return run, nil
}

// oneRun resolves every listener token as run a, as a receiver that tells no
// run from another would.
type oneRun struct{ inner gateway.RunResolver }

func (o oneRun) Resolve(ctx context.Context, _ string, who gateway.RunIdentity, now time.Time) (gateway.OpenedRun, error) {
	return o.inner.Resolve(ctx, runA, who, now)
}

var anyVersion = regexp.MustCompile(`^/enforce/[^/]+/`)

var admitMembers = []string{"tool", "arguments", "requestKey", "request_key", "traceparent"}

func editBody(body string, edit func(map[string]any)) string {
	var m map[string]any
	if json.Unmarshal([]byte(body), &m) != nil {
		return body
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return string(out)
}

func defects() map[string]defect {
	return map[string]defect{
		"enforces-nothing": {mode: controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE},
		"hands-out-proposed-bytes": {pipeline: mutate(func(m *mutant) {
			m.admit = func(ctx context.Context, a gateway.Admission) gateway.Disposition {
				d := m.Pipeline.Admit(ctx, a)
				if d.AuthorizedArgs != nil {
					d.AuthorizedArgs = a.Arguments
				}
				return d
			}
		})},
		"binds-each-request-anew": {pipeline: mutate(func(m *mutant) {
			m.admit = func(ctx context.Context, a gateway.Admission) gateway.Disposition {
				if a.Envelope.GetResource() != nil {
					a.Envelope.Resource.Id += "#" + a.Envelope.GetRequestId()
				}
				return m.Pipeline.Admit(ctx, a)
			}
		})},
		"replays-an-execute": {pipeline: replaysExecute()},
		"ignores-request-keys": {request: func(path, token, body string, _ map[string]string) (string, string, string) {
			return path, token, editBody(body, func(m map[string]any) { delete(m, "requestKey") })
		}},
		"never-sweeps":         {noSweep: true},
		"handles-never-expire": {adapter: func(c *enforce.Config) { c.Clock = base }},
		"tells-no-run-from-another": {resolver: func(inner gateway.RunResolver) gateway.RunResolver {
			return oneRun{inner}
		}},
		"keeps-one-spent-handle": {adapter: func(c *enforce.Config) { c.MaxSpent = 1 }},
		"token-optional": {request: func(path, token, body string, tokens map[string]string) (string, string, string) {
			if token == "" {
				token = tokens["a"]
			}
			return path, token, body
		}},
		"ignores-run-identity": {resolver: func(inner gateway.RunResolver) gateway.RunResolver {
			return anyIdentity{runs: inner.(*fakeRuns), checkClosed: true}
		}},
		"ignores-closed-runs": {resolver: func(inner gateway.RunResolver) gateway.RunResolver {
			return anyIdentity{runs: inner.(*fakeRuns)}
		}},
		"ignores-result-labels": {tools: func(tools []enforce.Tool) []enforce.Tool {
			for i := range tools {
				tools[i].ReturnsTrust = controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL
				tools[i].ReturnsSensitivity = controlv1.Sensitivity_SENSITIVITY_PUBLIC
			}
			return tools
		}},
		"classifies-every-tool": {tools: func(tools []enforce.Tool) []enforce.Tool {
			return append(tools, enforce.Tool{Name: "drop_database", Provider: "db", Classification: classify.Classification{Effect: effectRead, ResourceType: "database"}})
		}},
		"lenient-decoding": {request: func(path, token, body string, _ map[string]string) (string, string, string) {
			return path, token, editBody(body, func(m map[string]any) {
				for k := range m {
					if !slices.Contains(admitMembers, k) {
						delete(m, k)
					}
				}
			})
		}},
		"any-version": {request: func(path, token, body string, _ map[string]string) (string, string, string) {
			return anyVersion.ReplaceAllString(path, "/enforce/v1alpha1/"), token, body
		}},
		"records-an-uncertain-effect-as-failed": {pipeline: recordAs(controlv1.ResultStatus_RESULT_STATUS_TIMEOUT, controlv1.ResultStatus_RESULT_STATUS_FAILURE)},
		"records-a-cancel-as-success":           {pipeline: recordAs(controlv1.ResultStatus_RESULT_STATUS_CANCELLED, controlv1.ResultStatus_RESULT_STATUS_SUCCESS)},
		"records-not-sent-as-a-mismatch": {pipeline: mutate(func(m *mutant) {
			m.abort = func(ctx context.Context, d gateway.Disposition, _ gateway.AbortCause) error {
				return m.Pipeline.Abort(ctx, d, gateway.AbortArgsMismatch)
			}
		})},
		"answers-without-recording": {pipeline: mutate(func(m *mutant) {
			m.closeRep = func(context.Context, gateway.Disposition, []byte, *controlv1.ActionResult) error { return nil }
		})},
		"halts-the-plane": {pipeline: mutate(func(m *mutant) {
			m.closeRep = func(ctx context.Context, d gateway.Disposition, sent []byte, res *controlv1.ActionResult) error {
				return m.Pipeline.(*gateway.Pipeline).Close(ctx, d, sent, res)
			}
		})},
		"hands-out-advisory-obligations": {pipeline: mutate(func(m *mutant) {
			m.admit = func(ctx context.Context, a gateway.Admission) gateway.Disposition {
				d := m.Pipeline.Admit(ctx, a)
				for i, ob := range d.Obligations {
					ob = proto.CloneOf(ob)
					ob.Advisory = false
					d.Obligations[i] = ob
				}
				return d
			}
		})},
	}
}

func TestTheReceiverPassesEveryCase(t *testing.T) {
	for _, c := range receiverCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			for _, m := range runReceiverCase(t, c.ID, defect{}) {
				t.Error(m)
			}
		})
	}
}

func TestEveryReceiverCaseFailsUnderItsNegativeControl(t *testing.T) {
	all := defects()
	for _, c := range receiverCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			d, ok := all[c.NegativeControl.Defect]
			if !ok {
				t.Fatalf("no defect %q", c.NegativeControl.Defect)
			}
			if miss := runReceiverCase(t, c.ID, d); len(miss) == 0 {
				t.Fatalf("a receiver that %s passed", c.NegativeControl.Breaks)
			}
		})
	}
}

func TestTheReceiverCasesAgreeWithTheirIndex(t *testing.T) {
	cases := receiverCases(t)
	var listed []string
	for _, c := range cases {
		if c.Contract != "v1alpha1" || c.Rule == "" || c.NegativeControl.Defect == "" || c.NegativeControl.Breaks == "" {
			t.Errorf("%s: needs contract v1alpha1, a rule and a negative control: %+v", c.ID, c)
		}
		listed = append(listed, c.ID)
	}
	entries, err := os.ReadDir(filepath.Join(casesDir, "receiver"))
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	slices.Sort(listed)
	if !slices.Equal(listed, dirs) {
		t.Errorf("cases.json lists %v, receiver/ holds %v", listed, dirs)
	}
	for _, id := range []string{
		"block-before-send", "rewritten-bytes", "pending-then-resume", "concurrent-resumes",
		"timeout-before-send", "timeout-after-send", "cancellation", "completion", "duplicate-request-key",
		"abandoned-handle", "expired-handle", "foreign-handle", "spent-handle", "missing-run-token",
		"foreign-run-token", "unclassified-tool", "unknown-field", "unknown-version",
	} {
		if !slices.Contains(listed, id) {
			t.Errorf("no receiver case %s, which ADR-0051 lists", id)
		}
	}
}
