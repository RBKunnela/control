package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// vetoDocument is the fixture policy with a veto on reads: a read is allowed
// unless the decision point denies it.
const vetoDocument = `{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"gateway-fixture","version":"2026-09-20.1","serial":1,"maxStaleSeconds":600},
  "rules":[
    {"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}},
    {"id":"veto-reads","effect":"DENY","when":{"action":{"effect":["READ"]},"external":{"denies":true}}},
    {"id":"deny-transfers","effect":"DENY","when":{"action":{"effect":["TRANSACT"]}}}
  ]}`

const evaluationPath = "/access/v1/evaluation"

// pdpDouble is an AuthZEN decision point over plaintext on the loopback. It
// answers questions at its evaluation path with answer, and its metadata
// with metadata; a delay, then a hold, make it wait for their end or for the
// asker to give up.
type pdpDouble struct {
	url  string
	eval string

	mu       sync.Mutex
	answer   string
	metadata string
	delay    time.Duration
	hold     chan struct{}
	arrived  chan struct{}
	asked    []*http.Request
}

func newPDPDouble(t *testing.T, answer string) *pdpDouble {
	t.Helper()
	d := &pdpDouble{answer: answer, eval: evaluationPath, arrived: make(chan struct{}, 16)}
	ts := httptest.NewServer(d)
	t.Cleanup(ts.Close)
	d.url = ts.URL
	return d
}

func (d *pdpDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Reading the question through lets the server see the asker give up.
	_, _ = io.Copy(io.Discard, r.Body)
	d.mu.Lock()
	d.asked = append(d.asked, r.Clone(context.Background()))
	answer, metadata, delay, hold := d.answer, d.metadata, d.delay, d.hold
	d.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/.well-known/authzen-configuration") {
		if !wait(r, delay, hold) {
			return
		}
		if metadata == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, metadata) //nolint:gosec // G705: a test double's JSON document, chosen by the test; nothing renders it
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != d.eval {
		http.NotFound(w, r)
		return
	}
	d.arrived <- struct{}{}
	if !wait(r, delay, hold) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", r.Header.Get("X-Request-ID"))
	_, _ = io.WriteString(w, answer) //nolint:gosec // G705: a test double's JSON answer, chosen by the test; nothing renders it
}

// wait holds an answer for delay and then until hold is released, and says
// whether the asker is still there to take it.
func wait(r *http.Request, delay time.Duration, hold chan struct{}) bool {
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return false
		}
	}
	if hold != nil {
		select {
		case <-hold:
		case <-r.Context().Done():
			return false
		}
	}
	return true
}

func (d *pdpDouble) questions() []*http.Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.asked)
}

// withConfig appends text to the tree's configuration file, as an operator
// adds a block.
func withConfig(t *testing.T, tr tree, text string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(tr.config))
	if err != nil {
		t.Fatalf("reading the configuration: %v", err)
	}
	if err := os.WriteFile(filepath.Clean(tr.config), append(raw, text...), 0o600); err != nil {
		t.Fatalf("writing the configuration: %v", err)
	}
}

// vetoTree is the fixture tree under ENFORCE serving the veto bundle, with a
// decision point block that names identifier and adds extra.
func vetoTree(t *testing.T, identifier, extra string) tree {
	t.Helper()
	tr := newTree(t)
	writeBundle(t, filepath.Join(tr.dir, "policy.bundle"), vetoDocument)
	tr.confirm(t)
	withConfig(t, tr, "\npdp:\n  identifier: "+identifier+"\n  allow_plaintext: true\n"+extra)
	setEnv(t, "mode", "ENFORCE")
	return tr
}

// admitRead proposes one read under its own request id.
func admitRead(p *plane, requestID string) gateway.Disposition {
	env := readEnvelope()
	env.RequestId = requestID
	return p.pipeline.Admit(context.Background(), gateway.Admission{Envelope: env, Arguments: []byte(`{"id":"ord-1"}`)})
}

// expectPDP asserts the decision carries code and names the decision point by
// the identifier the configuration gave it.
func expectPDP(t *testing.T, d gateway.Disposition, action core.EnforcementAction, code, identifier string) {
	t.Helper()
	if d.Action != action {
		t.Errorf("Action = %v, want %v (decision %v)", d.Action, action, d.Decision.GetReasonCodes())
	}
	if !slices.Contains(d.Decision.GetReasonCodes(), code) {
		t.Errorf("the decision says %v, want %s among them", d.Decision.GetReasonCodes(), code)
	}
	if got := d.Decision.GetPdpInstance(); got != identifier {
		t.Errorf("pdp_instance = %q, want the configured %q", got, identifier)
	}
}

// TestThePlaneAsksTheConfiguredDecisionPoint: every key of the block reaches
// the question, the answer decides the veto, and the decision names the
// decision point.
func TestThePlaneAsksTheConfiguredDecisionPoint(t *testing.T) {
	dp := newPDPDouble(t, `{"decision":false}`)
	dp.eval = "/tenant-a/eval"
	tr := vetoTree(t, dp.url, "  evaluation_endpoint: "+dp.url+"/tenant-a/eval\n  timeout: 2s\n"+
		"  headers:\n    X-Tenant-Key: fixture-value\n")
	p := tr.plane(t)
	expectPDP(t, admitRead(p, "req-1"), core.Block, "PDP_DENY", dp.url)

	asked := dp.questions()
	if len(asked) != 1 {
		t.Fatalf("the decision point was asked %d time(s), want 1", len(asked))
	}
	if got := asked[0].Header.Get("X-Tenant-Key"); got != "fixture-value" {
		t.Errorf("the question carries X-Tenant-Key %q, want the configured header", got)
	}

	dp.mu.Lock()
	dp.answer = `{"decision":true}`
	dp.mu.Unlock()
	expectPDP(t, admitRead(p, "req-2"), core.Execute, "PDP_ALLOW", dp.url)
}

// TestTheInformationalContextIsTheConfiguredOne: an allow that carries a
// context member is read only where the operator listed it.
func TestTheInformationalContextIsTheConfiguredOne(t *testing.T) {
	answer := `{"decision":true,"context":{"reason":"ok"}}`
	for _, c := range []struct {
		name, extra, code string
		action            core.EnforcementAction
	}{
		{"listed", "  informational_context:\n    - reason\n", "PDP_ALLOW", core.Execute},
		{"not listed", "", "PDP_ANSWER_REFUSED", core.Block},
	} {
		t.Run(c.name, func(t *testing.T) {
			dp := newPDPDouble(t, answer)
			p := vetoTree(t, dp.url, "  timeout: 5s\n"+c.extra).plane(t)
			expectPDP(t, admitRead(p, "req-1"), c.action, c.code, dp.url)
		})
	}
}

// TestTheConfiguredProxyCarriesTheQuestion: with pdp.proxy set the question
// reaches the proxy and not the decision point, which answers otherwise.
func TestTheConfiguredProxyCarriesTheQuestion(t *testing.T) {
	dp := newPDPDouble(t, `{"decision":true}`)
	proxy := newPDPDouble(t, `{"decision":false}`)
	p := vetoTree(t, dp.url, "  timeout: 5s\n  proxy: "+proxy.url+"\n").plane(t)
	expectPDP(t, admitRead(p, "req-1"), core.Block, "PDP_DENY", dp.url)
	if n := len(dp.questions()); n != 0 {
		t.Errorf("the decision point was asked %d time(s) past the proxy", n)
	}
	asked := proxy.questions()
	if len(asked) != 1 || asked[0].RequestURI != dp.url+evaluationPath {
		t.Fatalf("the proxy saw %d request(s), want one for %s", len(asked), dp.url+evaluationPath)
	}
}

// TestTheBoundOnAsksInFlightIsTheConfiguredOne: with one ask held at the
// decision point, a second is unavailable at once under max_in_flight 1.
func TestTheBoundOnAsksInFlightIsTheConfiguredOne(t *testing.T) {
	dp := newPDPDouble(t, `{"decision":true}`)
	dp.hold = make(chan struct{})
	p := vetoTree(t, dp.url, "  timeout: 5s\n  max_in_flight: 1\n").plane(t)
	first := make(chan gateway.Disposition, 1)
	go func() { first <- admitRead(p, "req-1") }()
	select {
	case <-dp.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the first ask never reached the decision point")
	}
	second := admitRead(p, "req-2")
	close(dp.hold)
	expectPDP(t, second, core.Block, "PDP_UNAVAILABLE", dp.url)
	expectPDP(t, <-first, core.Execute, "PDP_ALLOW", dp.url)
}

// TestAnAskPastTheConfiguredTimeoutIsATimeout: a decision point that does not
// answer within pdp.timeout blocks the read it would have vetoed.
func TestAnAskPastTheConfiguredTimeoutIsATimeout(t *testing.T) {
	dp := newPDPDouble(t, `{"decision":true}`)
	dp.hold = make(chan struct{})
	t.Cleanup(func() { close(dp.hold) })
	p := vetoTree(t, dp.url, "  timeout: 50ms\n").plane(t)
	start := time.Now()
	expectPDP(t, admitRead(p, "req-1"), core.Block, "PDP_TIMEOUT", dp.url)
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the ask took %v under a 50ms timeout", took)
	}
}

// TestAPlaneStartsWhateverTheDecisionPointDoes: building the plane contacts
// nothing, so a decision point that is not there never stops it from
// starting.
func TestAPlaneStartsWhateverTheDecisionPointDoes(t *testing.T) {
	dp := newPDPDouble(t, `{"decision":true}`)
	p := vetoTree(t, dp.url, "").plane(t)
	if n := len(dp.questions()); n != 0 {
		t.Errorf("building the plane sent %d request(s) to the decision point", n)
	}
	if p.pdp == nil || p.pdp.Identifier() != dp.url {
		t.Fatalf("the plane holds no client of %s", dp.url)
	}
	vetoTree(t, "http://127.0.0.1:1", "").plane(t)
}

// TestRunRefusesADecisionPointAndABundleThatDisagree: the pipeline's refusal
// reaches the operator with the key or the bundle that fixes it, and a
// client the adapter refuses names the block it came from.
func TestRunRefusesADecisionPointAndABundleThatDisagree(t *testing.T) {
	for _, c := range []struct {
		name  string
		tree  func(t *testing.T) tree
		wants []string
	}{
		{"a bundle that reads external with no decision point", func(t *testing.T) tree {
			tr := newTree(t)
			writeBundle(t, filepath.Join(tr.dir, "policy.bundle"), vetoDocument)
			tr.confirm(t)
			return tr
		}, []string{"none is configured", "set pdp.identifier"}},
		{"a decision point no rule consults", func(t *testing.T) tree {
			tr := newTree(t)
			withConfig(t, tr, "\npdp:\n  identifier: https://pdp.example.test\n")
			return tr
		}, []string{"no rule consults it", "unset pdp.identifier"}},
		{"a plaintext decision point with no risk flag", func(t *testing.T) tree {
			tr := newTree(t)
			writeBundle(t, filepath.Join(tr.dir, "policy.bundle"), vetoDocument)
			tr.confirm(t)
			withConfig(t, tr, "\npdp:\n  identifier: http://127.0.0.1:1\n")
			return tr
		}, []string{"pdp: authzen: invalid options"}},
		{"no bound on asks in flight", func(t *testing.T) tree {
			return vetoTree(t, "http://127.0.0.1:1", "  max_in_flight: 0\n")
		}, []string{"pdp: authzen: invalid options", "InFlight"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := c.tree(t)
			var stdout, stderr bytes.Buffer
			if status := serve(context.Background(), tr.config, "", &stdout, &stderr); status != exitFail {
				t.Fatalf("run answered %d; it must refuse to start", status)
			}
			for _, want := range c.wants {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("the refusal is %q, which does not say %q", stderr.String(), want)
				}
			}
		})
	}
}

// TestDoctorReportsWhatTheMetadataSays is the last check: agreeing metadata
// passes, disagreeing metadata fails, and metadata that is not there is
// unknown, never a pass.
func TestDoctorReportsWhatTheMetadataSays(t *testing.T) {
	for _, c := range []struct {
		name     string
		metadata func(url string) string
		line     string
		status   int
	}{
		{"agrees", func(url string) string {
			return `{"policy_decision_point":"` + url + `","access_evaluation_endpoint":"` + url + evaluationPath + `"}`
		}, "ok      pdp", exitOK},
		{"disagrees", func(url string) string {
			return `{"policy_decision_point":"` + url + `","access_evaluation_endpoint":"` + url + `/other"}`
		}, "fail    pdp", exitFail},
		{"is not there", func(string) string { return "" }, "unknown pdp", exitFail},
	} {
		t.Run(c.name, func(t *testing.T) {
			dp := newPDPDouble(t, `{"decision":true}`)
			dp.metadata = c.metadata(dp.url)
			tr := vetoTree(t, dp.url, "  timeout: 5s\n")
			setEnv(t, "upstreams.0.endpoint", upstream(t))
			setEnv(t, "mode", "OBSERVE")
			var out, stderr bytes.Buffer
			status := doctor(context.Background(), tr.config, &out, &stderr)
			if status != c.status {
				t.Errorf("doctor answered %d, want %d:\n%s", status, c.status, out.String())
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			if last := lines[len(lines)-1]; !strings.HasPrefix(last, c.line) || !strings.Contains(last, dp.url) {
				t.Errorf("the last line is %q, want %q naming %s", last, c.line, dp.url)
			}
		})
	}
}

// TestDoctorsDiscoveryIsBoundedByTheConfiguredTimeout: metadata that never
// comes is unknown once pdp.timeout has passed.
func TestDoctorsDiscoveryIsBoundedByTheConfiguredTimeout(t *testing.T) {
	dp := newPDPDouble(t, `{"decision":true}`)
	dp.hold = make(chan struct{})
	t.Cleanup(func() { close(dp.hold) })
	tr := vetoTree(t, dp.url, "  timeout: 50ms\n")
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	setEnv(t, "mode", "OBSERVE")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var out, stderr bytes.Buffer
	start := time.Now()
	if status := doctor(ctx, tr.config, &out, &stderr); status == exitOK {
		t.Errorf("doctor passed on metadata that never came:\n%s", out.String())
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("doctor took %v under a 50ms pdp.timeout", took)
	}
	if !strings.Contains(out.String(), "\nunknown pdp") {
		t.Errorf("the pdp line is not unknown:\n%s", out.String())
	}
}

// TestWithDecisionPointSetsTheThreeTogether: the pipeline is handed the
// client, its identifier and the timeout at once, and nothing at all for no
// client, which stays a nil interface.
func TestWithDecisionPointSetsTheThreeTogether(t *testing.T) {
	var none gateway.Config
	withDecisionPoint(&none, nil, 250*time.Millisecond)
	if none.DecisionPoint != nil || none.DecisionPointID != "" || none.DecisionTimeout != 0 {
		t.Errorf("no client set %v, %q, %v", none.DecisionPoint, none.DecisionPointID, none.DecisionTimeout)
	}
	cfg := vetoTree(t, "http://127.0.0.1:1", "").load(t)
	client, err := decisionPoint(cfg)
	if err != nil {
		t.Fatalf("decisionPoint: %v", err)
	}
	var some gateway.Config
	withDecisionPoint(&some, client, 250*time.Millisecond)
	if some.DecisionPoint == nil || some.DecisionPointID != "http://127.0.0.1:1" || some.DecisionTimeout != 250*time.Millisecond {
		t.Errorf("the client set %v, %q, %v", some.DecisionPoint, some.DecisionPointID, some.DecisionTimeout)
	}
}

// TestDoctorSaysWhenNoDecisionPointIsConfigured: the line is there and it is
// a pass, since nothing is asked.
func TestDoctorSaysWhenNoDecisionPointIsConfigured(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	var out bytes.Buffer
	if status := doctor(context.Background(), tr.config, &out, &out); status != exitOK {
		t.Fatalf("doctor answered %d:\n%s", status, out.String())
	}
	if !strings.Contains(out.String(), "\nok      pdp           not configured") {
		t.Errorf("no pdp line says it is not configured:\n%s", out.String())
	}
}

// TestDoctorCarriesTheClientsRefusal: options the client refuses fail the
// seams check, which builds it, naming the pdp block.
func TestDoctorCarriesTheClientsRefusal(t *testing.T) {
	tr := newTree(t)
	writeBundle(t, filepath.Join(tr.dir, "policy.bundle"), vetoDocument)
	tr.confirm(t)
	withConfig(t, tr, "\npdp:\n  identifier: http://127.0.0.1:1\n")
	var out bytes.Buffer
	if status := doctor(context.Background(), tr.config, &out, &out); status == exitOK {
		t.Fatalf("doctor passed a plaintext decision point with no risk flag:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "\nfail    seams         pdp: authzen: invalid options") {
		t.Errorf("the seams check does not carry the client's refusal:\n%s", out.String())
	}
}

// TestDoctorsDiscoveryCheckNeedsThePlane: with no plane built there is no
// client to ask with, which is unknown.
func TestDoctorsDiscoveryCheckNeedsThePlane(t *testing.T) {
	tr := vetoTree(t, "http://127.0.0.1:1", "")
	d := &examination{cfg: tr.load(t)}
	if verdict, _, found := d.pdp(context.Background()); verdict != verdictUnknown {
		t.Errorf("the check with no plane is %s: %s", verdict, found)
	}
}

// TestDoctorNeverPrintsADecisionPointCredential: the headers and the proxy's
// userinfo are named, never shown.
func TestDoctorNeverPrintsADecisionPointCredential(t *testing.T) {
	tr := vetoTree(t, "http://127.0.0.1:1", "  proxy: http://operator@127.0.0.1:2\n"+
		"  headers:\n    X-Tenant-Key: fixture-value\n  informational_context:\n    - reason\n")
	var out bytes.Buffer
	doctor(context.Background(), tr.config, &out, &out)
	text := out.String()
	for _, secret := range []string{"fixture-value", "operator@"} {
		if strings.Contains(text, secret) {
			t.Errorf("doctor printed %q:\n%s", secret, text)
		}
	}
	for _, line := range []string{"pdp.headers.X-Tenant-Key", "pdp.informational_context.0  reason", "pdp.proxy                    set, not printed"} {
		if !strings.Contains(text, line) {
			t.Errorf("doctor does not print %q:\n%s", line, text)
		}
	}
}

// TestHealthCountsTheAsks: /healthz carries the ask counters beside the
// pipeline's others, each read from its own field.
func TestHealthCountsTheAsks(t *testing.T) {
	dp := newPDPDouble(t, `{"decision":false}`)
	p := vetoTree(t, dp.url, "  timeout: 5s\n").plane(t)
	admitRead(p, "req-1")
	_, body := ask(t, p, "/healthz")
	pipeline, _ := body["pipeline"].(map[string]any)
	asks, ok := pipeline["asks"].(map[string]any)
	if !ok {
		t.Fatalf("no asks among the pipeline's counters: %v", body["pipeline"])
	}
	if asks["made"] != float64(1) || asks["denied"] != float64(1) || asks["allowed"] != float64(0) {
		t.Errorf("asks are %v after one denied ask", asks)
	}

	out := askCounters(gateway.Asks{Made: 3, Allowed: 5, Denied: 7, DeniedObligations: 11, TimedOut: 13,
		Unavailable: 17, AnswerRefused: 19, Micros: 23})
	for key, want := range map[string]uint64{
		"made": 3, "allowed": 5, "denied": 7, "denied_obligations": 11, "timed_out": 13,
		"unavailable": 17, "answer_refused": 19, "wait_us": 23,
	} {
		if got, ok := out[key].(uint64); !ok || got != want {
			t.Errorf("%s is %v, want %d", key, out[key], want)
		}
	}
	if len(out) != 8 {
		t.Errorf("%d ask counters, want 8", len(out))
	}
}
