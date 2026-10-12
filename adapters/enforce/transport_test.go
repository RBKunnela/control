package enforce_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/guardana/control/adapters/enforce"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/gateway"
)

// refusal decodes an answer as the contract's Error body, strictly, and fails
// the test unless its status and code are the ones named.
func refusal(t *testing.T, status int, body []byte, wantStatus int, want enforcev1alpha1.ErrorCode) *enforcev1alpha1.Error {
	t.Helper()
	var e enforcev1alpha1.Error
	if err := protojson.Unmarshal(body, &e); err != nil {
		t.Fatalf("status %d with a body that is not an Error: %q: %v", status, body, err)
	}
	if status != wantStatus || e.GetCode() != want {
		t.Fatalf("answered %d %s (%q), want %d %s", status, e.GetCode(), e.GetMessage(), wantStatus, want)
	}
	return &e
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func admitBody(tool, args string) string {
	return `{"tool":"` + tool + `","arguments":"` + b64(args) + `"}`
}

func TestAPathOtherThanTheThreeIsAnUnsupportedVersion(t *testing.T) {
	r := newRig(t, defaults())
	for _, path := range []string{
		"/enforce/v1alpha2/admit", "/enforce/v1/admit", "/enforce/v1alpha1/admit/", "/enforce/v1alpha1/ADMIT",
		"/enforce/v1alpha1/%61dmit", "/enforce/v1alpha1/close", "/", "/enforce/v1alpha1",
	} {
		t.Run(path, func(t *testing.T) {
			status, body := r.post(t, runA, path, admitBody("read_file", `{"path":"a"}`))
			refusal(t, status, body, http.StatusNotFound, enforcev1alpha1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION)
		})
	}
	if n := len(r.sink.Events()); n != 0 {
		t.Fatalf("%d events written for refused paths", n)
	}
}

func TestAMethodOtherThanPostIsMalformed(t *testing.T) {
	r := newRig(t, defaults())
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://enforce"+enforce.PathAdmit, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(enforce.RunTokenHeader, runA)
	resp, err := r.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body [512]byte
	n, _ := resp.Body.Read(body[:])
	refusal(t, resp.StatusCode, body[:n], http.StatusMethodNotAllowed, enforcev1alpha1.ErrorCode_ERROR_CODE_MALFORMED)
	if resp.Header.Get("Allow") != http.MethodPost {
		t.Fatalf("Allow = %q", resp.Header.Get("Allow"))
	}
}

// A refused run token is answered before the body is read: each body here is
// not JSON, so a receiver that decoded it first would answer MALFORMED.
func TestARefusedRunTokenIsAnsweredBeforeTheBody(t *testing.T) {
	r := newRig(t, defaults())
	r.runs.close(runShut)
	expired := "run-x.x1"
	r.runs.add(expired, "run-x", listenerWho())
	r.runs.tokens[expired].run.Expires = base()
	for _, tc := range []struct {
		name  string
		token []string
		cause gateway.RunCause
	}{
		{"missing", nil, gateway.RunMissing},
		{"empty", []string{""}, gateway.RunMissing},
		{"two", []string{runA, runA}, gateway.RunMalformed},
		{"unknown", []string{"run-z.z1"}, gateway.RunUnknown},
		{"another agent's", []string{runOther}, gateway.RunOtherIdentity},
		{"closed", []string{runShut}, gateway.RunClosed},
		{"expired", []string{expired}, gateway.RunExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := r.a.Stats().RunsRefused[tc.cause]
			for _, path := range []string{enforce.PathAdmit, enforce.PathComplete, enforce.PathAbort} {
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://enforce"+path, strings.NewReader("{{not json"))
				if err != nil {
					t.Fatal(err)
				}
				for _, v := range tc.token {
					req.Header.Add(enforce.RunTokenHeader, v)
				}
				resp, err := r.http.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				var body [512]byte
				n, _ := resp.Body.Read(body[:])
				_ = resp.Body.Close()
				refusal(t, resp.StatusCode, body[:n], http.StatusUnauthorized, enforcev1alpha1.ErrorCode_ERROR_CODE_UNAUTHENTICATED)
				if resp.Header.Get("WWW-Authenticate") != enforce.RunTokenHeader {
					t.Fatalf("WWW-Authenticate = %q", resp.Header.Get("WWW-Authenticate"))
				}
			}
			if got := r.a.Stats().RunsRefused[tc.cause] - before; got != 3 {
				t.Fatalf("counted %d refusals as %s, want 3", got, tc.cause)
			}
		})
	}
	if n := len(r.sink.Events()); n != 0 {
		t.Fatalf("%d events written for refused tokens", n)
	}
	if got := r.a.Stats().Refused[enforcev1alpha1.ErrorCode_ERROR_CODE_UNAUTHENTICATED]; got != 21 {
		t.Fatalf("counted %d UNAUTHENTICATED, want 21", got)
	}
}

func TestEveryRefusedTokenGetsOneAnswer(t *testing.T) {
	r := newRig(t, defaults())
	_, first := r.post(t, "", enforce.PathAdmit, "{}")
	for _, token := range []string{"run-z.z1", runOther} {
		if _, body := r.post(t, token, enforce.PathAdmit, "{}"); string(body) != string(first) {
			t.Fatalf("%q answered %q, a missing token %q", token, body, first)
		}
	}
}

func TestAnAdmitBodyIsDecodedStrictly(t *testing.T) {
	r := newRig(t, defaults())
	for _, tc := range []struct{ name, body string }{
		{"not JSON", "{{"},
		{"empty", ""},
		{"an array", "[]"},
		{"an unknown member", `{"tool":"read_file","arguments":"` + b64(`{"path":"a"}`) + `","effect":"READ"}`},
		{"an envelope member", `{"tool":"read_file","principal":{"id":"root"}}`},
		{"trailing data", admitBody("read_file", `{"path":"a"}`) + `{}`},
		{"a duplicate member", `{"tool":"read_file","tool":"refund"}`},
		{"a number for a string", `{"tool":7}`},
		{"arguments that are not base64", `{"tool":"read_file","arguments":"%%%"}`},
		{"no tool", `{"arguments":"` + b64(`{}`) + `"}`},
		{"a tool past the bound", admitBody(strings.Repeat("t", 1025), `{}`)},
		{"a key past the bound", `{"tool":"read_file","requestKey":"` + strings.Repeat("k", 65) + `"}`},
		{"a key outside the charset", `{"tool":"read_file","requestKey":"a b"}`},
		{"a key with a slash", `{"tool":"read_file","requestKey":"a/b"}`},
		{"a traceparent past the bound", `{"tool":"read_file","traceparent":"` + strings.Repeat("0", 1025) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := r.post(t, runA, enforce.PathAdmit, tc.body)
			refusal(t, status, body, http.StatusBadRequest, enforcev1alpha1.ErrorCode_ERROR_CODE_MALFORMED)
		})
	}
	if n := len(r.sink.Events()); n != 0 {
		t.Fatalf("%d events written for malformed admits", n)
	}
}

func outcome(t *testing.T, status int, body []byte) *enforcev1alpha1.AdmitResponse {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("admit answered %d: %s", status, body)
	}
	var resp enforcev1alpha1.AdmitResponse
	if err := protojson.Unmarshal(body, &resp); err != nil {
		t.Fatalf("admit answer %q: %v", body, err)
	}
	return &resp
}

// Each bound is held at its value: one more than it is refused before
// anything is written, and the value itself is decided.
func TestTheAdmitBoundsAreWhereTheyAreDocumented(t *testing.T) {
	r := newRig(t, defaults())
	atBound := []string{
		admitBody(strings.Repeat("t", 1024), `{}`),
		`{"tool":"read_file","requestKey":"` + strings.Repeat("k", 64) + `"}`,
		`{"tool":"read_file","requestKey":"Az09._-"}`,
		`{"tool":"read_file","traceparent":"` + strings.Repeat("0", 1024) + `"}`,
	}
	for i, body := range atBound {
		status, answer := r.post(t, runA, enforce.PathAdmit, body)
		if resp := outcome(t, status, answer); resp.GetOutcome() == enforcev1alpha1.Outcome_OUTCOME_UNSPECIFIED {
			t.Fatalf("body %d: %s", i, answer)
		}
	}
	filler := strings.Repeat("x", 65536-len(`{"path":"a","pad":""}`))
	status, body := r.post(t, runA, enforce.PathAdmit, admitBody("read_file", `{"path":"a","pad":"`+filler+`"}`))
	if resp := outcome(t, status, body); resp.GetOutcome() != enforcev1alpha1.Outcome_OUTCOME_EXECUTE {
		t.Fatalf("arguments at the bound: %s", resp.GetOutcome())
	}
	status, body = r.post(t, runA, enforce.PathAdmit, admitBody("read_file", `{"path":"a","pad":"`+filler+`x"}`))
	refusal(t, status, body, http.StatusBadRequest, enforcev1alpha1.ErrorCode_ERROR_CODE_MALFORMED)
}

func TestTheBodyBoundIsTheConfiguredOne(t *testing.T) {
	o := defaults()
	o.adapter = func(c *enforce.Config) { c.MaxBodyBytes = enforce.MinBodyBytes }
	r := newRig(t, o)
	pad := func(n int) string {
		head := `{"tool":"read_file","traceparent":"`
		return head + strings.Repeat("0", n-len(head)-2) + `"}`
	}
	status, body := r.post(t, runA, enforce.PathAdmit, pad(enforce.MinBodyBytes))
	outcome(t, status, body)
	status, body = r.post(t, runA, enforce.PathAdmit, pad(enforce.MinBodyBytes+1))
	refusal(t, status, body, http.StatusBadRequest, enforcev1alpha1.ErrorCode_ERROR_CODE_MALFORMED)
}

func TestTheAnswersAreJSON(t *testing.T) {
	r := newRig(t, defaults())
	for _, tc := range []struct{ token, path, body string }{
		{runA, enforce.PathAdmit, admitBody("read_file", `{"path":"a"}`)},
		{"", enforce.PathAdmit, "{}"},
		{runA, "/nowhere", "{}"},
	} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://enforce"+tc.path, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		if tc.token != "" {
			req.Header.Set(enforce.RunTokenHeader, tc.token)
		}
		resp, err := r.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: headers %v", tc.path, resp.Header)
		}
	}
}

func TestARequestBeforeStartIsUnavailable(t *testing.T) {
	socket := socketPath(t)
	cfg := validConfig()
	cfg.Socket = socket
	a, err := enforce.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := a.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx, ln) }()
	defer func() { cancel(); <-done }()
	r := &rig{http: unixClient(socket)}
	status, body := r.post(t, runA, enforce.PathAdmit, admitBody("read_file", `{"path":"a"}`))
	refusal(t, status, body, http.StatusServiceUnavailable, enforcev1alpha1.ErrorCode_ERROR_CODE_UNAVAILABLE)
}

func TestServeReturnsWhenItsContextEnds(t *testing.T) {
	cfg := validConfig()
	cfg.Socket = socketPath(t)
	a, err := enforce.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := a.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx, ln) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// lyingRuns answers every token with run, refusing nothing.
type lyingRuns struct{ run gateway.OpenedRun }

func (l lyingRuns) Resolve(context.Context, string, gateway.RunIdentity, time.Time) (gateway.OpenedRun, error) {
	return l.run, nil
}

// A resolver that answers a run for someone else, or a run with no id, is not
// believed: the listener's own identity check stands behind the directory's.
func TestARunTheResolverShouldHaveRefusedIsRefused(t *testing.T) {
	other := listenerWho()
	other.PrincipalID = "user-2"
	for _, tc := range []struct {
		name  string
		run   gateway.OpenedRun
		cause gateway.RunCause
	}{
		{"for another principal", gateway.OpenedRun{ID: "run-a", Root: "run-a", Who: other, Expires: base().Add(time.Hour)}, gateway.RunOtherIdentity},
		{"with no id", gateway.OpenedRun{Root: "run-a", Who: listenerWho(), Expires: base().Add(time.Hour)}, gateway.RunUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := defaults()
			o.resolver = func(gateway.RunResolver) gateway.RunResolver { return lyingRuns{tc.run} }
			r := newRig(t, o)
			status, body := r.post(t, runA, enforce.PathAdmit, admitBody("read_file", `{"path":"a"}`))
			refusal(t, status, body, http.StatusUnauthorized, enforcev1alpha1.ErrorCode_ERROR_CODE_UNAUTHENTICATED)
			if got := r.a.Stats().RunsRefused[tc.cause]; got != 1 {
				t.Fatalf("counted %d as %s", got, tc.cause)
			}
		})
	}
}
