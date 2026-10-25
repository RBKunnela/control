package authzen

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const wellKnown = "/.well-known/authzen-configuration"

// metadata serves document at the discovery path under the identifier's
// path, and 404 anywhere else.
func metadata(path, document string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, document)
	}
}

// discoveryPDP starts a decision point whose metadata is built from its own
// address, under the identifier's path.
func discoveryPDP(t *testing.T, path string, document func(base string) string) (*pdp, Options) {
	t.Helper()
	var doc string
	p := newPDP(t, func(w http.ResponseWriter, r *http.Request) { metadata(wellKnown+path, doc)(w, r) })
	doc = document(p.URL)
	opts := options(p)
	opts.Identifier = p.URL + path
	return p, opts
}

func TestCheckDiscovery(t *testing.T) {
	cases := map[string]struct {
		path     string
		document func(base string) string
		want     DiscoveryVerdict
	}{
		"equal": {"", func(b string) string {
			return `{"policy_decision_point":"` + b + `","access_evaluation_endpoint":"` + b + askedPath + `","search_subject_endpoint":"x"}`
		}, DiscoveryAgrees},
		"equal, under a path": {"/tenant-a", func(b string) string {
			return `{"policy_decision_point":"` + b + `/tenant-a","access_evaluation_endpoint":"` + b + `/tenant-a` + askedPath + `"}`
		}, DiscoveryAgrees},
		"a different identifier": {"", func(b string) string {
			return `{"policy_decision_point":"https://evil.example","access_evaluation_endpoint":"` + b + askedPath + `"}`
		}, DiscoveryDisagrees},
		"a different endpoint": {"", func(b string) string {
			return `{"policy_decision_point":"` + b + `","access_evaluation_endpoint":"https://evil.example/eval"}`
		}, DiscoveryDisagrees},
		"no endpoint": {"", func(b string) string {
			return `{"policy_decision_point":"` + b + `"}`
		}, DiscoveryDisagrees},
		"no identifier": {"", func(b string) string {
			return `{"access_evaluation_endpoint":"` + b + askedPath + `"}`
		}, DiscoveryDisagrees},
		"the identifier twice": {"", func(b string) string {
			return `{"policy_decision_point":"https://evil.example","policy_decision_point":"` + b + `","access_evaluation_endpoint":"` + b + askedPath + `"}`
		}, DiscoveryUnknown},
		"the endpoint not a string": {"", func(b string) string {
			return `{"policy_decision_point":"` + b + `","access_evaluation_endpoint":["` + b + askedPath + `"]}`
		}, DiscoveryUnknown},
		"a null identifier": {"", func(b string) string {
			return `{"policy_decision_point":null,"access_evaluation_endpoint":"` + b + askedPath + `"}`
		}, DiscoveryUnknown},
		"a null endpoint": {"", func(b string) string {
			return `{"policy_decision_point":"` + b + `","access_evaluation_endpoint":null}`
		}, DiscoveryUnknown},
		"not JSON": {"", func(string) string { return `<html></html>` }, DiscoveryUnknown},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, opts := discoveryPDP(t, tc.path, tc.document)
			r := client(t, opts).CheckDiscovery(within(t, 10*time.Second))
			if r.Verdict != tc.want {
				t.Errorf("verdict = %v (%s), want %v", r.Verdict, r.Detail, tc.want)
			}
			if !strings.Contains(r.Detail, "signed_metadata is not verified") {
				t.Errorf("the report does not say signed_metadata is unverified: %s", r.Detail)
			}
			if strings.Contains(r.Detail, "evil") {
				t.Errorf("the report quotes the document: %s", r.Detail)
			}
			if p.hits() != 1 {
				t.Errorf("the check made %d requests, want 1", p.hits())
			}
		})
	}
}

// TestADocumentThatEndsPastTheDeadlineIsUnread: metadata read to its end
// only after the deadline is not compared, whole as it may look.
func TestADocumentThatEndsPastTheDeadlineIsUnread(t *testing.T) {
	p := newPDP(t, answer(`{}`))
	opts := options(p)
	opts.Timeout = 50 * time.Millisecond
	c := client(t, opts)
	c.http.Transport = endsPastTheDeadline(`{"policy_decision_point":"` + p.URL + `","access_evaluation_endpoint":"` + p.URL + askedPath + `"}`)
	r := c.CheckDiscovery(within(t, 30*time.Second))
	if r.Verdict != DiscoveryUnknown || !strings.Contains(r.Detail, "within the bound") {
		t.Errorf("a document read past the deadline = %v (%s), want unknown, unread", r.Verdict, r.Detail)
	}
}

// TestCheckDiscoveryUnreachable: a document that cannot be fetched is
// unknown, never an agreement.
func TestCheckDiscoveryUnreachable(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		_, opts := discoveryPDP(t, "/other", func(string) string { return `{}` })
		opts.Identifier = strings.TrimSuffix(opts.Identifier, "/other")
		if r := client(t, opts).CheckDiscovery(within(t, 10*time.Second)); r.Verdict != DiscoveryUnknown {
			t.Errorf("a missing document = %v (%s), want unknown", r.Verdict, r.Detail)
		}
	})
	t.Run("an agreeing document under another status", func(t *testing.T) {
		var doc string
		p := newPDP(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			_, _ = io.WriteString(w, doc)
		})
		doc = `{"policy_decision_point":"` + p.URL + `","access_evaluation_endpoint":"` + p.URL + askedPath + `"}`
		if r := client(t, options(p)).CheckDiscovery(within(t, 10*time.Second)); r.Verdict != DiscoveryUnknown {
			t.Errorf("a 203 = %v (%s), want unknown", r.Verdict, r.Detail)
		}
	})
	t.Run("an agreeing document that is not JSON by its type", func(t *testing.T) {
		var doc string
		p := newPDP(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, doc)
		})
		doc = `{"policy_decision_point":"` + p.URL + `","access_evaluation_endpoint":"` + p.URL + askedPath + `"}`
		if r := client(t, options(p)).CheckDiscovery(within(t, 10*time.Second)); r.Verdict != DiscoveryUnknown {
			t.Errorf("text/plain = %v (%s), want unknown", r.Verdict, r.Detail)
		}
	})
	t.Run("closed", func(t *testing.T) {
		p, opts := discoveryPDP(t, "", func(b string) string {
			return `{"policy_decision_point":"` + b + `","access_evaluation_endpoint":"` + b + askedPath + `"}`
		})
		p.Close()
		if r := client(t, opts).CheckDiscovery(within(t, 10*time.Second)); r.Verdict != DiscoveryUnknown {
			t.Errorf("an unreachable document = %v (%s), want unknown", r.Verdict, r.Detail)
		}
	})
	t.Run("a client nobody built", func(t *testing.T) {
		var none *Client
		if r := none.CheckDiscovery(within(t, 10*time.Second)); r.Verdict != DiscoveryUnknown {
			t.Errorf("a nil client = %v, want unknown", r.Verdict)
		}
	})
}

// TestNewAndAskNeverFetchDiscovery: construction contacts nothing, and an ask
// contacts only the evaluation endpoint.
func TestNewAndAskNeverFetchDiscovery(t *testing.T) {
	p := newPDP(t, answer(`{"decision":true}`))
	c := client(t, options(p))
	if p.hits() != 0 {
		t.Fatalf("New made %d requests", p.hits())
	}
	c.Ask(within(t, 10*time.Second), envelope())
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.Join(p.paths, " ") != askedPath {
		t.Errorf("paths requested = %q, want only %s", p.paths, askedPath)
	}
}
