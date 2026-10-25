package mcp_test

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy/rules"
)

func obligation(typ string, params map[string]string) *controlv1.Obligation {
	return &controlv1.Obligation{Type: typ, Params: params}
}

// assertRefused checks that the call was answered as a block naming the
// obligation and that the victim never ran the tool.
func assertRefused(t *testing.T, r *rig, res *sdk.CallToolResult, err error, tool string) {
	t.Helper()
	if err != nil || !res.IsError {
		t.Fatalf("%s under the obligation: %v %+v", tool, err, res)
	}
	if codes := codesOf(t, res); !slices.Equal(codes, []string{"OBLIGATIONS_ATTACHED", "OBLIGATION_NOT_UNDERSTOOD"}) {
		t.Errorf("codes %v", codes)
	}
	if n := r.victim.count(tool); n != 0 {
		t.Errorf("victim ran %s %d times", tool, n)
	}
	aborts := r.pipe.aborted()
	if len(aborts) == 0 || aborts[len(aborts)-1].cause != gateway.AbortObligation {
		t.Errorf("the refusal was not aborted as an obligation: %+v", aborts)
	}
}

// TestReadOnlyObligation: read_only lets a read through and refuses a call
// whose manifest effect is not a read.
func TestReadOnlyObligation(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	r.pipe.decide = executeWith(obligation("read_only", nil))
	agent := r.connect(t, "agent-a")
	if res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"}); err != nil || res.IsError {
		t.Fatalf("read under read_only: %v %+v", err, res)
	}
	res, err := callTool(t, agent, "delete_file", map[string]any{"path": "/x"})
	assertRefused(t, r, res, err, "delete_file")
	if r.victim.count("read_file") != 1 {
		t.Errorf("read ran %d times", r.victim.count("read_file"))
	}
	// Advisory: the same obligation marked advisory does not stop the call.
	r.pipe.decide = executeWith(&controlv1.Obligation{Type: "read_only", Advisory: true})
	if res, err := callTool(t, agent, "delete_file", map[string]any{"path": "/x"}); err != nil || res.IsError {
		t.Fatalf("advisory read_only stopped the call: %v %+v", err, res)
	}
}

// TestRestrictResourcesObligation: the resource named by the call has to
// be one of the ids or under the prefix; no parameter allows nothing, and
// the prefix is literal. Under the prefix, a segment or a byte a resolver
// could read as leaving it refuses the call; an exact id stays text. NUL,
// the other control characters, DEL and trailing white space are refused
// already as an invalid identifier, before any obligation runs.
func TestRestrictResourcesObligation(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	agent := r.connect(t, "agent-a")
	cases := []struct {
		name   string
		params map[string]string
		path   string
		allow  bool
	}{
		{"exact id", map[string]string{"ids": "/a,/b"}, "/b", true},
		{"id outside", map[string]string{"ids": "/a,/b"}, "/c", false},
		{"prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/x", true},
		{"prefix is literal", map[string]string{"prefix": "/srv/data/"}, "/srv/data-evil/x", false},
		{"deeper path under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a/b.c/..d", true},
		{"dot-dot under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/../../etc/passwd", false},
		{"dot segment under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/./x", false},
		{"empty segment under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a//x", false},
		{"backslash under the prefix", map[string]string{"prefix": "/srv/data/"}, `/srv/data/..\..\etc\passwd`, false},
		{"trailing dot-dot under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a/..", false},
		{"trailing slash under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a/", true},
		{"prefix without a slash", map[string]string{"prefix": "/srv/data"}, "/srv/data/x", true},
		{"dot-dot after a prefix without a slash", map[string]string{"prefix": "/srv/data"}, "/srv/data/../x", false},
		{"exact id is text", map[string]string{"ids": "/srv/data/../x"}, "/srv/data/../x", true},
		{"id equal to the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/", true},
		{"hyphen, underscore and tilde under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a-b_c~d.txt", true},
		{"url prefix", map[string]string{"prefix": "https://api.example/v1/users/"}, "https://api.example/v1/users/42", true},
		{"encoded dot-dot", map[string]string{"prefix": "/srv/data/"}, "/srv/data/%2e%2e/%2e%2e/etc/passwd", false},
		{"encoded slash", map[string]string{"prefix": "/srv/data/"}, "/srv/data/..%2f..%2fetc%2fpasswd", false},
		{"encoded backslash", map[string]string{"prefix": "/srv/data/"}, "/srv/data/..%5c..%5cetc", false},
		{"fullwidth dots", map[string]string{"prefix": "/srv/data/"}, "/srv/data/．．/．．/etc/passwd", false},
		{"path parameter", map[string]string{"prefix": "/srv/data/"}, "/srv/data/..;/..;/etc/passwd", false},
		{"nul after dot-dot", map[string]string{"prefix": "/srv/data/"}, "/srv/data/..\x00", false},
		{"nul in a name", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a\x00b", false},
		{"control character", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a\tb", false},
		{"delete character", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a\x7fb", false},
		{"dot-dot and a space", map[string]string{"prefix": "/srv/data/"}, "/srv/data/.. ", false},
		{"dot-dot and a space mid-path", map[string]string{"prefix": "/srv/data/"}, "/srv/data/.. /etc/passwd", false},
		{"space segment", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a/ /b", false},
		{"space inside a name", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a b", true},
		{"three dots", map[string]string{"prefix": "/srv/data/"}, "/srv/data/.../x", false},
		{"file url encoded dot-dot", map[string]string{"prefix": "file:///srv/data/"}, "file:///srv/data/%2E%2E/%2E%2E/etc/passwd", false},
		{"https url encoded dot-dot", map[string]string{"prefix": "https://api.example/v1/users/"}, "https://api.example/v1/users/%2e%2e/admin", false},
		{"prefix ending in dot-dot", map[string]string{"prefix": "/srv/data/.."}, "/srv/data/../etc", false},
		{"id equal to a prefix ending in dot-dot", map[string]string{"prefix": "/srv/data/.."}, "/srv/data/..", false},
		{"percent in an exact id is text", map[string]string{"ids": "/srv/data/%2e%2e"}, "/srv/data/%2e%2e", true},
		{"https dot-dot before a query", map[string]string{"prefix": "https://api.example/pub/"}, "https://api.example/pub/..?x", false},
		{"https dot-dot before a fragment", map[string]string{"prefix": "https://api.example/pub/"}, "https://api.example/pub/..#x", false},
		{"file url dot-dot before an empty query", map[string]string{"prefix": "file:///srv/data/"}, "file:///srv/data/..?", false},
		{"query below the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a?b", false},
		{"query in an exact id is text", map[string]string{"ids": "https://api.example/pub/a?x"}, "https://api.example/pub/a?x", true},
		{"no parameter", nil, "/a", false},
		{"empty ids", map[string]string{"ids": ""}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r.pipe.decide = executeWith(obligation("restrict_resources", tc.params))
			before := r.victim.count("read_file")
			res, err := callTool(t, agent, "read_file", map[string]any{"path": tc.path})
			if err != nil {
				t.Fatal(err)
			}
			if tc.allow && (res.IsError || r.victim.count("read_file") != before+1) {
				t.Fatalf("allowed resource refused: %+v", res)
			}
			if !tc.allow && (!res.IsError || r.victim.count("read_file") != before) {
				t.Fatalf("resource outside the set sent: %+v", res)
			}
		})
	}
}

// TestShortenTimeoutObligation: the upstream call gets the obligation's
// deadline; a tool that outlives it is cut off and closed as TIMEOUT. A
// missing or non-positive ms refuses the call, and so does one past what a
// duration holds, which would wrap to no bound or to a bound nobody wrote.
func TestShortenTimeoutObligation(t *testing.T) {
	forEachKind(t, rigOptions{}, func(t *testing.T, r *rig) {
		r.pipe.decide = executeWith(obligation("shorten_timeout", map[string]string{"ms": "100"}))
		agent := r.connect(t, "agent-a")
		start := time.Now()
		_, err := callTool(t, agent, "slow", map[string]any{"path": "/x"})
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("the slow tool completed under a 100ms obligation")
		}
		if elapsed >= 2*time.Second {
			t.Fatalf("the call took %v; the deadline did not apply", elapsed)
		}
		closes := r.pipe.closed()
		if len(closes) != 1 || closes[0].result.GetStatus() != controlv1.ResultStatus_RESULT_STATUS_TIMEOUT {
			t.Fatalf("Close calls %+v", closes)
		}
		for _, params := range []map[string]string{nil, {"ms": "0"}, {"ms": "-5"}, {"ms": "soon"}, {"ms": "9223372036855"}, {"ms": "18446744073710"}} {
			r.pipe.decide = executeWith(obligation("shorten_timeout", params))
			res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"})
			assertRefused(t, r, res, err, "read_file")
		}
	})
}

// TestDenyExternalSinkObligation: a tool whose destination is not trusted
// is refused; one classified as trusted internal proceeds; one with no
// destination at all is refused, because nobody vouched for it.
func TestDenyExternalSinkObligation(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{overrides: func(v *victim, t *testing.T) []mcp.Override {
		o := v.overrides(t)
		o = append(o, mcp.Override{Upstream: "victim", Tool: "unlisted", Fingerprint: v.fingerprint(t, "unlisted"), Classification: classify.Classification{Effect: effectComm, ResourceType: "peer", ResourceFrom: "/path", TrustZone: zoneInternal}})
		return o
	}})
	r.pipe.decide = executeWith(obligation("deny_external_sink", nil))
	agent := r.connect(t, "agent-a")
	res, err := callTool(t, agent, "send_mail", map[string]any{"to": "x@example.com"})
	assertRefused(t, r, res, err, "send_mail")
	res, err = callTool(t, agent, "read_file", map[string]any{"path": "/x"})
	assertRefused(t, r, res, err, "read_file")
	if res, err := callTool(t, agent, "unlisted", map[string]any{"path": "/x"}); err != nil || res.IsError {
		t.Fatalf("trusted sink refused: %v %+v", err, res)
	}
}

// TestObligationWithAnUnreadParameterIsNotApplied: a parameter the type does
// not read is an instruction nobody follows, so the obligation carrying it is
// not applied. Each case passes without the extra parameter; with it, a
// non-advisory obligation stops the call and an advisory one is skipped.
func TestObligationWithAnUnreadParameterIsNotApplied(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{overrides: func(v *victim, t *testing.T) []mcp.Override {
		o := v.overrides(t)
		o = append(o, mcp.Override{Upstream: "victim", Tool: "unlisted", Fingerprint: v.fingerprint(t, "unlisted"), Classification: classify.Classification{Effect: effectRead, ResourceType: "file", ResourceFrom: "/path", TrustZone: zoneInternal}})
		return o
	}})
	agent := r.connect(t, "agent-a")
	type unread struct {
		typ    string
		params map[string]string
		extra  string
	}
	// The extra key is, where one exists, a parameter another type reads.
	cases := []unread{
		{"read_only", map[string]string{}, "ids"},
		{"restrict_resources", map[string]string{"ids": "/x"}, "ms"},
		{"restrict_resources", map[string]string{"prefix": "/"}, "fields"},
		{"shorten_timeout", map[string]string{"ms": "60000"}, "prefix"},
		{"deny_external_sink", map[string]string{}, "limit"},
	}
	// And a key no type of the catalogue declares, on every applied type.
	for _, extra := range outsideTheCatalogue(t, "per_minute", "seconds", "x", "MS") {
		cases = append(cases,
			unread{"read_only", map[string]string{}, extra},
			unread{"restrict_resources", map[string]string{"ids": "/x"}, extra},
			unread{"shorten_timeout", map[string]string{"ms": "60000"}, extra},
			unread{"deny_external_sink", map[string]string{}, extra})
	}
	for _, tc := range cases {
		t.Run(tc.typ+"/"+tc.extra, func(t *testing.T) {
			r.pipe.decide = executeWith(obligation(tc.typ, tc.params))
			if res, err := callTool(t, agent, "unlisted", map[string]any{"path": "/x"}); err != nil || res.IsError {
				t.Fatalf("%s %v refused without an extra parameter: %v %+v", tc.typ, tc.params, err, res)
			}
			extra := map[string]string{tc.extra: "/"}
			maps.Copy(extra, tc.params)
			r.pipe.decide = executeWith(obligation(tc.typ, extra))
			before := r.victim.count("unlisted")
			res, err := callTool(t, agent, "unlisted", map[string]any{"path": "/x"})
			if err != nil || !res.IsError || r.victim.count("unlisted") != before {
				t.Fatalf("%s %v was applied: %v %+v", tc.typ, extra, err, res)
			}
			if codes := codesOf(t, res); !slices.Equal(codes, []string{"OBLIGATIONS_ATTACHED", "OBLIGATION_NOT_UNDERSTOOD"}) {
				t.Errorf("codes %v", codes)
			}
			r.pipe.decide = executeWith(&controlv1.Obligation{Type: tc.typ, Params: extra, Advisory: true})
			if res, err := callTool(t, agent, "unlisted", map[string]any{"path": "/x"}); err != nil || res.IsError {
				t.Fatalf("advisory %s with an extra parameter stopped the call: %v %+v", tc.typ, err, res)
			}
		})
	}
}

// outsideTheCatalogue returns names after checking that no type of the
// catalogue declares any of them.
func outsideTheCatalogue(t *testing.T, names ...string) []string {
	t.Helper()
	for _, spec := range rules.Obligations() {
		for _, p := range spec.Params {
			if slices.Contains(names, p.Name) {
				t.Fatalf("%s declares %s, which this test needs undeclared", spec.Type, p.Name)
			}
		}
	}
	return names
}

// TestAppliedObligationsAreACopy: a caller that changes the returned list
// changes nothing the adapter declares.
func TestAppliedObligationsAreACopy(t *testing.T) {
	want := []string{"read_only", "restrict_resources", "shorten_timeout", "deny_external_sink"}
	got := mcp.AppliedObligations()
	if !slices.Equal(got, want) {
		t.Fatalf("AppliedObligations = %v, want %v", got, want)
	}
	got[0] = "cap_rate"
	if again := mcp.AppliedObligations(); !slices.Equal(again, want) {
		t.Errorf("a caller's change reached the list: %v", again)
	}
}

// TestAdvisoryShortenTimeoutWithAnUnreadParameterIsSkipped: the skip is
// observable on the one type that changes the send: the deadline an advisory
// shorten_timeout sets applies, and does not once it carries a parameter the
// type does not read.
func TestAdvisoryShortenTimeoutWithAnUnreadParameterIsSkipped(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	agent := r.connect(t, "agent-a")
	r.pipe.decide = executeWith(&controlv1.Obligation{Type: "shorten_timeout", Params: map[string]string{"ms": "100"}, Advisory: true})
	if _, err := callTool(t, agent, "slow", map[string]any{"path": "/x"}); err == nil {
		t.Fatal("the slow tool completed under an advisory 100ms obligation")
	}
	r.pipe.decide = executeWith(&controlv1.Obligation{Type: "shorten_timeout", Params: map[string]string{"ms": "100", "limit": "1"}, Advisory: true})
	if res, err := callTool(t, agent, "slow", map[string]any{"path": "/x"}); err != nil || res.IsError {
		t.Fatalf("an advisory shorten_timeout with an unread parameter cut the call: %v %+v", err, res)
	}
}

// TestUndeclaredObligationIsRefused: an obligation outside the declared set
// stops the call unless advisory, whatever the pipeline let through.
func TestUndeclaredObligationIsRefused(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	agent := r.connect(t, "agent-a")
	r.pipe.decide = executeWith(obligation("cap_amount", map[string]string{"max": "1"}))
	res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"})
	assertRefused(t, r, res, err, "read_file")
	r.pipe.decide = executeWith(&controlv1.Obligation{Type: "emit_alert", Advisory: true})
	if res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"}); err != nil || res.IsError {
		t.Fatalf("advisory obligation stopped the call: %v %+v", err, res)
	}
}

// bearer authenticates "<user>-token" as that user for alice and bob, and
// nothing else.
func bearer() func(http.Handler) http.Handler {
	return auth.RequireBearerToken(func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		user, ok := strings.CutSuffix(token, "-token")
		if !ok || (user != "alice" && user != "bob") {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: user, Expiration: time.Now().Add(time.Hour)}, nil
	}, nil)
}

// TestAuthenticatedListenerBindsTheUser: Authenticates and BindEndUser. The
// principal is the user the token names, with the listener's strength; a
// request with no token never reaches the pipeline.
func TestAuthenticatedListenerBindsTheUser(t *testing.T) {
	for _, k := range kinds[:2] {
		t.Run(k.name, func(t *testing.T) {
			r := newRig(t, k.kind, rigOptions{auth: bearer()})
			caps := r.adapter.Capabilities()
			if !caps.Authenticates || !caps.BindEndUser {
				t.Fatalf("capabilities %+v", caps)
			}
			if _, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x"}); err != nil {
				t.Fatal(err)
			}
			bob := connectHTTP(t, r.url, "agent-a", r.version, http.Header{"Authorization": {"Bearer bob-token"}})
			if _, err := callTool(t, bob, "read_file", map[string]any{"path": "/x"}); err != nil {
				t.Fatal(err)
			}
			assertPrincipals(t, r, "alice", "bob")
			c := sdk.NewClient(&sdk.Implementation{Name: "anon", Version: "0"}, nil)
			_, err := c.Connect(ctxT(t), &sdk.StreamableClientTransport{Endpoint: r.url}, &sdk.ClientSessionOptions{ProtocolVersion: r.version})
			if err == nil {
				t.Fatal("a client with no token connected")
			}
			if len(r.pipe.admitted()) != 2 || r.victim.count("read_file") != 2 {
				t.Errorf("the unauthenticated request reached something: %d admissions", len(r.pipe.admitted()))
			}
		})
	}
}

func assertPrincipals(t *testing.T, r *rig, users ...string) {
	t.Helper()
	adm := r.pipe.admitted()
	if len(adm) != len(users) {
		t.Fatalf("admissions %d, want %d", len(adm), len(users))
	}
	for i, want := range users {
		p := adm[i].a.Envelope.GetPrincipal()
		if p.GetId() != want || p.GetAuthnStrength() != "bearer" || p.GetTenantId() != "t1" {
			t.Errorf("principal %v, want %s", p, want)
		}
	}
}

// TestAuthenticatorWithoutUserBlocks: an authenticator that lets a request
// through with no user identity binds nothing; the call is refused before
// the policy sees a principal.
func TestAuthenticatorWithoutUserBlocks(t *testing.T) {
	passThrough := func(next http.Handler) http.Handler { return next }
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{auth: passThrough})
	res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x"})
	if err != nil || !res.IsError {
		t.Fatalf("no user, yet: %v %+v", err, res)
	}
	adm := r.pipe.admitted()
	if len(adm) != 1 || !errors.Is(adm[0].a.Refusal, mcp.ErrNoEndUser) || adm[0].a.Envelope != nil {
		t.Fatalf("admission %+v", adm)
	}
	if n := r.victim.count("read_file"); n != 0 {
		t.Fatalf("victim ran %d times", n)
	}
}

// TestAuthenticatorWithoutUserListsNothing: a request an authenticator let
// through with no user is refused every list, the forwarded ones as
// tools/list, and no upstream is asked for one; a request naming a user is
// answered from the upstream.
func TestAuthenticatorWithoutUserListsNothing(t *testing.T) {
	passThrough := func(next http.Handler) http.Handler { return next }
	for _, tc := range []struct {
		name    string
		auth    func(http.Handler) http.Handler
		refused bool
		asked   int64
	}{
		{"no user", passThrough, true, 0},
		{"a user", bearer(), false, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newVictim()
			var asked atomic.Int64
			v.server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
				return func(ctx context.Context, m string, req sdk.Request) (sdk.Result, error) {
					if m == "resources/list" || m == "resources/templates/list" || m == "prompts/list" {
						asked.Add(1)
					}
					return next(ctx, m, req)
				}
			})
			r := newRigOver(t, v, mcp.KindStatelessHTTP, rigOptions{auth: tc.auth})
			agent := r.connect(t, "agent-a")
			ctx := ctxT(t)
			for method, list := range map[string]func() error{
				"tools/list":               func() error { _, err := agent.ListTools(ctx, nil); return err },
				"resources/list":           func() error { _, err := agent.ListResources(ctx, nil); return err },
				"resources/templates/list": func() error { _, err := agent.ListResourceTemplates(ctx, nil); return err },
				"prompts/list":             func() error { _, err := agent.ListPrompts(ctx, nil); return err },
			} {
				err := list()
				var werr *jsonrpc.Error
				blocked := errors.As(err, &werr) && werr.Code == mcp.CodeBlocked
				if blocked != tc.refused || (!tc.refused && err != nil) {
					t.Errorf("%s answered %v; want refused as blocked: %t", method, err, tc.refused)
				}
			}
			if n := asked.Load(); n != tc.asked {
				t.Errorf("the upstream was asked for %d list(s), want %d", n, tc.asked)
			}
		})
	}
}

// TestUnauthenticatedListenerDeclaresNoBinding: without an authenticator
// the adapter declares neither capability and the pipeline refuses to
// bind an end user on it.
func TestUnauthenticatedListenerDeclaresNoBinding(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	caps := r.adapter.Capabilities()
	if caps.Authenticates || caps.BindEndUser {
		t.Fatalf("capabilities %+v", caps)
	}
	if !caps.ObserveRequest || !caps.ObserveResult || caps.Enforcement != gateway.EnforcementInline || !caps.SeeResourceIDs || caps.SeeDelegation {
		t.Fatalf("capabilities %+v", caps)
	}
	if !slices.Equal(caps.Obligations, []string{"read_only", "restrict_resources", "shorten_timeout", "deny_external_sink"}) {
		t.Fatalf("obligations %v", caps.Obligations)
	}
}
