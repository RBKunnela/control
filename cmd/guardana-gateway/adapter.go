package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/secretscan"
	"github.com/guardana/control/pkg/contract"
)

// listenerTenant is the tenant of the listener's principal: its own, or the
// plane's.
func listenerTenant(cfg *gatewayconfig.Config) string { return cfg.ListenerTenant() }

// sessionCap is the cap on live sessions of a listener that keeps them; any
// other carries none, whatever the key's default says.
func sessionCap(cfg *gatewayconfig.Config) int {
	if cfg.Listener.Kind != gatewayconfig.ListenerStatefulHTTP {
		return 0
	}
	return cfg.Listener.MaxSessions
}

// adapterConfig translates the configuration into the adapter's, which is
// where every MCP-side refusal is made.
func adapterConfig(cfg *gatewayconfig.Config, logger *slog.Logger) (adaptermcp.Config, error) {
	kinds := map[string]adaptermcp.Kind{
		gatewayconfig.ListenerStatelessHTTP: adaptermcp.KindStatelessHTTP,
		gatewayconfig.ListenerStatefulHTTP:  adaptermcp.KindStatefulHTTP,
		gatewayconfig.ListenerStdio:         adaptermcp.KindStdio,
	}
	shapings := map[string]adaptermcp.Shaping{
		"none": adaptermcp.ShapeNone, "annotate": adaptermcp.ShapeAnnotate, "hide": adaptermcp.ShapeHide,
	}
	tenant := listenerTenant(cfg)
	upstreams, err := upstreams(cfg)
	if err != nil {
		return adaptermcp.Config{}, err
	}
	overrides, err := overrides(cfg)
	if err != nil {
		return adaptermcp.Config{}, err
	}
	secrets, err := secretscan.New(cfg.Secrets(os.LookupEnv))
	if err != nil {
		return adaptermcp.Config{}, fmt.Errorf("the secrets upstream answers are scanned for: %w", err)
	}
	return adaptermcp.Config{
		Listener: adaptermcp.Listener{
			Kind:        kinds[cfg.Listener.Kind],
			Origins:     cfg.Listener.Origins,
			SessionIdle: cfg.Listener.SessionIdle,
			MaxSessions: sessionCap(cfg),
			Identity: adaptermcp.Identity{
				Principal: &controlv1.Principal{Id: cfg.Listener.PrincipalID, Type: cfg.Listener.PrincipalType, TenantId: tenant},
				Agent: &controlv1.Agent{
					Id:        cfg.Listener.AgentID,
					Framework: cfg.Listener.AgentFramework,
					Version:   cfg.Listener.AgentVersion,
				},
			},
		},
		Upstreams:   upstreams,
		Overrides:   overrides,
		Shaping:     shapings[cfg.List.Shaping],
		ListTTL:     cfg.List.TTL,
		CallTimeout: cfg.Upstream.CallTimeout,
		ListTimeout: cfg.Upstream.ListTimeout,
		ProjectID:   cfg.ProjectID,
		TenantID:    cfg.TenantID,
		Environment: cfg.Environment,
		Clock:       time.Now,
		NewID:       newID,
		Secrets:     secrets,
		Logger:      logger,
	}, nil
}

// maxUpstreamAnswerBytes bounds an upstream's HTTP answer the library reads
// whole: the bound it puts itself on one event of a stream and on one
// message over stdio.
const maxUpstreamAnswerBytes = mcp.DefaultMaxEventSize

// errUpstreamAnswerTooLong is an upstream's HTTP answer read past
// maxUpstreamAnswerBytes.
var errUpstreamAnswerTooLong = errors.New("the upstream's answer is longer than the bound")

// boundedAnswers fails every answer past maxUpstreamAnswerBytes but an event
// stream under a success status, whose events the library bounds one by one
// and which a session holds open for as long as it lasts.
type boundedAnswers struct{ next http.RoundTripper }

func (b boundedAnswers) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := b.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	media, _, perr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode/100 == 2 && perr == nil && media == "text/event-stream" {
		return resp, nil
	}
	resp.Body = &boundedBody{ReadCloser: resp.Body, left: maxUpstreamAnswerBytes}
	return resp, nil
}

// boundedBody reads up to left bytes and fails on the first byte past them.
type boundedBody struct {
	io.ReadCloser
	left int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		var past [1]byte
		if n, err := b.ReadCloser.Read(past[:]); n == 0 {
			return 0, err
		}
		return 0, errUpstreamAnswerTooLong
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, err
}

// upstreams builds one transport per configured server: Streamable HTTP for
// an endpoint, a child process for a command. An HTTP upstream's redirect is
// not followed: it reaches the adapter as the upstream's answer, a failed
// call, so a call goes only to the endpoint the operator configured. An HTTP
// answer is read no further than maxUpstreamAnswerBytes.
func upstreams(cfg *gatewayconfig.Config) ([]adaptermcp.Upstream, error) {
	out := make([]adaptermcp.Upstream, 0, len(cfg.Upstreams))
	for i, up := range cfg.Upstreams {
		var transport mcp.Transport
		if up.Endpoint != "" {
			transport = &mcp.StreamableClientTransport{
				Endpoint: up.Endpoint,
				HTTPClient: &http.Client{
					Transport:     boundedAnswers{next: http.DefaultTransport},
					CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
				},
			}
		} else {
			path, err := exec.LookPath(cfg.Resolve(up.Command))
			if err != nil {
				return nil, fmt.Errorf("upstreams.%d.command: %w", i, err)
			}
			// The command and its arguments are the operator's own
			// configuration: an upstream server is a program they chose to run,
			// and nothing an agent sends reaches this line.
			//nolint:gosec // G204: the command comes from the operator's configuration file, never from a request
			cmd := exec.Command(filepath.Clean(path), up.Args...)
			cmd.Env = upstreamEnv(up.Env, os.LookupEnv)
			transport = &mcp.CommandTransport{Command: cmd}
		}
		out = append(out, adaptermcp.Upstream{
			Name: up.Name, Transport: transport, TenantID: up.TenantID, Environment: up.Environment,
		})
	}
	return out, nil
}

// upstreamEnv is a command upstream's whole environment: each variable in
// gatewayconfig.BaseEnv or in listed that the plane has, with the plane's
// value. It is never nil, since a nil environment is exec's signal to pass
// the plane's whole one.
func upstreamEnv(listed []string, lookup func(string) (string, bool)) []string {
	env := []string{}
	var seen []string
	for _, name := range append(gatewayconfig.BaseEnv(), listed...) {
		if slices.Contains(seen, name) {
			continue
		}
		seen = append(seen, name)
		if value, ok := lookup(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// printUpstream prints one upstream for doctor: where it is reached, a
// command by its program and how many arguments it takes, since an argument
// can carry a credential, then each variable its command receives by name,
// never its value, marking one this environment lacks, since the command would
// start without it.
func printUpstream(w io.Writer, i int, up gatewayconfig.UpstreamConfig) {
	where := gatewayconfig.ShowAddress(up.Endpoint)
	if up.Endpoint == "" {
		where = fmt.Sprintf("command %s (%d arguments)", up.Command, len(up.Args))
	}
	writeLine(w, fmt.Sprintf("       %-28s %s -> %s", fmt.Sprintf("upstreams.%d", i), oneLine(up.Name), oneLine(where)))
	for j, name := range up.Env {
		if _, set := os.LookupEnv(name); !set {
			name += " (not set here)"
		}
		writeLine(w, fmt.Sprintf("       %-28s %s", fmt.Sprintf("upstreams.%d.env.%d", i, j), oneLine(name)))
	}
}

// overrides turns the operator's classifications into the manifest's.
func overrides(cfg *gatewayconfig.Config) ([]adaptermcp.Override, error) {
	out := make([]adaptermcp.Override, 0, len(cfg.Overrides))
	for i := range cfg.Overrides {
		o := &cfg.Overrides[i]
		effect, err := contract.ParseEffect(o.Effect)
		if err != nil {
			return nil, fmt.Errorf("overrides.%d.effect: %w", i, err)
		}
		zone, err := o.Zone()
		if err != nil {
			return nil, fmt.Errorf("overrides.%d.trust_zone: %w", i, err)
		}
		returnsZone, err := o.ReturnsZone()
		if err != nil {
			return nil, fmt.Errorf("overrides.%d.returns.trust: %w", i, err)
		}
		returnsLevel, err := o.ReturnsLevel()
		if err != nil {
			return nil, fmt.Errorf("overrides.%d.returns.sensitivity: %w", i, err)
		}
		out = append(out, adaptermcp.Override{
			Upstream: o.Upstream, Tool: o.Tool, Fingerprint: o.Fingerprint, Effect: effect,
			ResourceType: o.ResourceType, ResourceFrom: o.ResourceFrom, TrustZone: zone,
			ReturnsTrust: returnsZone, ReturnsSensitivity: returnsLevel,
		})
	}
	return out, nil
}

// orWord is value, or what its absence means.
func orWord(value, absent string) string {
	if value == "" {
		return absent
	}
	return value
}

// startUpstreams connects every upstream, after which the manifest holds
// what they listed. A refusal names the upstream and what failed, never its
// endpoint or its own message; withheldRefusal stands behind that.
func (p *plane) startUpstreams(ctx context.Context) error {
	if err := p.adapter.Start(ctx, p.pipeline); err != nil {
		return withheldRefusal(err, p.cfg.Upstreams)
	}
	p.listed.Store(true)
	return nil
}

// withheldRefusal is err as run and doctor print it: should it quote a part of
// an endpoint ShowAddress withholds, the userinfo, the query or the fragment,
// it names that endpoint's key and why in its place.
func withheldRefusal(err error, upstreams []gatewayconfig.UpstreamConfig) error {
	text := err.Error()
	for i, up := range upstreams {
		shown := gatewayconfig.ShowAddress(up.Endpoint)
		if shown != up.Endpoint && quotesCredential(text, up.Endpoint) {
			return fmt.Errorf("the transport's error is not printed, because it quotes upstreams.%d.endpoint, which is %s", i, shown)
		}
	}
	return err
}

// quotesCredential says whether text holds a part of endpoint that can carry
// a credential: raw, decoded, or as the Authorization header the HTTP client
// builds from the userinfo. An endpoint that does not parse counts as quoted,
// since its parts cannot be told apart.
func quotesCredential(text, endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return true
	}
	parts := append(userinfoParts(u.User, endpoint), u.RawQuery, u.Fragment, u.EscapedFragment())
	for key, values := range u.Query() {
		parts = append(parts, key)
		parts = append(parts, values...)
	}
	for _, part := range parts {
		if part != "" && strings.Contains(text, part) {
			return true
		}
	}
	return false
}

// userinfoParts is every spelling of a userinfo's user and password a text may
// quote: as the endpoint writes them, decoded, escaped again as the HTTP
// client quotes a URL, and as the base64 of user:password the client sends,
// in each alphabet. The unpadded base64 is a prefix of the padded.
func userinfoParts(user *url.Userinfo, endpoint string) []string {
	if user == nil {
		return nil
	}
	password, _ := user.Password()
	basic := []byte(user.Username() + ":" + password)
	parts := []string{user.Username(), password, base64.RawStdEncoding.EncodeToString(basic), base64.RawURLEncoding.EncodeToString(basic)}
	for _, spelled := range []string{rawUserinfo(endpoint), user.String()} {
		name, secret, _ := strings.Cut(spelled, ":")
		parts = append(parts, name, secret)
	}
	return parts
}

// rawUserinfo is the userinfo as endpoint spells it, before any decoding.
func rawUserinfo(endpoint string) string {
	_, rest, ok := strings.Cut(endpoint, "//")
	if !ok {
		return ""
	}
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		rest = rest[:end]
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return ""
	}
	return rest[:at]
}
