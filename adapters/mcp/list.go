package mcp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/gateway"
)

// cacheScopePrivate is what every list the adapter answers carries: a list
// shaped for one principal is nobody else's to serve (ADR-0013).
const cacheScopePrivate = "private"

// Bounds on what the adapter reads from one upstream list and keeps of the
// lists it shaped: an upstream decides how long its list is, and a list
// that never ends would otherwise hold the manifest, a forwarded list and
// the memory behind them.
const (
	maxListPages   = 100
	maxListEntries = 10000
	maxCachedLists = 1024
)

// DefaultListTimeout is the bound on reading one upstream's list while
// Config.ListTimeout is zero.
const DefaultListTimeout = 30 * time.Second

// brandMeta is the prefix of every _meta key the gateway itself speaks for.
// An upstream's key under it is removed from what the agent sees, so an
// upstream cannot speak as the gateway.
var brandMeta = brand.OTelNamespace + "/"

// underBrand reports whether k is under the gateway's namespace in any case,
// since a client may match a _meta key to a field of its own without regard
// to case. The prefix is compared rune by rune, as folding maps one rune to
// one rune but not one byte to one byte.
func underBrand(k string) bool {
	n := utf8.RuneCountInString(brandMeta)
	for i := range k {
		if n == 0 {
			return strings.EqualFold(k[:i], brandMeta)
		}
		n--
	}
	return n == 0 && strings.EqualFold(k, brandMeta)
}

// metaKeyVerdict is the _meta key an annotated tool carries: the verdict
// the policy gives a call to it, ACTION_UNCLASSIFIED, or DECIDED_PER_CALL
// when the preview cannot decide without the call's arguments.
var metaKeyVerdict = brandMeta + "verdict"

const markDecidedPerCall = "DECIDED_PER_CALL"

// readAll reads a paginated list page by page and refuses one longer than
// maxListPages pages or maxListEntries entries.
func readAll[T any](ctx context.Context, page func(ctx context.Context, cursor string) ([]T, string, error)) ([]T, error) {
	var out []T
	cursor := ""
	for pages := 0; ; pages++ {
		if pages == maxListPages {
			return nil, fmt.Errorf("%w: more than %d pages", ErrListBound, maxListPages)
		}
		items, next, err := page(ctx, cursor)
		if err != nil {
			return nil, err
		}
		if len(out)+len(items) > maxListEntries {
			return nil, fmt.Errorf("%w: more than %d entries", ErrListBound, maxListEntries)
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		cursor = next
	}
}

// stripMeta returns m without the keys under the gateway's namespace, or m
// itself when it holds none.
func stripMeta(m mcp.Meta) mcp.Meta {
	var out mcp.Meta
	for k := range m {
		if underBrand(k) {
			out = make(mcp.Meta, len(m))
			break
		}
	}
	if out == nil {
		return m
	}
	for k, v := range m {
		if !underBrand(k) {
			out[k] = v
		}
	}
	return out
}

// stripped copies each item with its _meta stripped; the upstream client may
// hand the same items to another request, so none is written to.
func stripped[T any](items []*T, meta func(*T) *mcp.Meta) []*T {
	out := make([]*T, 0, len(items))
	for _, it := range items {
		if it == nil {
			continue
		}
		c := *it
		m := meta(&c)
		*m = stripMeta(*m)
		out = append(out, &c)
	}
	return out
}

// listTools answers tools/list for the calling principal from the manifest,
// shaped by the same pipeline a call is decided by. The library's cache hook
// does not run for an answer the middleware made, so the cacheable fields
// are set here, and the per-principal cache is the adapter's own.
func (a *Adapter) listTools(ctx context.Context, req mcp.Request) (mcp.Result, error) {
	p, _, err := a.started()
	if err != nil {
		return nil, err
	}
	principal, agent, err := a.identity(req)
	if err != nil {
		return nil, blockedError(nil, map[string]any{keyReasonCodes: []string{"REQUIRED_FIELD_ABSENT"}})
	}
	entries, generation := a.manifest.snapshot(a.names)
	s := &shaping{a: a, ctx: ctx, p: p, req: req, principal: principal, agent: agent}
	key, cacheable := principalKey(principal), a.lists.enabled()
	var bundle string
	if cacheable {
		bundle, cacheable = s.bundle(entries)
	}
	if cacheable {
		if tools, ok := a.lists.get(key, bundle, generation, a.cfg.Clock()); ok {
			return a.listResult(tools), nil
		}
	}
	tools := []*mcp.Tool{}
	for i := range entries {
		if t := s.shape(&entries[i]); t != nil {
			tools = append(tools, t)
		}
	}
	if cacheable && !s.mixed {
		a.lists.put(key, tools, bundle, generation, a.cfg.Clock())
	}
	return a.listResult(tools), nil
}

// shaping is one tools/list shaped for one principal, and the bundles its
// previews were decided under.
type shaping struct {
	a         *Adapter
	ctx       context.Context
	p         Pipeline
	req       mcp.Request
	principal *controlv1.Principal
	agent     *controlv1.Agent
	// probe is the entry bundle previewed, and probed its decision, which
	// shaping that entry takes instead of asking again.
	probe  *Entry
	probed *controlv1.Decision
	digest string
	// mixed is a preview decided under a bundle other than probed's: the list
	// straddles two bundles and is cached under neither.
	mixed bool
}

// bundle previews the first entry shaping would preview and returns the
// bundle that decided it, so a list is cached and looked up under the bundle
// in force. A list no preview shapes reads no bundle. A preview that names
// no bundle leaves nothing to tell the next one from, and nothing is cached.
func (s *shaping) bundle(entries []Entry) (string, bool) {
	if s.a.cfg.Shaping == ShapeNone {
		return "", true
	}
	for i := range entries {
		if previewed(&entries[i]) {
			s.probe = &entries[i]
			s.probed = s.a.preview(s.ctx, s.p, s.req, s.probe, s.principal, s.agent)
			s.digest = s.probed.GetPolicyBundleDigest()
			return s.digest, s.digest != ""
		}
	}
	return "", true
}

// decide is the preview of e, read once for the probe.
func (s *shaping) decide(e *Entry) *controlv1.Decision {
	if e == s.probe {
		return s.probed
	}
	d := s.a.preview(s.ctx, s.p, s.req, e, s.principal, s.agent)
	if s.probe != nil && d.GetPolicyBundleDigest() != s.digest {
		s.mixed = true
	}
	return d
}

// previewed is an entry shaping asks the policy about.
func previewed(e *Entry) bool { return e.Classified && !e.Ambiguous }

// principalKey names a principal for the shaped-list cache by every field a
// policy can read about it.
func principalKey(p *controlv1.Principal) string {
	return strings.Join([]string{p.GetTenantId(), p.GetType(), p.GetId(), p.GetAuthnStrength()}, "\x00")
}

func (a *Adapter) listResult(tools []*mcp.Tool) *mcp.ListToolsResult {
	out := &mcp.ListToolsResult{Tools: tools}
	out.TTLMs, out.CacheScope = a.ttlMs(), cacheScopePrivate
	return out
}

func (a *Adapter) ttlMs() int { return int(a.cfg.ListTTL / time.Millisecond) }

// shape returns the tool as the principal may see it, or nil to omit it.
// Shaping only subtracts: none shows the upstream's tool, annotate marks it,
// hide omits what the preview denies and what nobody classified. A tool the
// preview cannot decide without the call's arguments stays, because the call
// is decided when it is made. A definition the scan withheld is omitted under
// every shaping.
func (s *shaping) shape(e *Entry) *mcp.Tool {
	if e.withheld {
		return nil
	}
	shapingKind := s.a.cfg.Shaping
	if shapingKind == ShapeNone {
		return present(e.Tool, "")
	}
	mark := codeUnclassified
	if previewed(e) {
		switch v := s.decide(e).GetVerdict(); v {
		case controlv1.Verdict_VERDICT_DENY:
			if shapingKind == ShapeHide {
				return nil
			}
			mark = v.String()
		case controlv1.Verdict_VERDICT_ALLOW, controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS, controlv1.Verdict_VERDICT_REQUIRE_APPROVAL:
			mark = v.String()
		default:
			mark = markDecidedPerCall
		}
	} else if shapingKind == ShapeHide {
		return nil
	}
	if shapingKind == ShapeAnnotate {
		return present(e.Tool, mark)
	}
	return present(e.Tool, "")
}

// preview asks the pipeline what a call to the tool with no arguments would
// be decided, for this principal, without recording anything, so it names no
// trace.
func (a *Adapter) preview(ctx context.Context, p Pipeline, req mcp.Request, e *Entry, principal *controlv1.Principal, agent *controlv1.Agent) *controlv1.Decision {
	up := a.upstreamConfig(e.Upstream)
	env := a.base(req, nil, principal, agent, a.cfg.NewID())
	env.Action = &controlv1.Action{Kind: channel.KindTool, Name: e.Tool.Name, Protocol: channel.ProtocolMCP, Effect: e.Effect, Provider: e.Upstream}
	env.Resource = &controlv1.Resource{Type: e.ResourceType, TenantId: up.TenantID, Environment: up.Environment}
	if e.TrustZone != controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED {
		env.Destination = &controlv1.Destination{TrustZone: e.TrustZone}
	}
	args := []byte(noArguments)
	return p.Preview(ctx, gateway.Admission{Envelope: env, Refusal: a.finish(env, args), Arguments: args})
}

// present is the tool as the agent sees it: its _meta without the gateway's
// namespace and, when mark is set, the verdict. The manifest's own tool is
// never written to.
func present(t *mcp.Tool, mark string) *mcp.Tool {
	meta := stripMeta(t.Meta)
	if mark == "" && len(meta) == len(t.Meta) {
		return t
	}
	out := *t
	out.Meta = make(mcp.Meta, len(meta)+1)
	for k, v := range meta {
		out.Meta[k] = v
	}
	if mark != "" {
		out.Meta[metaKeyVerdict] = mark
	}
	return &out
}

// listCache keeps one shaped list per principal for the operator's TTL, at
// most maxCachedLists of them, and only lists shaped from the manifest's
// current generation. A list answers only under the bundle and the
// generation it was shaped from, since a caller can snapshot a refreshed
// manifest before the cache is reset.
type listCache struct {
	ttl        time.Duration
	mu         sync.Mutex
	generation uint64
	m          map[string]cachedList
}

type cachedList struct {
	tools      []*mcp.Tool
	bundle     string
	generation uint64
	expires    time.Time
}

func newListCache(ttl time.Duration) *listCache {
	return &listCache{ttl: ttl, m: map[string]cachedList{}}
}

func (c *listCache) enabled() bool { return c.ttl > 0 }

func (c *listCache) get(key, bundle string, generation uint64, now time.Time) ([]*mcp.Tool, bool) {
	if !c.enabled() {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || !now.Before(e.expires) || e.bundle != bundle || e.generation != generation {
		delete(c.m, key)
		return nil, false
	}
	return e.tools, true
}

// put keeps tools for key unless they were shaped from a manifest older than
// the last reset, or the cache is full of lists that have not expired.
func (c *listCache) put(key string, tools []*mcp.Tool, bundle string, generation uint64, now time.Time) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation < c.generation {
		return
	}
	if _, ok := c.m[key]; !ok && len(c.m) >= maxCachedLists {
		for k, e := range c.m {
			if !now.Before(e.expires) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxCachedLists {
			return
		}
	}
	c.m[key] = cachedList{tools: tools, bundle: bundle, generation: generation, expires: now.Add(c.ttl)}
}

// reset drops every cached list when the manifest changed, and refuses from
// then on a list shaped before generation.
func (c *listCache) reset(generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation = max(c.generation, generation)
	c.m = map[string]cachedList{}
}

func (c *listCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
