package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/secretscan"
)

// fingerprintDomain separates a tool fingerprint from every other digest
// this module computes.
const fingerprintDomain = "mcp-tool-fingerprint/v1\n"

// Override is the operator's classification of one tool definition. The
// fingerprint pins the definition it classifies: a tool whose name matches
// and whose fingerprint does not is unclassified until the operator looks
// again (ADR-0013). Annotations never classify; only this does. The promoted
// Check covers the classification alone; New checks the rest of the override.
type Override struct {
	// Upstream names the server that serves the tool.
	Upstream string
	// Tool is the tool's name as the upstream lists it.
	Tool string
	// Fingerprint is Fingerprint of the definition the operator classified.
	Fingerprint string
	classify.Classification
}

// Entry is one tool as the manifest holds it: the upstream's definition and,
// when an override pins its fingerprint, its classification. The promoted
// Check covers the classification alone, and an unclassified entry holds the
// zero one, which it refuses; New checked the override it was copied from.
type Entry struct {
	Upstream    string
	Tool        *mcp.Tool
	Fingerprint string
	// Classified is false for a definition no override pins; a call to it
	// is refused before the policy sees it.
	Classified bool
	classify.Classification
	// Ambiguous marks a name two upstreams serve: no call can be routed.
	Ambiguous bool
	// why is the reason a listed definition is not classified.
	why string
	// withheld marks a definition that quoted a secret or could not be
	// scanned: it is never classified and never listed; verdict says why.
	withheld bool
	verdict  secretscan.Verdict
}

// Fingerprint identifies a tool definition by all of it as the library types
// it: name, title, description, input schema, output schema, annotations,
// icons and _meta, canonicalized through canon.FingerprintJSON and hashed under
// a domain tag. That form takes any finite number and member names that fold
// together, which a schema holds and a definition authorizes nothing by; a
// definition it still refuses, one with a duplicate key for instance, has no
// fingerprint and so cannot be classified.
func Fingerprint(t *mcp.Tool) (string, error) {
	if t == nil {
		return "", errors.New("mcp: no tool")
	}
	raw, err := json.Marshal(map[string]any{
		"name":         t.Name,
		"title":        t.Title,
		"description":  t.Description,
		"inputSchema":  t.InputSchema,
		"outputSchema": t.OutputSchema,
		"annotations":  t.Annotations,
		"icons":        t.Icons,
		"_meta":        t.Meta,
	})
	if err != nil {
		return "", fmt.Errorf("mcp: fingerprint: %w", err)
	}
	body, err := canon.FingerprintJSON(raw)
	if err != nil {
		return "", fmt.Errorf("mcp: fingerprint: %w", err)
	}
	sum := sha256.Sum256(append([]byte(fingerprintDomain), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// manifest is the adapter's own view of every upstream's tools, keyed by
// name across upstreams, rebuilt per upstream from its tools/list. An entry
// is never written after it is published: a refresh builds new entries and a
// new index, so a reader holding an entry sees what was classified when it
// looked.
type manifest struct {
	overrides map[string]Override // upstream + "\x00" + tool
	secrets   *secretscan.Set

	mu        sync.RWMutex
	perUp     map[string][]*Entry
	byName    map[string]*Entry
	ambiguous map[string]bool
	// generation counts replacements, so a list shaped from an older
	// manifest is never cached as current.
	generation uint64
}

func newManifest(overrides []Override, secrets *secretscan.Set) *manifest {
	m := &manifest{
		overrides: make(map[string]Override, len(overrides)),
		secrets:   secrets,
		perUp:     map[string][]*Entry{},
		byName:    map[string]*Entry{},
		ambiguous: map[string]bool{},
	}
	for _, o := range overrides {
		m.overrides[o.Upstream+"\x00"+o.Tool] = o
	}
	return m
}

// refresh replaces upstream's entries with what it lists now. A list that
// cannot be read, or is longer than the bound, drops the upstream's entries:
// a manifest that kept the old ones would classify a definition it can no
// longer see.
func (m *manifest) refresh(ctx context.Context, upstream string, cs *mcp.ClientSession) error {
	tools, err := readAll(ctx, func(ctx context.Context, cursor string) ([]*mcp.Tool, string, error) {
		res, err := cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		return res.Tools, res.NextCursor, nil
	})
	if err != nil {
		m.replace(upstream, nil)
		return err
	}
	entries := make([]*Entry, 0, len(tools))
	for _, tool := range tools {
		if tool != nil {
			entries = append(entries, m.classify(upstream, tool))
		}
	}
	m.replace(upstream, entries)
	return nil
}

// classify builds the entry for one listed tool from its fingerprint and the
// override that pins it, if any. A definition the scan withholds is neither
// fingerprinted nor classified, whatever pins it.
func (m *manifest) classify(upstream string, tool *mcp.Tool) *Entry {
	e := &Entry{Upstream: upstream, Tool: tool}
	if v := scanned(m.secrets, tool); v.Withhold() {
		e.withheld, e.verdict, e.why = true, v, definitionWithheld(v)
		return e
	}
	fp, err := Fingerprint(tool)
	if err != nil {
		e.why = err.Error()
		return e
	}
	e.Fingerprint = fp
	o, ok := m.overrides[upstream+"\x00"+tool.Name]
	switch {
	case !ok:
		e.why = "no override classifies it"
	case o.Fingerprint != fp:
		e.why = "the definition changed since it was classified"
	default:
		e.Classified = true
		e.Classification = o.Classification
	}
	return e
}

// replace installs upstream's entries and rebuilds the name index from every
// upstream's, marking a name listed twice ambiguous in the index and never
// on an entry.
func (m *manifest) replace(upstream string, entries []*Entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.perUp[upstream] = entries
	byName := map[string]*Entry{}
	ambiguous := map[string]bool{}
	for _, list := range m.perUp {
		for _, e := range list {
			if _, dup := byName[e.Tool.Name]; dup {
				ambiguous[e.Tool.Name] = true
				continue
			}
			byName[e.Tool.Name] = e
		}
	}
	m.byName, m.ambiguous = byName, ambiguous
	m.generation++
}

// route returns the entry for name and, when a call to it cannot be
// classified, gateway.ErrUnclassified wrapped with the reason. The entry is
// nil when no upstream, or more than one, lists the name.
func (m *manifest) route(name string) (*Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.byName[name]
	switch {
	case !ok:
		return nil, fmt.Errorf("%w: no upstream lists it", gateway.ErrUnclassified)
	case m.ambiguous[name]:
		return nil, fmt.Errorf("%w: two upstreams list it", gateway.ErrUnclassified)
	case !e.Classified:
		return e, fmt.Errorf("%w: %s", gateway.ErrUnclassified, e.why)
	}
	return e, nil
}

// snapshot returns a copy of every entry, in upstream order then list
// order, each marked with the index's ambiguity, and the generation they
// belong to.
func (m *manifest) snapshot(upstreams []string) ([]Entry, uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Entry
	for _, up := range upstreams {
		for _, e := range m.perUp[up] {
			c := *e
			c.Ambiguous = m.ambiguous[e.Tool.Name]
			out = append(out, c)
		}
	}
	return out, m.generation
}

// currentGeneration is the manifest's generation as it stands.
func (m *manifest) currentGeneration() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.generation
}
