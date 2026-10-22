package main

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/pause"
)

// strayEntry is a pause entry whose scope names a provider no call of the
// plane carries, or a tool its provider does not serve. A field a call does
// not carry matches, so on an MCP plane such an entry pauses only calls that
// carry no provider, which are calls to names no upstream lists, and the
// operator has to see that it pauses less than it says.
type strayEntry struct {
	id, provider, tool string
}

// pauseTargets is what a pause entry can name on a plane: the providers its
// calls carry, and whether a provider serves a tool of a name, which is nil
// while that is not known.
type pauseTargets struct {
	providers []string
	serves    func(provider, tool string) bool
}

// upstreamTargets are an MCP plane's: its upstreams and, once listed says the
// manifest was read, the tools each lists in manifest.
func upstreamTargets(upstreams []gatewayconfig.UpstreamConfig, manifest []adaptermcp.Entry, listed bool) pauseTargets {
	out := pauseTargets{}
	for _, u := range upstreams {
		out.providers = append(out.providers, u.Name)
	}
	if listed {
		out.serves = func(provider, tool string) bool {
			return slices.ContainsFunc(manifest, func(m adaptermcp.Entry) bool {
				return m.Upstream == provider && m.Tool != nil && m.Tool.Name == tool
			})
		}
	}
	return out
}

// toolTargets are an enforce_api plane's: the providers and the tools of its
// tool table, known from the start.
func toolTargets(tools []gatewayconfig.ToolConfig) pauseTargets {
	out := pauseTargets{serves: func(provider, tool string) bool {
		return slices.ContainsFunc(tools, func(t gatewayconfig.ToolConfig) bool { return t.Provider == provider && t.Name == tool })
	}}
	for _, t := range tools {
		out.providers = append(out.providers, t.Provider)
	}
	return out
}

// targetsOf is what cfg's plane calls, with manifest read when listed.
func targetsOf(cfg *gatewayconfig.Config, manifest []adaptermcp.Entry, listed bool) pauseTargets {
	if cfg.Listener.Kind == gatewayconfig.ListenerEnforceAPI {
		return toolTargets(cfg.Tools)
	}
	return upstreamTargets(cfg.Upstreams, manifest, listed)
}

// strayEntries names, in the file's order, every entry of a provider or
// action scope whose provider is none of to's and, where to knows the tools,
// every tool scope whose tool its provider does not serve. A global entry
// names no provider and is never one; a prompt or resource scope names no
// tool.
func strayEntries(entries []pause.Entry, to pauseTargets) []strayEntry {
	var out []strayEntry
	for _, e := range entries {
		s := e.Scope
		if s.Kind == pause.ScopeGlobal {
			continue
		}
		if !slices.Contains(to.providers, s.Provider) {
			out = append(out, strayEntry{id: e.ID, provider: s.Provider})
			continue
		}
		if to.serves == nil || s.Kind != pause.ScopeAction || s.Action != pause.ActionTool {
			continue
		}
		if !to.serves(s.Provider, s.Name) {
			out = append(out, strayEntry{id: e.ID, provider: s.Provider, tool: s.Name})
		}
	}
	return out
}

// strayIDs is strayEntries over the manifest as it stands, by id: what the
// pause file's reader logs at warn with a change of the snapshot. Before the
// upstreams answered there is no manifest, and only the upstreams are
// judged.
func (p *plane) strayIDs(entries []pause.Entry) []string {
	var ids []string
	for _, e := range p.strayEntries(entries) {
		ids = append(ids, e.id)
	}
	return ids
}

func (p *plane) strayEntries(entries []pause.Entry) []strayEntry {
	var manifest []adaptermcp.Entry
	listed := p.listed.Load()
	if listed {
		manifest = p.adapter.Entries()
	}
	return strayEntries(entries, targetsOf(p.cfg, manifest, listed))
}

// warnStray logs, once the upstreams answered, every entry of the snapshot
// the plane serves that pauses only calls to names no upstream lists. The
// reader logs them with each change after this.
func (p *plane) warnStray() {
	if p.poller == nil {
		return
	}
	if ids := p.strayIDs(p.poller.Current().Entries()); len(ids) > 0 {
		p.logger.Warn("pause entries that pause only calls carrying no provider, which are calls to names no upstream lists", "unlisted_only", ids)
	}
}

// hasGlobal reports whether an entry pauses every call.
func hasGlobal(entries []pause.Entry) bool {
	return slices.ContainsFunc(entries, func(e pause.Entry) bool { return e.Scope.Kind == pause.ScopeGlobal })
}

// pauseFile reads the pause file once with every check a start makes, and
// takes no lock and writes nothing: the file's directory is the writers'
// (ADR-0019). It prints the path, the state, the number of entries and each
// entry naming an upstream this configuration does not have, and never a
// reason. A file the start would refuse fails here, naming the cause. On an
// MCP plane the entries naming a tool are judged by the upstreams check, once
// the manifest is read; an enforce_api plane's tool table is judged here.
func (d *examination) pauseFile(context.Context) (string, string, string) {
	if d.cfg.Pause.File == "" {
		return verdictOK, "pause", "disabled: pause.file is not set, so no call can be paused without a restart"
	}
	path := filepath.ToSlash(d.cfg.Resolve(d.cfg.Pause.File))
	snap := pause.Read(d.cfg.Resolve(d.cfg.Pause.File), time.Now(), d.cfg.Pause.PollInterval)
	if snap.State() == pause.Unknown {
		return verdictFail, "pause", fmt.Sprintf("%s cannot be read: %s: %s; run refuses to start on it",
			path, snap.Cause(), snap.Detail())
	}
	entries := snap.Entries()
	d.pauseEntries = entries
	stray := strayEntries(entries, targetsOf(d.cfg, nil, false))
	if d.cfg.Listener.Kind == gatewayconfig.ListenerEnforceAPI {
		for _, e := range stray {
			if e.tool != "" {
				writeLine(d.out, fmt.Sprintf("       pause entry %s names tool %s of provider %s, which tools does not classify: it pauses no call this plane runs",
					oneLine(e.id), oneLine(strconv.Quote(e.tool)), oneLine(strconv.Quote(e.provider))))
				continue
			}
			writeLine(d.out, fmt.Sprintf("       pause entry %s names provider %s, which no tool in tools has: it pauses no call this plane runs",
				oneLine(e.id), oneLine(strconv.Quote(e.provider))))
		}
		return verdictOK, "pause", fmt.Sprintf("%s is %s: %d entry(ies), %d naming a provider or a tool the tool table does not have; read every %s",
			path, snap.State(), len(entries), len(stray), d.cfg.Pause.PollInterval)
	}
	for _, e := range stray {
		writeLine(d.out, fmt.Sprintf("       pause entry %s names upstream %s, which this configuration does not have: it pauses only calls that carry no provider, which are calls to names no upstream lists",
			oneLine(e.id), oneLine(strconv.Quote(e.provider))))
	}
	return verdictOK, "pause", fmt.Sprintf("%s is %s: %d entry(ies), %d naming an upstream this configuration does not have; read every %s",
		path, snap.State(), len(entries), len(stray), d.cfg.Pause.PollInterval)
}

// strayTools prints each pause entry naming a tool its upstream does not
// list in the manifest just read, and returns how many there are.
func (d *examination) strayTools(manifest []adaptermcp.Entry) int {
	n := 0
	for _, e := range strayEntries(d.pauseEntries, upstreamTargets(d.cfg.Upstreams, manifest, true)) {
		if e.tool == "" {
			continue
		}
		n++
		writeLine(d.out, fmt.Sprintf("       pause entry %s names tool %s, which upstream %s does not list: it pauses only calls to that name that carry no provider, which are calls when no upstream lists it",
			oneLine(e.id), oneLine(strconv.Quote(e.tool)), oneLine(strconv.Quote(e.provider))))
	}
	return n
}
