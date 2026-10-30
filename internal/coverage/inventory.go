package coverage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/guardana/control/internal/netname"
)

// InventoryVersion is the one inventory schema_version this package reads.
const InventoryVersion = "0.1"

// The kinds of path an inventory declares.
const (
	KindMCPTool = "mcp_tool"
	KindHTTPAPI = "http_api"
	KindProcess = "process"
	KindEgress  = "egress"
	// KindEnforceTool is a tool a client asks the enforcement API about
	// before it acts, named as the listener's tool table names it.
	KindEnforceTool = "enforce_tool"
)

const (
	maxInventoryBytes = 1 << 20
	maxIDBytes        = 64
)

// kindNames is, per kind, the members that name a path of it.
var kindNames = map[string][]string{
	KindMCPTool: {"upstream", "tool"},
	KindHTTPAPI: {"name"},
	KindProcess: {"name"},
	KindEgress:  {"host"},
	// An enforce_tool is named as a tool table names it, with no upstream.
	KindEnforceTool: {"tool"},
}

// Inventory is the operator's statement of the paths agents are expected to
// take, in the order written.
type Inventory struct {
	Paths []Path
}

// Path is one declared path. Which names are set depends on Kind: Upstream
// and Tool for mcp_tool, Tool for enforce_tool, Host for egress, Name for
// http_api and process.
type Path struct {
	ID       string
	Kind     string
	Upstream string
	Tool     string
	Host     string
	Name     string
	// Sources are the observation sources that would see the path, and the
	// names an observation of it carries there.
	Sources []PathSource
}

// PathSource names how one source's observations name the path: a tool
// observation whose subject name is Name and, when ServerAddress is set,
// whose server address is ServerAddress; on an egress path, a connection
// whose host is Name.
type PathSource struct {
	SourceID      string
	Name          string
	ServerAddress string
}

// ReadInventory parses an inventory's bytes as an operator's document is
// read: strict JSON of at most 1 MiB, an unknown or repeated member refused,
// schema_version "0.1" only, and at least one path. An id is 1 to 64 bytes of
// [a-z0-9._-] and unique, an mcp_tool's upstream and tool pair is unique, and
// a path names a source once, and an enforce_tool's tool is unique. An egress
// path's host and its sources' names are hosts in netname's one spelling,
// the one a connection's host is written in, and its sources carry no
// server_address. Every refusal wraps ErrInventory.
func ReadInventory(b []byte) (*Inventory, error) {
	inv, err := readInventory(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInventory, err)
	}
	return inv, nil
}

func readInventory(b []byte) (*Inventory, error) {
	if len(b) > maxInventoryBytes {
		return nil, fmt.Errorf("%d bytes, limit %d", len(b), maxInventoryBytes)
	}
	if err := strictJSON(b); err != nil {
		return nil, err
	}
	top, err := object(bytes.TrimSpace(b), "schema_version", "paths")
	if err != nil {
		return nil, err
	}
	if v, err := top.str("schema_version"); err != nil || v != InventoryVersion {
		return nil, fmt.Errorf("schema_version: want %q", InventoryVersion)
	}
	raws, err := top.list("paths")
	if err != nil || len(raws) == 0 {
		return nil, fmt.Errorf("paths: want a list of at least one path")
	}
	inv := &Inventory{Paths: make([]Path, 0, len(raws))}
	for i, raw := range raws {
		p, err := readPath(raw)
		if err != nil {
			return nil, fmt.Errorf("paths[%d]: %w", i, err)
		}
		inv.Paths = append(inv.Paths, p)
	}
	if err := unique(inv.Paths); err != nil {
		return nil, err
	}
	return inv, nil
}

// unique refuses an id declared twice, an upstream's tool declared twice, and
// an enforce_tool's tool declared twice.
func unique(paths []Path) error {
	ids, tools, named := map[string]bool{}, map[[2]string]bool{}, map[string]bool{}
	for i, p := range paths {
		pair := [2]string{p.Upstream, p.Tool}
		switch {
		case ids[p.ID]:
			return fmt.Errorf("paths[%d]: id %s declared twice", i, p.ID)
		case p.Kind == KindMCPTool && tools[pair]:
			return fmt.Errorf("paths[%d]: tool %s on %s declared twice", i, strconv.QuoteToASCII(p.Tool), strconv.QuoteToASCII(p.Upstream))
		case p.Kind == KindEnforceTool && named[p.Tool]:
			return fmt.Errorf("paths[%d]: %s %s declared twice", i, KindEnforceTool, strconv.QuoteToASCII(p.Tool))
		}
		ids[p.ID] = true
		switch p.Kind {
		case KindMCPTool:
			tools[pair] = true
		case KindEnforceTool:
			named[p.Tool] = true
		}
	}
	return nil
}

func readPath(raw json.RawMessage) (Path, error) {
	probe, err := object(raw, "id", "kind", "upstream", "tool", "host", "name", "sources")
	if err != nil {
		return Path{}, err
	}
	kind, err := probe.str("kind")
	names, known := kindNames[kind]
	if err != nil || !known {
		return Path{}, fmt.Errorf("kind: want %s, %s, %s, %s or %s", KindMCPTool, KindEnforceTool, KindHTTPAPI, KindProcess, KindEgress)
	}
	m, err := object(raw, append([]string{"id", "kind", "sources"}, names...)...)
	if err != nil {
		return Path{}, fmt.Errorf("%s: %w", kind, err)
	}
	p := Path{Kind: kind}
	if p.ID, err = m.str("id"); err != nil || !validID(p.ID) {
		return Path{}, fmt.Errorf("id: want 1 to %d bytes of [a-z0-9._-]", maxIDBytes)
	}
	fields := map[string]*string{"upstream": &p.Upstream, "tool": &p.Tool, "host": &p.Host, "name": &p.Name}
	for _, name := range names {
		if err := required(m, name, fields[name]); err != nil {
			return Path{}, err
		}
	}
	if kind == KindEgress {
		if p.Host, err = egressHost(p.Host); err != nil {
			return Path{}, fmt.Errorf("host: %w", err)
		}
	}
	p.Sources, err = readSources(m, kind)
	return p, err
}

func readSources(m members, kind string) ([]PathSource, error) {
	raws, err := m.list("sources")
	if err != nil {
		return nil, err
	}
	var out []PathSource
	seen := map[string]bool{}
	for i, raw := range raws {
		s, err := object(raw, "source_id", "name", "server_address")
		if err != nil {
			return nil, fmt.Errorf("sources[%d]: %w", i, err)
		}
		var ps PathSource
		if err := required(s, "source_id", &ps.SourceID); err != nil {
			return nil, fmt.Errorf("sources[%d]: %w", i, err)
		}
		if err := required(s, "name", &ps.Name); err != nil {
			return nil, fmt.Errorf("sources[%d]: %w", i, err)
		}
		if kind == KindEgress {
			if err := egressSource(s, &ps); err != nil {
				return nil, fmt.Errorf("sources[%d]: %w", i, err)
			}
		} else if _, ok := s["server_address"]; ok {
			if err := required(s, "server_address", &ps.ServerAddress); err != nil {
				return nil, fmt.Errorf("sources[%d]: %w", i, err)
			}
		}
		if seen[ps.SourceID] {
			return nil, fmt.Errorf("sources[%d]: source %s named twice", i, strconv.QuoteToASCII(ps.SourceID))
		}
		seen[ps.SourceID] = true
		out = append(out, ps)
	}
	return out, nil
}

// egressSource holds a source of an egress path to a host for its name and no
// server_address, which a connection does not carry.
func egressSource(s members, ps *PathSource) error {
	if _, ok := s["server_address"]; ok {
		return fmt.Errorf("server_address: not a member of an %s path's source", KindEgress)
	}
	name, err := egressHost(ps.Name)
	if err != nil {
		return fmt.Errorf("name: %w", err)
	}
	ps.Name = name
	return nil
}

// egressHost holds s to the one spelling a connection's host is written in.
// A host in another spelling, in capitals or as an IPv4-mapped IPv6 address
// among them, is refused with the spelling to write instead: read as written,
// it would match no connection.
func egressHost(s string) (string, error) {
	h, ok := netname.Host(s)
	switch {
	case !ok:
		return "", fmt.Errorf("%s is not a host", strconv.QuoteToASCII(clip(s)))
	case h != s:
		return "", fmt.Errorf("%s is not in the one spelling a connection's host has: write %s",
			strconv.QuoteToASCII(clip(s)), strconv.QuoteToASCII(h))
	}
	return h, nil
}

// required reads member name into dst as a name text accepts.
func required(m members, name string, dst *string) error {
	if _, ok := m[name]; !ok {
		return fmt.Errorf("%s: required", name)
	}
	s, err := m.str(name)
	if err != nil {
		return err
	}
	if err := text(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	*dst = s
	return nil
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > maxIDBytes {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
