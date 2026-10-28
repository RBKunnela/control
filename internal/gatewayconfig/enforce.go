package gatewayconfig

import (
	"fmt"
	"time"

	"github.com/guardana/control/internal/classify"
)

// The bounds of listener.execution_lifetime and listener.max_body_bytes, the
// enforcement adapter's own.
const (
	minExecutionLifetime = time.Second
	maxExecutionLifetime = time.Hour
	minBodyBytes         = 1 << 10
	maxBodyBytes         = 1 << 18
)

// maxSocketPath is the longest socket path the adapter binds: what a macOS
// sockaddr_un holds, its terminator taken off.
const maxSocketPath = 103

// ToolConfig is the operator's classification of one tool of an enforcement
// API listener, by name. Its resource's tenant and environment are the
// listener's. The trust zone is where a call to the tool sends data; the
// returns keys are what its results contain (ADR-0021).
type ToolConfig struct {
	Name     string
	Provider string
	classify.Spelling
}

// Classification is the tool's classification as the adapter takes it, or
// the refusal naming its key.
func (t *ToolConfig) Classification() (classify.Classification, error) {
	return classify.Parse(t.Spelling)
}

// enforceOnly are the scalar keys only an enforce_api listener reads.
var enforceOnly = []string{"listener.socket", "listener.execution_lifetime", "listener.max_body_bytes", "listener.max_open_per_run"}

// mcpOnly are the scalar keys only an MCP listener reads: they bound an
// upstream or shape a tool list, and an enforce_api listener has neither.
var mcpOnly = []string{"listener.address", "upstream.call_timeout", "upstream.list_timeout", "list.shaping", "list.ttl"}

// checkKindKeys refuses a key the listener's kind does not read: a key that
// applies to nothing is a setting the operator believes is in force.
func (c *Config) checkKindKeys() error {
	if c.Listener.Kind == ListenerEnforceAPI {
		return c.checkEnforceAPI()
	}
	for _, key := range enforceOnly {
		if c.wasSet(key) {
			return fmt.Errorf("%s: only an %s listener reads it, and the kind is %s", key, ListenerEnforceAPI, c.Listener.Kind)
		}
	}
	if len(c.Tools) > 0 {
		return fmt.Errorf("tools: only an %s listener classifies tools by name, and the kind is %s; an MCP tool is classified in overrides", ListenerEnforceAPI, c.Listener.Kind)
	}
	return nil
}

// checkEnforceAPI holds an enforce_api listener to what the enforcement
// adapter serves: a Unix socket, operator-opened runs, a bounded execution
// lifetime and body, and a tool table in place of upstreams (ADR-0051).
func (c *Config) checkEnforceAPI() error {
	for _, key := range mcpOnly {
		if c.wasSet(key) {
			return fmt.Errorf("%s: an %s listener serves no MCP client and calls no upstream, so it reads no %s", key, ListenerEnforceAPI, key)
		}
	}
	if err := c.checkEnforceListener(); err != nil {
		return err
	}
	switch {
	case c.Runs.Dir == "":
		return fmt.Errorf("runs.dir: no value, and every request to an %s listener presents a run token, which only an opened run has (ADR-0034)", ListenerEnforceAPI)
	case len(c.Upstreams) > 0:
		return fmt.Errorf("upstreams: an %s listener calls no upstream; its tools are named in tools", ListenerEnforceAPI)
	case len(c.Overrides) > 0:
		return fmt.Errorf("overrides: an %s listener classifies its tools in tools", ListenerEnforceAPI)
	}
	return c.checkTools()
}

// checkEnforceListener refuses an origin, a missing socket or one whose path
// the adapter cannot bind, a lifetime or a body bound the adapter would
// refuse, and a bound on a run's open executions that is not below the
// plane's: at the plane's own bound a handful of runs would hold every slot.
func (c *Config) checkEnforceListener() error {
	l := c.Listener
	switch {
	case len(l.Origins) > 0:
		return fmt.Errorf("listener.origins: an %s listener serves a Unix socket, which no browser calls", ListenerEnforceAPI)
	case l.Socket == "":
		return fmt.Errorf("listener.socket: an %s listener serves on a Unix socket, and no path is named", ListenerEnforceAPI)
	case len(c.Resolve(l.Socket)) > maxSocketPath:
		return fmt.Errorf("listener.socket: the path is %d bytes as it resolves, and a socket path is at most %d", len(c.Resolve(l.Socket)), maxSocketPath)
	case l.ExecutionLifetime == 0:
		return fmt.Errorf("listener.execution_lifetime: no value, and an %s listener needs one; it has no default", ListenerEnforceAPI)
	case l.ExecutionLifetime < minExecutionLifetime || l.ExecutionLifetime > maxExecutionLifetime:
		return fmt.Errorf("listener.execution_lifetime: %v is outside %v to %v", l.ExecutionLifetime, minExecutionLifetime, maxExecutionLifetime)
	case l.MaxBodyBytes < minBodyBytes || l.MaxBodyBytes > maxBodyBytes:
		return fmt.Errorf("listener.max_body_bytes: %d is outside %d to %d", l.MaxBodyBytes, minBodyBytes, maxBodyBytes)
	case l.MaxOpenPerRun < 1:
		return fmt.Errorf("listener.max_open_per_run: %d is not a positive bound", l.MaxOpenPerRun)
	case c.Approvals.MaxOpen <= l.MaxOpenPerRun:
		return fmt.Errorf("approvals.max_open: %d is at or below listener.max_open_per_run, %d, so one run could hold every open execution of the plane", c.Approvals.MaxOpen, l.MaxOpenPerRun)
	}
	return nil
}

// checkTools refuses an empty table, which would leave every call
// unclassified, an entry missing a key, a name or a provider no envelope can
// carry, a classification classify.Parse refuses, one whose envelope needs an
// environment the plane leaves unset, and a second entry of one name.
func (c *Config) checkTools() error {
	if len(c.Tools) == 0 {
		return fmt.Errorf("tools: no tool; an %s listener blocks every call to a tool it does not classify", ListenerEnforceAPI)
	}
	seen := make(map[string]int, len(c.Tools))
	for i := range c.Tools {
		t := &c.Tools[i]
		if err := checkRequired(t, toolFields, fmt.Sprintf("tools.%d.", i)); err != nil {
			return err
		}
		for _, f := range []struct{ key, value string }{{"name", t.Name}, {"provider", t.Provider}} {
			if err := classify.CheckEnvelopeString(f.value); err != nil {
				return fmt.Errorf("tools.%d.%s: %w", i, f.key, err)
			}
		}
		cls, err := t.Classification()
		if err != nil {
			return fmt.Errorf("tools.%d.%w", i, err)
		}
		// The resource's environment is the listener's too.
		if err := unsetRequired(fmt.Sprintf("tools.%d.", i), t.Effect, cls.Effect, keySource{"environment", "environment", c.Environment},
			keySource{"resource.environment", "environment", c.Environment}); err != nil {
			return err
		}
		if first, ok := seen[t.Name]; ok {
			return fmt.Errorf("tools.%d: the tool %s is classified by tools.%d already", i, quoteValue(t.Name), first)
		}
		seen[t.Name] = i
	}
	return nil
}
