package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/gatewayconfig"
)

// printSettings prints every bound and every choice the plane will run with,
// and where each came from, so the defaults are read rather than assumed. A
// header value is a credential and is never printed, and every other value
// passes through oneLine: an upstream's arguments may carry a certificate,
// and a value may carry a line break.
func printSettings(w io.Writer, cfg *gatewayconfig.Config) {
	sources := cfg.Sources()
	for _, s := range cfg.Settings() {
		source := "default"
		if where, ok := sources[s.Path]; ok {
			source = where
		}
		value := s.Value
		if s.Path == "upstream.list_timeout" && cfg.Upstream.ListTimeout == 0 {
			value = adaptermcp.DefaultListTimeout.String() + " (0s: adapter's own)"
		}
		writeLine(w, fmt.Sprintf("       %-28s %-24s (%s)", s.Path, oneLine(value), oneLine(source)))
	}
	printHeaders(w, gatewayconfig.HeadersPrefix, cfg.Export.Headers)
	printHeaders(w, gatewayconfig.PDPHeadersPrefix, cfg.PDP.Headers)
	for i, origin := range cfg.Listener.Origins {
		writeLine(w, fmt.Sprintf("       %-28s %s", fmt.Sprintf("listener.origins.%d", i), oneLine(origin)))
	}
	for i, name := range cfg.PDP.InformationalContext {
		writeLine(w, fmt.Sprintf("       %-28s %s", fmt.Sprintf("pdp.informational_context.%d", i), oneLine(name)))
	}
	for i, up := range cfg.Upstreams {
		printUpstream(w, i, up)
	}
	printTools(func(line string) { writeLine(w, line) }, cfg.Tools)
	for i, o := range cfg.Overrides {
		writeLine(w, fmt.Sprintf("       %-28s %s/%s is %s on %s from %s, returns %s %s, fingerprint %s",
			fmt.Sprintf("overrides.%d", i), oneLine(o.Upstream), oneLine(o.Tool), o.Effect, oneLine(o.ResourceType),
			oneLine(strconv.Quote(o.ResourceFrom)), orWord(o.ReturnsTrust, "untrusted"), orWord(o.ReturnsSensitivity, "unknown"),
			oneLine(o.Fingerprint)))
	}
}

// printHeaders names each header under prefix, in order, and never its value.
func printHeaders(w io.Writer, prefix string, headers map[string]string) {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		writeLine(w, fmt.Sprintf("       %-28s %-24s (%s)", prefix+name, gatewayconfig.NotPrinted, "credential"))
	}
}
