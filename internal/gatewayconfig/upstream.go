package gatewayconfig

import "fmt"

// checkUpstreams refuses an upstream that names neither a URL nor a command,
// or both, arguments or variables without a command, and a variable a
// command may not receive. An enforce_api listener has none, which
// checkKindKeys holds.
func (c *Config) checkUpstreams() error {
	if c.Listener.Kind == ListenerEnforceAPI {
		return nil
	}
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("upstreams: no upstream; the gateway has nothing to serve")
	}
	for i := range c.Upstreams {
		if err := c.checkUpstream(i); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) checkUpstream(i int) error {
	up := c.Upstreams[i]
	at := fmt.Sprintf("upstreams.%d.", i)
	if err := checkRequired(&c.Upstreams[i], upstreamFields, at); err != nil {
		return err
	}
	switch {
	case (up.Endpoint == "") == (up.Command == ""):
		return fmt.Errorf("%s: name either an endpoint or a command, not both and not neither", at[:len(at)-1])
	case up.Command == "" && len(up.Args) > 0:
		return fmt.Errorf("%sargs: arguments without a command", at)
	case up.Command == "" && len(up.Env) > 0:
		return fmt.Errorf("%senv: variables without a command; an HTTP upstream starts no process to pass them to", at)
	}
	if err := checkEnvNames(at+"env.", up.Env); err != nil {
		return err
	}
	if up.Endpoint != "" && !httpURL(up.Endpoint) {
		return notHTTP(at+"endpoint", up.Endpoint)
	}
	return nil
}

// checkOverrides refuses a classification of a tool on a server this
// configuration does not have, which would classify nothing and leave the
// tool blocked, and a second classification of one upstream's tool, which
// the adapter would let replace the first.
func (c *Config) checkOverrides() error {
	names := map[string]bool{}
	for _, up := range c.Upstreams {
		names[up.Name] = true
	}
	type tool struct{ upstream, name string }
	seen := make(map[tool]int, len(c.Overrides))
	for i := range c.Overrides {
		o := &c.Overrides[i]
		at := fmt.Sprintf("overrides.%d.", i)
		if err := checkRequired(o, overrideFields, at); err != nil {
			return err
		}
		if !names[o.Upstream] {
			return fmt.Errorf("%supstream: %s is not a configured upstream", at, quoteValue(o.Upstream))
		}
		if first, ok := seen[tool{o.Upstream, o.Tool}]; ok {
			return fmt.Errorf("overrides.%d: the tool %s of %s is classified by overrides.%d already", i, quoteValue(o.Tool), quoteValue(o.Upstream), first)
		}
		seen[tool{o.Upstream, o.Tool}] = i
	}
	return nil
}
