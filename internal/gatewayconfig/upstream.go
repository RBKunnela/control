package gatewayconfig

import (
	"fmt"
	"slices"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/pkg/contract"
)

// checkUpstreams refuses an upstream whose name no envelope can carry, one
// that names neither a URL nor a command, or both, arguments or variables
// without a command, and a variable a command may not receive. An enforce_api
// listener has none, which checkKindKeys holds.
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
	// The name is every MCP call's action.provider.
	if err := classify.CheckEnvelopeString(up.Name); err != nil {
		return fmt.Errorf("%sname: %w", at, err)
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

// checkOverrides refuses a classification classify.Parse refuses, one of a
// tool on a server this configuration does not have, which would classify
// nothing and leave the tool blocked, one whose envelope needs an environment
// or a tenant the plane or the upstream leaves unset, and a second
// classification of one upstream's tool, which the adapter would let replace
// the first.
func (c *Config) checkOverrides() error {
	names := map[string]int{}
	for i, up := range c.Upstreams {
		if _, ok := names[up.Name]; !ok {
			names[up.Name] = i
		}
	}
	type tool struct{ upstream, name string }
	seen := make(map[tool]int, len(c.Overrides))
	for i := range c.Overrides {
		o := &c.Overrides[i]
		at := fmt.Sprintf("overrides.%d.", i)
		if err := checkRequired(o, overrideFields, at); err != nil {
			return err
		}
		cls, err := o.Classification()
		if err != nil {
			return fmt.Errorf("%s%w", at, err)
		}
		up, ok := names[o.Upstream]
		if !ok {
			return fmt.Errorf("%supstream: %s is not a configured upstream", at, quoteValue(o.Upstream))
		}
		if err := unsetRequired(at, o.Effect, cls.Effect, keySource{"environment", "environment", c.Environment},
			keySource{"resource.environment", fmt.Sprintf("upstreams.%d.environment", up), c.Upstreams[up].Environment},
			keySource{"resource.tenant_id", fmt.Sprintf("upstreams.%d.tenant_id", up), c.Upstreams[up].TenantID}); err != nil {
			return err
		}
		if first, ok := seen[tool{o.Upstream, o.Tool}]; ok {
			return fmt.Errorf("overrides.%d: the tool %s of %s is classified by overrides.%d already", i, quoteValue(o.Tool), quoteValue(o.Upstream), first)
		}
		seen[tool{o.Upstream, o.Tool}] = i
	}
	return nil
}

// keySource is the key that supplies one path of an envelope.
type keySource struct{ path, key, value string }

// unsetRequired refuses a classification whose envelope needs, by the
// contract's table, a path whose key has no value: every call to the tool
// would be refused, OBSERVE included.
func unsetRequired(at, spelled string, effect controlv1.EffectClass, sources ...keySource) error {
	required := contract.EffectRequires(effect)
	for _, s := range sources {
		if s.value == "" && slices.Contains(required, s.path) {
			return fmt.Errorf("%seffect: %s needs %s, which has no value", at, spelled, s.key)
		}
	}
	return nil
}
