package gatewayconfig

import (
	"fmt"

	"github.com/guardana/control/pkg/contract"
)

// checkIdentifiers refuses a key an envelope carries that contract.CheckID
// refuses, naming the key: the plane's project, tenant and environment, the
// listener's principal and agent, and an upstream's tenant and environment.
// Validate holds each of these fields to the identifier rule and its bound,
// so the contract would refuse every call instead. An empty optional key is
// unset; checkRequired has refused an empty required one.
func (c *Config) checkIdentifiers() error {
	type key struct{ path, value string }
	l := c.Listener
	keys := []key{
		{"project_id", c.ProjectID}, {"tenant_id", c.TenantID}, {"environment", c.Environment},
		{"listener.principal.id", l.PrincipalID}, {"listener.principal.type", l.PrincipalType},
		{"listener.principal.tenant_id", l.PrincipalTenant},
		{"listener.agent.id", l.AgentID}, {"listener.agent.framework", l.AgentFramework}, {"listener.agent.version", l.AgentVersion},
	}
	for i, up := range c.Upstreams {
		keys = append(keys, key{fmt.Sprintf("upstreams.%d.tenant_id", i), up.TenantID},
			key{fmt.Sprintf("upstreams.%d.environment", i), up.Environment})
	}
	for _, k := range keys {
		if k.value == "" {
			continue
		}
		if err := contract.CheckID(k.value); err != nil {
			return fmt.Errorf("%s: %w", k.path, err)
		}
	}
	return nil
}
