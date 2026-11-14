package gatewayconfig

import "fmt"

// signedKeys is every key only the signed authority reads.
var signedKeys = []string{
	"plane_id", "approvals.inbox_dir", "trust.root_public_key", "trust.roster", "trust.roster_id", "trust.floor_dir",
	"operators.authenticator.kind", "operators.authorizer.kind",
}

// checkSignedKeys requires under the signed authority every key it reads,
// and refuses each of them under any other: a key that applies to nothing is
// a setting the operator believes is in force.
func (c *Config) checkSignedKeys() error {
	for _, key := range signedKeys {
		set := c.show(key) != ""
		switch {
		case c.Approvals.Authority == AuthoritySigned && !set:
			return fmt.Errorf("%s: the %s authority needs it, and it has no default (ADR-0073)", key, AuthoritySigned)
		case c.Approvals.Authority != AuthoritySigned && set:
			return fmt.Errorf("%s: only the %s authority reads it, and the authority is %s", key, AuthoritySigned, c.Approvals.Authority)
		}
	}
	if err := c.checkSignedPause(); err != nil {
		return err
	}
	if c.Approvals.Authority != AuthoritySigned {
		return nil
	}
	if err := c.checkSignedTenant(); err != nil {
		return err
	}
	inbox := c.Resolve(c.Approvals.InboxDir)
	for _, other := range []struct{ key, dir string }{
		{"evidence.dir", c.Resolve(c.Evidence.Dir)},
		{"approvals.dir", c.Resolve(c.Approvals.Dir)},
		{"approvals.hold_journal_dir", c.Resolve(c.Approvals.HoldJournalDir)},
	} {
		overlap, err := sharesDir(inbox, other.dir)
		if err != nil {
			return fmt.Errorf("approvals.inbox_dir: %w", err)
		}
		if overlap {
			return fmt.Errorf("approvals.inbox_dir: %q shares a path with %s %q; operators write the inbox, and the plane alone writes the other (ADR-0073)",
				c.Approvals.InboxDir, other.key, other.dir)
		}
	}
	return nil
}

// checkSignedTenant refuses, under the signed authority, a listener tenant
// apart from the plane's: answers and pauses are judged under tenant_id, runs
// and stops under the listener's tenant, and one plane serves one tenant
// (ADR-0082).
func (c *Config) checkSignedTenant() error {
	if t := c.Listener.PrincipalTenant; t != "" && t != c.TenantID {
		return fmt.Errorf("listener.principal.tenant_id: %q is not tenant_id %q; under the %s authority a plane serves one tenant, so leave it unset or set it to tenant_id (ADR-0082)",
			t, c.TenantID, AuthoritySigned)
	}
	return nil
}

// show is the value of the scalar key at path, as doctor prints it.
func (c *Config) show(path string) string {
	for _, f := range configFields {
		if f.path == path {
			return f.show(c)
		}
	}
	return ""
}
