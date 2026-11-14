package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/gatewayconfig"
)

// TestADevPlaneTakesOnlyTheTrustDevLaidOut: the dev start check takes a
// configuration naming the trust root, roster, floor, inbox, pause file and
// pause floor dev wrote under its state, the dev roster id and the dev
// plane's id, and refuses each one named elsewhere.
func TestADevPlaneTakesOnlyTheTrustDevLaidOut(t *testing.T) {
	st := devState{dir: t.TempDir()}
	laidOut := func() *gatewayconfig.Config {
		cfg := &gatewayconfig.Config{}
		cfg.Trust.RootPublicKey = filepath.Join(st.dir, "trust", "root.pub")
		cfg.Trust.Roster = filepath.Join(st.dir, "trust", "roster.json")
		cfg.Trust.FloorDir = filepath.Join(st.dir, "trust", "floors")
		cfg.Trust.RosterID = "dev"
		cfg.PlaneID = "dev"
		cfg.Approvals.InboxDir = filepath.Join(st.dir, "inbox")
		cfg.Pause.File = filepath.Join(st.dir, "pause", "pause.json")
		cfg.Pause.FloorDir = filepath.Join(st.dir, "pausefloor")
		return cfg
	}
	check := devSignedStart(st)
	if err := check(laidOut()); err != nil {
		t.Fatalf("the layout dev made: %v", err)
	}
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	for key, spoil := range map[string]func(*gatewayconfig.Config){
		"trust.root_public_key": func(c *gatewayconfig.Config) { c.Trust.RootPublicKey = elsewhere },
		"trust.roster":          func(c *gatewayconfig.Config) { c.Trust.Roster = elsewhere },
		"trust.floor_dir":       func(c *gatewayconfig.Config) { c.Trust.FloorDir = elsewhere },
		"approvals.inbox_dir":   func(c *gatewayconfig.Config) { c.Approvals.InboxDir = elsewhere },
		"trust.roster_id":       func(c *gatewayconfig.Config) { c.Trust.RosterID = "other" },
		"plane_id":              func(c *gatewayconfig.Config) { c.PlaneID = "other" },
		"pause.file":            func(c *gatewayconfig.Config) { c.Pause.File = elsewhere },
		"pause.floor_dir":       func(c *gatewayconfig.Config) { c.Pause.FloorDir = elsewhere },
	} {
		cfg := laidOut()
		spoil(cfg)
		if err := check(cfg); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("%s elsewhere: %v, want it refused by name", key, err)
		}
	}
}
