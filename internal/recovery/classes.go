package recovery

import "github.com/guardana/control/internal/gatewayconfig"

// The class names a manifest files a copy under.
const (
	ClassPlaneFloor     = "floor/plane"
	ClassRouteFloor     = "floor/route"
	ClassAuthorityFloor = "floor/authority"
	ClassPauseFloor     = "floor/pause"
	ClassStopsFloor     = "floor/stops"
	ClassRuns           = "runs"
	ClassPause          = "pause"
	ClassStops          = "stops"
)

// class is one kind of state a backup copies: the configuration key that
// names where it lives, whether that is a directory, and whether only the
// signed authority reads it.
type class struct {
	name       string
	key        string
	value      func(*gatewayconfig.Config) string
	dir        bool
	signedOnly bool
}

// classes is every class a backup copies, in the order a restore takes them:
// the floors first, so a file put back later is judged against them.
var classes = []class{
	{ClassPlaneFloor, "policy.state_dir", func(c *gatewayconfig.Config) string { return c.Policy.StateDir }, true, false},
	{ClassRouteFloor, "reaction.floor_dir", func(c *gatewayconfig.Config) string { return c.Reaction.FloorDir }, true, false},
	{ClassAuthorityFloor, "trust.floor_dir", func(c *gatewayconfig.Config) string { return c.Trust.FloorDir }, true, true},
	{ClassPauseFloor, "pause.floor_dir", func(c *gatewayconfig.Config) string { return c.Pause.FloorDir }, true, true},
	{ClassStopsFloor, "reaction.stops_floor_dir", func(c *gatewayconfig.Config) string { return c.Reaction.StopsFloorDir }, true, true},
	{ClassRuns, "runs.dir", func(c *gatewayconfig.Config) string { return c.Runs.Dir }, true, false},
	{ClassPause, "pause.file", func(c *gatewayconfig.Config) string { return c.Pause.File }, false, false},
	{ClassStops, "reaction.stops", func(c *gatewayconfig.Config) string { return c.Reaction.Stops }, true, false},
}

// neverBackedUp is every key naming a file or a directory that a backup
// leaves out, and why.
var neverBackedUp = map[string]string{
	"listener.socket":            "a socket the plane makes at its start",
	"health.socket":              "a socket the plane makes at its start",
	"policy.bundle_file":         "the signer's; its floor is restored",
	"policy.statement_file":      "the signer's; its floor is restored",
	"approvals.dir":              "the approvals store: a restored one would resume a hold",
	"approvals.hold_journal_dir": "the hold journal and its ledger: a restored one would reuse an approval",
	"approvals.inbox_dir":        "the operators' signed answers to holds that are not restored",
	"trust.root_public_key":      "a key",
	"trust.roster":               "the operators' signed roster; its floor is restored",
	"reaction.route":             "the operators' signed route; its floor is restored",
	"reaction.public_key":        "a key",
	"evidence.dir":               "the spool of trail records not yet exported",
	"upstreams.N.command":        "a program",
}

func classNamed(name string) (class, bool) {
	for _, c := range classes {
		if c.name == name {
			return c, true
		}
	}
	return class{}, false
}

// applies reports whether the class is backed up under authority.
func (c class) applies(authority string) bool {
	return !c.signedOnly || authority == gatewayconfig.AuthoritySigned
}
