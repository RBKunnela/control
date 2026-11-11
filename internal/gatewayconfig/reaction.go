package gatewayconfig

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
)

// ReactionConfig names the signed route under which a finding may stop one
// run, the file holding the public key the route is signed with, the route
// floor's directory and the stop list's directory, and how often the plane
// reads the list (ADR-0046). The four names are set together or not at all;
// with none the plane has no route and says its stops are disabled.
type ReactionConfig struct {
	Route        string
	PublicKey    string
	FloorDir     string
	Stops        string
	PollInterval time.Duration
	// StopsFloorDir is the stop list floor's directory, which only the
	// signed authority reads: its route, header and lifts are an operator's,
	// and no route key is set.
	StopsFloorDir string
}

// Configured reports whether a route is configured; the load refuses a
// configuration that names only some of the four.
func (r ReactionConfig) Configured() bool { return r.Route != "" }

// The bounds of reaction.poll_interval, those of pause.poll_interval: a stop
// bites up to one interval after it is written.
const (
	minStopPoll = minPausePoll
	maxStopPoll = maxPausePoll
)

// checkReaction refuses a route named without the rest of what serves it, a
// poll interval with no route to apply to or outside its bounds, a route on a
// plane with no runs directory, whose opened runs are the only ones a stop can
// name, and a stop list's directory that shares a path with one the plane or
// its commands lock or own.
func (c *Config) checkReaction() error {
	keyed := []struct{ key, value string }{
		{"reaction.route", c.Reaction.Route},
		{"reaction.floor_dir", c.Reaction.FloorDir},
		{"reaction.stops", c.Reaction.Stops},
	}
	together := "reaction.route, reaction.public_key, reaction.floor_dir and reaction.stops"
	refused := struct{ key, value string }{"reaction.stops_floor_dir", c.Reaction.StopsFloorDir}
	if c.Approvals.Authority == AuthoritySigned {
		together = "reaction.route, reaction.floor_dir, reaction.stops and reaction.stops_floor_dir under the signed authority"
		keyed = append(keyed, refused)
		refused = struct{ key, value string }{"reaction.public_key", c.Reaction.PublicKey}
	} else {
		keyed = append(keyed, struct{ key, value string }{"reaction.public_key", c.Reaction.PublicKey})
	}
	if refused.value != "" {
		return fmt.Errorf("%s: set, and the %s authority reads no such key; under signed an operator signs the route and its lifts, and the plane keeps a stop list floor (ADR-0077)",
			refused.key, c.Approvals.Authority)
	}
	var set, missing []string
	for _, k := range keyed {
		if k.value == "" {
			missing = append(missing, k.key)
		} else {
			set = append(set, k.key)
		}
	}
	switch {
	case len(set) == 0:
		if c.wasSet("reaction.poll_interval") {
			return fmt.Errorf("reaction.poll_interval: set, and reaction.route names no route for it to apply to")
		}
		return nil
	case len(missing) > 0:
		return fmt.Errorf("%s: not set, and %s is; a route is configured with all of %s, or with none (ADR-0046)",
			strings.Join(missing, ", "), strings.Join(set, ", "), together)
	case c.Reaction.PollInterval < minStopPoll || c.Reaction.PollInterval > maxStopPoll:
		return fmt.Errorf("reaction.poll_interval: %v is outside %v to %v", c.Reaction.PollInterval, minStopPoll, maxStopPoll)
	case c.Runs.Dir == "":
		return fmt.Errorf("runs.dir: not set, and reaction.route is; a stop names a run the operator opened, and only a runs directory serves those (ADR-0046)")
	}
	return c.checkStopsDir()
}

// checkStopsDir keeps the stop list's directory apart from every directory a
// plane or the commands beside it lock or own: one inside another, or around
// it, is a directory two writers judge as theirs.
func (c *Config) checkStopsDir() error {
	stops := c.Resolve(c.Reaction.Stops)
	others := []struct{ key, dir string }{
		{"runs.dir", c.Runs.Dir},
		{"evidence.dir", c.Evidence.Dir},
		{"approvals.dir", c.Approvals.Dir},
		{"approvals.hold_journal_dir", c.Approvals.HoldJournalDir},
		{"policy.state_dir", c.Policy.StateDir},
		{"reaction.floor_dir", c.Reaction.FloorDir},
		{"reaction.stops_floor_dir", c.Reaction.StopsFloorDir},
		{"pause.floor_dir", c.Pause.FloorDir},
	}
	if c.Pause.File != "" {
		others = append(others, struct{ key, dir string }{"pause.file", filepath.Dir(c.Resolve(c.Pause.File))})
	}
	for _, other := range others {
		if other.dir == "" {
			continue
		}
		shared, err := sharesDir(stops, c.Resolve(other.dir))
		if err != nil {
			return fmt.Errorf("reaction.stops: %w", err)
		}
		if shared {
			return fmt.Errorf("reaction.stops: %q shares a path with %s %q; the stop list's directory holds the stop list only (ADR-0046)",
				c.Reaction.Stops, other.key, other.dir)
		}
	}
	return nil
}

// sharesDir reports whether directories a and b are one, or one sits inside
// the other, compared by their paths and, where they exist, by identity along
// each one's resolved path, so a link naming one inside the other is caught.
// A pair this build cannot compare is reported as shared.
func sharesDir(a, b string) (bool, error) {
	a, err := asResolved(a)
	if err != nil {
		return true, err
	}
	if b, err = asResolved(b); err != nil {
		return true, err
	}
	for _, compare := range []func() (bool, error){
		func() (bool, error) { return overlaps(a, b) },
		func() (bool, error) { return underSameDir(a, b) },
		func() (bool, error) { return underSameDir(b, a) },
	} {
		if shared, err := compare(); err != nil || shared {
			return true, err
		}
	}
	return false, nil
}

// asResolved is dir as the system resolves it where it exists, every link
// followed, so a link that puts one directory inside another is caught.
func asResolved(dir string) (string, error) {
	resolved, err := filepath.EvalSymlinks(dir)
	switch {
	case err == nil:
		return filepath.Abs(resolved)
	case !errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("%q cannot be compared: %w", dir, err)
	}
	return dir, nil
}

func routeFormat(r reaction.Route) string {
	if r.Signed() {
		return reaction.SignedRouteKind
	}
	return reaction.RouteKind
}

// ListenerTenant is the tenant of the listener's principal: its own, or the
// plane's.
func (c *Config) ListenerTenant() string {
	if c.Listener.PrincipalTenant != "" {
		return c.Listener.PrincipalTenant
	}
	return c.TenantID
}

// CheckRoute holds a route to this configuration: its tenant is the
// listener's, and its format the authority's. A v1alpha2 route names the
// plane's project. For a v1alpha1 route, verified under routeKey, the route
// key, the route's lift key, the policy key and the freshness key are four
// keys, no two of them one as reaction.DistinctKeys compares them, since one
// private key signs for a point and its negation and would then speak for
// two authorities.
func (c *Config) CheckRoute(route reaction.Route, routeKey ed25519.PublicKey) error {
	if tenant := c.ListenerTenant(); route.TenantID() != tenant {
		return fmt.Errorf("reaction.route: its tenant_id is %s and the listener's tenant is %s; a plane stops runs of its own tenant only (ADR-0046)",
			quoteValue(route.TenantID()), quoteValue(tenant))
	}
	if route.Signed() != (c.Approvals.Authority == AuthoritySigned) {
		return fmt.Errorf("reaction.route: a %s route under the %s authority; under signed only a v1alpha2 route an operator signed is read, and elsewhere only a v1alpha1 route (ADR-0077)",
			routeFormat(route), c.Approvals.Authority)
	}
	if route.Signed() {
		if route.ProjectID() != c.ProjectID {
			return fmt.Errorf("reaction.route: its project_id is %s and the plane's project is %s (ADR-0077)",
				quoteValue(route.ProjectID()), quoteValue(c.ProjectID))
		}
		return nil
	}
	policyKey, err := policykey.ParsePublic(c.Policy.PublicKey)
	if err != nil {
		return fmt.Errorf("policy.public_key: %w", err)
	}
	freshnessKey, err := policykey.ParsePublic(c.Policy.FreshnessPublicKey)
	if err != nil {
		return fmt.Errorf("policy.freshness_public_key: %w", err)
	}
	keys := []struct {
		name string
		key  ed25519.PublicKey
	}{
		{"reaction.public_key", routeKey},
		{"the route's lift_public_key", route.LiftKey()},
		{"policy.public_key", policyKey},
		{"policy.freshness_public_key", freshnessKey},
	}
	for i, a := range keys {
		for _, b := range keys[i+1:] {
			if err := reaction.DistinctKeys(a.key, b.key); err != nil {
				return fmt.Errorf("reaction.route: %s and %s: %w; each authority signs with a key of its own (ADR-0046)", a.name, b.name, err)
			}
		}
	}
	return nil
}
