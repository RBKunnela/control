package recovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// stopsLockWait bounds how long a restore waits for a stop list writer's
// lock on the stops directory.
const stopsLockWait = 10 * time.Second

// maxRouteKeyFileBytes bounds the route key's file, which holds one line.
const maxRouteKeyFileBytes = 1 << 10

// stopsPlan is what a restore under the directory authority does with the
// stop list: keep the live one, saying why, or carry the backup's into a new
// list judged against route.
type stopsPlan struct {
	keep  bool
	why   string
	route reaction.Route
}

// planStops decides the stop list's restore from the live list and the
// backup's copy: a live list that begins with the backup's, or whose lines
// after its header begin with what a carry of the backup's writes, is kept;
// with no live list the backup's is carried; any other live list is
// ErrStopHistories. Short of a live list the backup's begins, the backup's is
// judged against the route at once, so a list no carry would take is refused
// before a restore's first write.
func (r *restorer) planStops(live, from string) (stopsPlan, error) {
	backup, err := readListed(filepath.Join(from, stoplist.FileName), reaction.MaxListBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return stopsPlan{keep: true, why: "the backup holds no list"}, nil
	case err != nil:
		return stopsPlan{}, fmt.Errorf("the backup's list: %w", err)
	}
	cur, err := readListed(filepath.Join(live, stoplist.FileName), reaction.MaxListBytes)
	missing := errors.Is(err, fs.ErrNotExist)
	switch {
	case err == nil && bytes.HasPrefix(cur, backup):
		return stopsPlan{keep: true, why: "kept; it begins with the backup's list"}, nil
	case err != nil && !missing:
		return stopsPlan{}, err
	}
	route, rerr := directoryRoute(r.cfg)
	if rerr != nil {
		return stopsPlan{}, rerr
	}
	carried, err := stopwrite.CarriedLines(route, backup, r.now)
	if err != nil {
		return stopsPlan{}, fmt.Errorf("the backup's list: %w", err)
	}
	if missing {
		return stopsPlan{route: route}, nil
	}
	if _, rest, _ := bytes.Cut(cur, []byte{'\n'}); bytes.HasPrefix(rest, carried) {
		return stopsPlan{keep: true, why: "kept; it carries the backup's list"}, nil
	}
	return stopsPlan{}, fmt.Errorf("%w: %s neither begins with the backup's list nor carries it; move it aside to carry the backup's",
		ErrStopHistories, clip(filepath.Join(live, stoplist.FileName)))
}

// stops restores the stop list: under signed it is an operator's file a
// restore never writes, whose floor is raised; under directory as planStops
// decides, a carry making the stops directory where it is missing.
func (r *restorer) stops(live, from string, signed bool, step func(string) error) (string, error) {
	if signed {
		r.out.PutBack = append(r.out.PutBack, "reaction.stops")
		return "left to an operator; its floor is raised", nil
	}
	plan, err := r.planStops(live, from)
	if err != nil || plan.keep {
		return plan.why, err
	}
	if _, err := os.Lstat(live); errors.Is(err, fs.ErrNotExist) {
		if err := step("make the directory"); err != nil {
			return "", err
		}
		if err := os.Mkdir(live, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	if err := step("carry"); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(r.ctx, stopsLockWait)
	defer cancel()
	got, err := stopwrite.Carry(ctx, from, plan.route, live, plan.route, r.now)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("the backup's list carried into list %s: %d stops, %d covered, %d lines left out",
		got.Header.ListID, got.Stops, got.Covered, got.LeftOut), nil
}

// stopLists is the stop lists a stop list floor's history may be shown by:
// the live list and the backup's copy. One that does not read shows
// nothing, and two floors no list shows one history of are refused.
func (r *restorer) stopLists() [][]byte {
	c, _ := classNamed(ClassStops)
	if c.value(r.cfg) == "" {
		return nil
	}
	live, from, err := r.paths(c)
	if err != nil {
		return nil
	}
	var lists [][]byte
	for _, p := range []string{filepath.Join(live, stoplist.FileName), filepath.Join(from, stoplist.FileName)} {
		if raw, err := readListed(p, reaction.MaxListBytes); err == nil {
			lists = append(lists, raw)
		}
	}
	return lists
}

// directoryRoute reads and verifies the route a plane of the directory
// authority judges its stop list against, as the plane does: under the route
// key, and held to the configuration.
func directoryRoute(cfg *gatewayconfig.Config) (reaction.Route, error) {
	raw, err := files.ReadRegular(cfg.Resolve(cfg.Reaction.Route), reaction.MaxRouteFileBytes, 0)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.route: %w", err)
	}
	env, err := reaction.ParseRouteFile(raw)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.route: %w", err)
	}
	line, err := files.ReadRegular(cfg.Resolve(cfg.Reaction.PublicKey), maxRouteKeyFileBytes, 0)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.public_key: %w", err)
	}
	pub, err := policykey.ParsePublic(string(line))
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.public_key: %w", err)
	}
	route, err := reaction.VerifyRoute(env, pub)
	if err != nil {
		return reaction.Route{}, fmt.Errorf("reaction.route: %w", err)
	}
	if err := cfg.CheckRoute(route, pub); err != nil {
		return reaction.Route{}, err
	}
	return route, nil
}
