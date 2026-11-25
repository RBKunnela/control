package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/policywatch"
)

// floorLockWait bounds how long the start waits for the floor directory's
// lock, which a plane beside this one may hold while it raises a floor.
const floorLockWait = 10 * time.Second

// planePolicy is what a plane decides by: the holder, the floor directory it
// raises, and the refresher that reads the bundle and the statement again.
type planePolicy struct {
	holder *policy.Holder
	floor  *policystate.Store
	// refresher is nil on an inspecting plane, which never refreshes.
	refresher *policywatch.Refresher
	start     policywatch.StartResult
}

// startPolicy opens the floor directory, installs what the start rule allows
// and, for a serving plane, makes the refresher. An inspecting plane
// reads the floor and never raises it. Each refusal names the key whose file
// or directory refused.
func startPolicy(cfg *gatewayconfig.Config, logger *slog.Logger, r role) (*planePolicy, error) {
	store, err := policystate.Open(cfg.Resolve(cfg.Policy.StateDir), policystate.KindPlane)
	if err != nil {
		return nil, fmt.Errorf("policy.state_dir: %w", err)
	}
	pp, err := installPolicy(cfg, logger, r, store)
	if err != nil {
		return nil, errors.Join(err, store.Close())
	}
	return pp, nil
}

func installPolicy(cfg *gatewayconfig.Config, logger *slog.Logger, r role, store *policystate.Store) (*planePolicy, error) {
	// Bounded gives up a raise at its deadline even on a disk that stopped
	// answering, which the clock rule would otherwise wait on.
	var floor = policywatch.Bounded(store)
	if r == roleInspect {
		floor = peekFloor{store}
	}
	holder, err := policy.NewFloorHolder(cfg.Policy.BundleID, floor)
	if err != nil {
		return nil, fmt.Errorf("policy.bundle_id: %w", err)
	}
	o, err := policyOptions(cfg, holder, floor, logger)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), floorLockWait)
	defer cancel()
	res, err := policywatch.Start(ctx, o)
	if err != nil {
		return nil, keyedRefusal(cfg, err)
	}
	pp := &planePolicy{holder: holder, floor: store, start: res}
	if r == roleServe {
		logStart(ctx, logger, cfg, store, holder, res)
		if pp.refresher, err = policywatch.New(o); err != nil {
			return nil, err
		}
	}
	return pp, nil
}

// policyOptions is the refresher's view of cfg over holder and floor. The
// monotonic clock is time.Since an origin read here, which Go reads from the
// monotonic clock.
func policyOptions(cfg *gatewayconfig.Config, holder *policy.Holder, floor policy.FloorStore, logger *slog.Logger) (policywatch.Options, error) {
	bundleKey, err := policykey.ParsePublic(cfg.Policy.PublicKey)
	if err != nil {
		return policywatch.Options{}, fmt.Errorf("policy.public_key: %w", err)
	}
	freshnessKey, err := policykey.ParsePublic(cfg.Policy.FreshnessPublicKey)
	if err != nil {
		return policywatch.Options{}, fmt.Errorf("policy.freshness_public_key: %w", err)
	}
	origin := time.Now()
	return policywatch.Options{
		BundleID:      cfg.Policy.BundleID,
		BundlePath:    cfg.Resolve(cfg.Policy.BundleFile),
		StatementPath: cfg.Resolve(cfg.Policy.StatementFile),
		BundleKeys:    bundle.Keyring{cfg.Policy.KeyID: bundleKey},
		FreshnessKeys: bundle.Keyring{cfg.Policy.FreshnessKeyID: freshnessKey},
		Holder:        holder,
		Floor:         floor,
		Interval:      cfg.Policy.PollInterval,
		MaxStale:      cfg.Policy.MaxStale,
		Wall:          time.Now,
		Mono:          func() time.Duration { return time.Since(origin) },
		Logger:        logger,
	}, nil
}

// keyedRefusal names the key whose file or directory refused the start. A
// bundle signed under another key id than the pinned one says both, the
// bundle's cut to a bound, since nothing has verified it.
func keyedRefusal(cfg *gatewayconfig.Config, err error) error {
	var se *policywatch.StartError
	if !errors.As(err, &se) {
		return fmt.Errorf("policy: %w", err)
	}
	switch {
	case se.Input == policywatch.InputFloor:
		return fmt.Errorf("policy.state_dir: %w", err)
	case se.Input == policywatch.InputStatement:
		return fmt.Errorf("policy.statement_file: %w", err)
	case errors.Is(err, policy.ErrKey) && se.BundleKeyID != cfg.Policy.KeyID:
		return fmt.Errorf("policy.bundle_file: signed under key_id %q, and policy.key_id is %q: %w", shortID(se.BundleKeyID), cfg.Policy.KeyID, err)
	}
	return fmt.Errorf("policy.bundle_file: %w", err)
}

// logStart says how the policy started, in the state /healthz names, with the
// floor as the start left it, and the operator's last reset of the floor,
// which only a start reports.
func logStart(ctx context.Context, logger *slog.Logger, cfg *gatewayconfig.Config, store *policystate.Store, holder *policy.Holder, res policywatch.StartResult) {
	floor := floorText(res.Floor)
	rec, err := store.Record(ctx, cfg.Policy.BundleID)
	switch {
	case err != nil:
		logger.Warn("the floor's record cannot be read to report its last reset", "err", err)
	case rec.Reset != nil:
		floor = floorText(rec.Floor)
		from := floorText(rec.Reset.From)
		if rec.Reset.FileMissing {
			from = "unknown: the reset found no floor file"
		}
		logger.Warn("the floor was reset by the operator", "reason", rec.Reset.Reason, "from", from, "floor", floor)
	default:
		floor = floorText(rec.Floor)
	}
	state, expires := policywatch.Freshness(holder.Current(), cfg.Policy.MaxStale, time.Now())
	if state == policywatch.Confirmed {
		logger.Info("the policy starts confirmed", "expires_at", policy.FormatIssuedAt(expires), "floor", floor)
		return
	}
	logger.Warn("the policy starts "+state.String()+": every call is POLICY_STALE until a statement confirms it",
		"cause", res.Unconfirmed, "floor", floor)
}

// floorText is a floor as the plane's log and doctor print it.
func floorText(f policy.Floor) string {
	if !f.HasSerial() {
		return "no serial yet"
	}
	return "serial " + strconv.FormatInt(f.Serial(), 10) + " digest " + f.Digest() +
		" issued_at " + policy.FormatIssuedAt(f.IssuedAt())
}

// peekFloor reads the floor and judges a raise without writing it: an
// inspecting plane installs what a start would, and the floor stays as it is.
type peekFloor struct{ store *policystate.Store }

func (p peekFloor) Floor(ctx context.Context, bundleID string) (policy.Floor, error) {
	return p.store.Floor(ctx, bundleID)
}

func (p peekFloor) RaiseAt(ctx context.Context, st policy.Statement, now policy.Reading) (policy.Floor, error) {
	f, err := p.store.Floor(ctx, st.BundleID())
	if err != nil {
		return policy.Floor{}, err
	}
	at, err := now()
	if err != nil {
		return policy.Floor{}, err
	}
	return f.Raise(st, at)
}
