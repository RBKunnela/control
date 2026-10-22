package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policystate"
)

// raiseSignerFloor raises the signer's floor in dir to st and, once the floor
// took it, runs then under the directory's lock. Opening the directory and
// raising share one wait of floorLockWait for its lock. A refusal of the
// raise names what the floor holds when it can be read; then's error is
// returned as it is.
func raiseSignerFloor(dir string, st policy.Statement, now time.Time, then func() error) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), floorLockWait)
	defer cancel()
	store, err := policystate.OpenContext(ctx, dir, policystate.KindSigner)
	if err != nil {
		return fmt.Errorf("--floor %s: %w", dir, lockWaited(err))
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("--floor %s: %w", dir, closeErr))
		}
	}()
	var ran bool
	var thenErr error
	_, err = store.RaiseWith(ctx, st, now, func(policy.Floor) error {
		ran = true
		thenErr = then()
		return thenErr
	})
	switch {
	case err == nil:
		return nil
	case ran && thenErr != nil:
		return err
	case ran:
		return fmt.Errorf("--floor %s: %w", dir, err)
	}
	err = lockWaited(err)
	id := oneLine(st.BundleID())
	if f, readErr := store.Floor(ctx, st.BundleID()); readErr == nil {
		return fmt.Errorf("--floor %s: bundle id %s: %w; the signer floor holds %s", dir, id, err, floorText(f))
	}
	return fmt.Errorf("--floor %s: bundle id %s: %w", dir, id, err)
}

// lockWaited names a wait for the floor directory's lock that ran out.
func lockWaited(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w; another holder kept the floor directory's lock past %s", err, floorLockWait)
	}
	return err
}

// floorText is a floor as the commands print it.
func floorText(f policy.Floor) string {
	if !f.HasSerial() {
		return "no serial"
	}
	return "serial " + strconv.FormatInt(f.Serial(), 10) + " digest " + f.Digest() +
		" issued_at " + policy.FormatIssuedAt(f.IssuedAt()) + " latest_issued_at " + policy.FormatIssuedAt(f.LatestIssuedAt())
}
