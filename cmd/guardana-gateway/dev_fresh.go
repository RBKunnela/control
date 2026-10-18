package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"sync"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policykey"
)

// devSigner is what a dev plane renews its statement with: the freshness key,
// drawn apart from the bundle key and held in memory for the session only,
// and the bundle it vouches for. It writes the statement file and nothing
// else.
type devSigner struct {
	// maxStale is the document's own budget.
	maxStale time.Duration
	// every is how often the statement is renewed, set before the plane
	// starts.
	every  time.Duration
	key    ed25519.PrivateKey
	keyID  string
	path   string
	id     string
	serial int64
	digest string

	stop context.CancelFunc
	done sync.WaitGroup
}

// newDevSigner draws the freshness key for b, whose statement it writes at
// path.
func newDevSigner(b *controlv1.PolicyBundle, serial int64, maxStale time.Duration, path string) (*devSigner, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	return &devSigner{
		maxStale: maxStale, key: key, keyID: policykey.KeyID(pub), path: path,
		id: b.GetRef().GetBundleId(), serial: serial, digest: b.GetRef().GetDigest(),
	}, nil
}

// public is the freshness key's public half, which the plane pins.
func (s *devSigner) public() ed25519.PublicKey {
	pub, _ := s.key.Public().(ed25519.PublicKey)
	return pub
}

// renew writes a statement for the bundle issued at now, to the second.
func (s *devSigner) renew(now time.Time) error {
	env, err := policy.SignStatement(s.id, s.serial, s.digest, now.UTC().Truncate(time.Second), s.key, s.keyID)
	if err != nil {
		return err
	}
	return policykey.WriteStatement(s.path, env)
}

// renewalEvery is how often the statement is renewed: a third of the budget
// the plane holds its bundle to, and sooner where the poll interval needs it.
// A statement is issued up to a second before it is written and read up to an
// interval after, so it must be renewed within the budget less twice the
// interval, the interval being at least a second; an interval of half the
// budget or more leaves no period that holds.
func renewalEvery(budget, poll time.Duration) (time.Duration, error) {
	every := min(budget/3, budget-2*poll)
	if every <= 0 {
		return 0, fmt.Errorf("policy.poll_interval: %v is half the %v budget or more, so no renewal keeps the plane fresh between two polls", poll, budget)
	}
	return every, nil
}

// schedule sets how often the statement is renewed for a plane configured as
// cfg, or refuses a poll interval no renewal period holds against.
func (s *devSigner) schedule(cfg *gatewayconfig.Config) (string, error) {
	budget := policy.Budget(s.maxStale, cfg.Policy.MaxStale)
	every, err := renewalEvery(budget, cfg.Policy.PollInterval)
	if err != nil {
		return "", err
	}
	s.every = every
	return renewalLine(every, budget), nil
}

// start renews the statement every period schedule set until halt, saying on
// log when a renewal fails: the plane then turns stale at the end of its
// budget, and /healthz says so.
func (s *devSigner) start(ctx context.Context, log io.Writer) {
	interval := s.every
	ctx, s.stop = context.WithCancel(ctx)
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if err := s.renew(now); err != nil {
					writeLine(log, brand.Gateway+": dev: renewing the freshness statement: "+oneLine(err.Error()))
				}
			}
		}
	}()
}

// halt stops the renewals and clears the key; copies the standard library
// made while signing are not cleared.
func (s *devSigner) halt() {
	if s.stop != nil {
		s.stop()
	}
	s.done.Wait()
	clear(s.key)
}

// renewalLine says how often the statement is renewed and for how long one
// confirms the policy.
func renewalLine(every, budget time.Duration) string {
	return fmt.Sprintf("every %v of the %v budget; a statement confirms the policy for the budget", every, budget)
}
