package policywatch_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policywatch"
)

// The plane's bundle id, and the ids of the bundle key and the freshness key.
const (
	planeID     = "plane"
	bundleKeyID = "k1"
	freshKeyID  = "f1"
	// interval is the poll interval every rig runs under, and operatorBudget
	// policy.max_stale.
	interval       = 5 * time.Second
	operatorBudget = 10 * time.Minute
)

// t0 is when the rig's first statement is issued.
var t0 = time.Date(2026, time.October, 2, 12, 0, 0, 0, time.UTC)

func seededKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func publicOf(k ed25519.PrivateKey) ed25519.PublicKey {
	pub, _ := k.Public().(ed25519.PublicKey)
	return pub
}

var (
	bundleKey = seededKey(1)
	freshKey  = seededKey(2)
	otherKey  = seededKey(3)
)

// doc is a policy of id at serial, with a budget of maxStale seconds; version
// tells two documents of one serial apart.
func doc(id string, serial int64, version string, maxStale int64) []byte {
	return fmt.Appendf(nil, `{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":%q,"version":%q,"serial":%d,"maxStaleSeconds":%d},`+
		`"rules":[{"id":"reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}}]}`, id, version, serial, maxStale)
}

// signed is the bundle of document signed by key under the bundle key's id,
// so a bundle signed by another key names a key id the plane pins.
func signed(t *testing.T, document []byte, key ed25519.PrivateKey) *controlv1.PolicyBundle {
	t.Helper()
	b, err := policy.Sign(document, key, bundleKeyID)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return b
}

func marshal(t *testing.T, b *controlv1.PolicyBundle) []byte {
	t.Helper()
	raw, err := proto.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}

// statementBytes is the statement file naming id, serial and digest, issued
// at, signed by key under keyID.
func statementBytes(t *testing.T, id string, serial int64, digest string, at time.Time, key ed25519.PrivateKey, keyID string) []byte {
	t.Helper()
	env, err := policy.SignStatement(id, serial, digest, at, key, keyID)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	raw, err := policykey.MarshalStatement(env)
	if err != nil {
		t.Fatalf("MarshalStatement: %v", err)
	}
	return raw
}

// memFloor is a floor store in memory: Raise judges with Floor.Raise and
// keeps the result, as the store on disk does under its lock. failRaise
// fails every raise after the floor judged it; failRead every read. writes
// counts the raises that changed the floor.
type memFloor struct {
	mu        sync.Mutex
	floor     policy.Floor
	failRaise bool
	failRead  bool
	writes    int
	// blocked, when set, makes Raise wait until its context ends, as a raise
	// does while another process holds the directory's lock; each such raise
	// is announced on it first.
	blocked chan struct{}
	// hung, when set, makes Raise wait until it is closed whatever its
	// context says, as a write to a disk that stopped answering does; each
	// such raise is announced on it first.
	hung chan struct{}
	// readBlocked, when set, makes Floor wait until its context ends; each
	// such read is announced on it first.
	readBlocked chan struct{}
}

var errStore = errors.New("memFloor: the store failed")

func (s *memFloor) Floor(ctx context.Context, _ string) (policy.Floor, error) {
	s.mu.Lock()
	if blocked := s.readBlocked; blocked != nil {
		s.mu.Unlock()
		blocked <- struct{}{}
		<-ctx.Done()
		return policy.Floor{}, ctx.Err()
	}
	defer s.mu.Unlock()
	if s.failRead {
		return policy.Floor{}, errStore
	}
	return s.floor, nil
}

func (s *memFloor) Raise(ctx context.Context, st policy.Statement, now time.Time) (policy.Floor, error) {
	s.mu.Lock()
	if hung := s.hung; hung != nil {
		s.mu.Unlock()
		hung <- struct{}{}
		<-hung
		return policy.Floor{}, errStore
	}
	if blocked := s.blocked; blocked != nil {
		s.mu.Unlock()
		blocked <- struct{}{}
		<-ctx.Done()
		return policy.Floor{}, ctx.Err()
	}
	defer s.mu.Unlock()
	next, err := s.floor.Raise(st, now)
	if err != nil {
		return policy.Floor{}, err
	}
	if s.failRaise {
		return policy.Floor{}, errStore
	}
	if !next.Equal(s.floor) {
		s.floor, s.writes = next, s.writes+1
	}
	return next, nil
}

func (s *memFloor) stored() (policy.Floor, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.floor, s.writes
}

// clock is a wall clock and a monotonic clock a test moves.
type clock struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

func (c *clock) Wall() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

func (c *clock) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono
}

// tick moves the monotonic clock by d and the wall clock by wall.
func (c *clock) tick(d, wall time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mono += d
	c.wall = c.wall.Add(wall)
}

// advance moves both clocks by d.
func (c *clock) advance(d time.Duration) { c.tick(d, d) }

// rig is one plane's two files, its floor, its holder and its clocks.
type rig struct {
	t         *testing.T
	dir       string
	store     *memFloor
	holder    *policy.Holder
	clock     *clock
	opts      policywatch.Options
	refresher *policywatch.Refresher
	// bundles holds what was written by serial and version, for its digest.
	digests map[string]string
}

func newRig(t *testing.T, floor policy.Floor) *rig {
	t.Helper()
	dir := t.TempDir()
	store := &memFloor{floor: floor}
	h, err := policy.NewFloorHolder(planeID, store)
	if err != nil {
		t.Fatalf("NewFloorHolder: %v", err)
	}
	c := &clock{wall: t0.Add(30 * time.Second), mono: time.Hour}
	r := &rig{t: t, dir: dir, store: store, holder: h, clock: c, digests: map[string]string{}}
	r.opts = policywatch.Options{
		BundleID:      planeID,
		BundlePath:    filepath.Join(dir, "policy.bundle"),
		StatementPath: filepath.Join(dir, "policy.statement"),
		BundleKeys:    bundle.Keyring{bundleKeyID: publicOf(bundleKey)},
		FreshnessKeys: bundle.Keyring{freshKeyID: publicOf(freshKey)},
		Holder:        h,
		Floor:         store,
		Interval:      interval,
		MaxStale:      operatorBudget,
		Wall:          c.Wall,
		Mono:          c.Mono,
	}
	return r
}

func emptyFloor(t *testing.T) policy.Floor {
	t.Helper()
	f, err := policy.EmptyFloor(planeID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// writeBundle signs and writes the bundle of planeID at serial and returns
// its digest.
func (r *rig) writeBundle(serial int64, version string, maxStale int64) string {
	r.t.Helper()
	b := signed(r.t, doc(planeID, serial, version, maxStale), bundleKey)
	r.write(r.opts.BundlePath, marshal(r.t, b))
	r.digests[fmt.Sprint(serial, version)] = b.GetRef().GetDigest()
	return b.GetRef().GetDigest()
}

// writeStatement signs and writes a statement for planeID at serial and
// digest, issued at.
func (r *rig) writeStatement(serial int64, digest string, at time.Time) {
	r.t.Helper()
	r.write(r.opts.StatementPath, statementBytes(r.t, planeID, serial, digest, at, freshKey, freshKeyID))
}

func (r *rig) write(path string, raw []byte) {
	r.t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

// startConfirmed writes bundle serial 2 and its statement issued at t0 and
// installs it confirmed, raising the floor, and starts the refresher.
func (r *rig) startConfirmed() string {
	r.t.Helper()
	digest := r.writeBundle(2, "v2", 600)
	r.writeStatement(2, digest, t0)
	raw, err := os.ReadFile(r.opts.BundlePath)
	if err != nil {
		r.t.Fatal(err)
	}
	var b controlv1.PolicyBundle
	if err := proto.Unmarshal(raw, &b); err != nil {
		r.t.Fatal(err)
	}
	env, err := policykey.ReadStatement(r.opts.StatementPath)
	if err != nil {
		r.t.Fatal(err)
	}
	st, err := policy.VerifyStatement(env, r.opts.FreshnessKeys)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.holder.InstallConfirmed(context.Background(), &b, r.opts.BundleKeys, st, t0); err != nil {
		r.t.Fatalf("InstallConfirmed: %v", err)
	}
	r.newRefresher()
	return digest
}

func (r *rig) newRefresher() {
	r.t.Helper()
	ref, err := policywatch.New(r.opts)
	if err != nil {
		r.t.Fatalf("New: %v", err)
	}
	r.refresher = ref
}

func (r *rig) poll() { r.refresher.Poll(context.Background()) }

// expectSnapshot fails unless the holder serves serial, digest, confirmed at
// confirmed or unconfirmed for the zero time.
func (r *rig) expectSnapshot(serial int64, digest string, confirmed time.Time) {
	r.t.Helper()
	cur := r.holder.Current()
	if cur == nil {
		r.t.Fatalf("no snapshot, want serial %d", serial)
	}
	if cur.Serial() != serial || cur.Ref().GetDigest() != digest || !cur.ConfirmedAt().Equal(confirmed) {
		r.t.Fatalf("the holder serves serial %d, digest %s, confirmed %v; want %d, %s, %v",
			cur.Serial(), cur.Ref().GetDigest(), cur.ConfirmedAt(), serial, digest, confirmed)
	}
}

// expectFloor fails unless the store holds serial, digest and issuedAt.
func (r *rig) expectFloor(serial int64, digest string, issued time.Time) {
	r.t.Helper()
	f, _ := r.store.stored()
	if f.Serial() != serial || f.Digest() != digest || !f.IssuedAt().Equal(issued) {
		r.t.Fatalf("the floor holds serial %d, digest %s, issued %v; want %d, %s, %v",
			f.Serial(), f.Digest(), f.IssuedAt(), serial, digest, issued)
	}
}

// statementOf is the verified statement for planeID at serial and digest,
// issued at.
func statementOf(t *testing.T, serial int64, digest string, at time.Time) policy.Statement {
	t.Helper()
	env, err := policy.SignStatement(planeID, serial, digest, at, freshKey, freshKeyID)
	if err != nil {
		t.Fatal(err)
	}
	st, err := policy.VerifyStatement(env, bundle.Keyring{freshKeyID: publicOf(freshKey)})
	if err != nil {
		t.Fatal(err)
	}
	return st
}
