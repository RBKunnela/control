package policy

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/match"
)

// Holder keeps the current snapshot. Every entry point that changes it is
// serialized; Current is a read that takes no lock. Only NewFloorHolder makes
// a Holder that installs anything: it pins one bundle id and confirms a
// snapshot only by a freshness statement. The zero Holder holds
// nothing and refuses every entry point with ErrNoFloorStore.
type Holder struct {
	mu      sync.Mutex
	current atomic.Pointer[Snapshot]
	// pin is the one bundle id the holder takes.
	pin string
	// installed holds, per bundle id, the highest serial installed and its
	// digest. Guarded by mu.
	installed map[string]installed
	// store is the floor the holder confirms through.
	store FloorStore
	// withdrawn is the latest confirmation Unconfirm took back; until a
	// statement issued after it is accepted, none confirms the holder.
	// Guarded by mu.
	withdrawn time.Time
	// verified is the latest issuedAt the holder verified, from a statement
	// it confirmed or a floor it read; every snapshot it publishes is not
	// before it. It only rises. Guarded by mu.
	verified time.Time
}

// verify raises the latest verified time to at. mu is held.
func (h *Holder) verify(at time.Time) {
	if at.After(h.verified) {
		h.verified = at
	}
}

type installed struct {
	serial int64
	digest string
}

// admit applies the rollback rules to next and records it. mu is held.
func (h *Holder) admit(next *Snapshot) error {
	if err := h.check(next); err != nil {
		return err
	}
	h.record(next)
	return nil
}

// check applies the rollback rules to next. mu is held.
func (h *Holder) check(next *Snapshot) error {
	id, digest := next.ref.GetBundleId(), next.ref.GetDigest()
	if last, ok := h.installed[id]; ok {
		switch {
		case next.serial < last.serial:
			return fmt.Errorf("%w: serial %d after %d", ErrRollback, next.serial, last.serial)
		case next.serial == last.serial && digest != last.digest:
			return fmt.Errorf("%w: serial %d", ErrSerialReused, next.serial)
		}
	}
	return nil
}

// record keeps next as the highest serial installed for its bundle id. mu is
// held.
func (h *Holder) record(next *Snapshot) {
	if h.installed == nil {
		h.installed = make(map[string]installed)
	}
	h.installed[next.ref.GetBundleId()] = installed{serial: next.serial, digest: next.ref.GetDigest()}
}

// Current returns the current snapshot, or nil before the first successful
// install.
func (h *Holder) Current() *Snapshot {
	return h.current.Load()
}

// NewFloorHolder returns a Holder pinned to bundleID whose snapshots are
// confirmed only by a freshness statement, each raising the floor store
// keeps. InstallUnconfirmed, InstallConfirmed, Confirm and Unconfirm are its
// entry points. An empty bundleID is ErrBundlePin and a nil store
// ErrNoFloorStore.
func NewFloorHolder(bundleID string, store FloorStore) (*Holder, error) {
	if bundleID == "" {
		return nil, fmt.Errorf("%w: an empty bundle id pins nothing", ErrBundlePin)
	}
	if store == nil {
		return nil, ErrNoFloorStore
	}
	return &Holder{pin: bundleID, store: store}, nil
}

// InstallUnconfirmed loads b and, when the floor the store holds lets it start
// without its statement, publishes it with no confirmation: a floor with no
// serial yet takes any bundle of its id, and a floor with one only its own,
// the same serial and digest. A lower bundle is ErrBelowFloor, the floor's
// serial with another digest ErrFloorSerialReused and a higher one
// ErrAboveFloorUnbound, which only InstallConfirmed installs. The current
// snapshot's digest again leaves that snapshot, and its confirmation, as it
// is. A bundle of another id than the pin is ErrBundlePin; for the pinned id,
// a serial below one installed before is ErrRollback and the same serial with
// another digest ErrSerialReused.
func (h *Holder) InstallUnconfirmed(ctx context.Context, b *controlv1.PolicyBundle, keys bundle.Keyring) error {
	return h.installUnconfirmed(ctx, b, keys, match.Compile)
}

// installUnconfirmed is InstallUnconfirmed with the compiler as a parameter,
// so that a test can hold one install inside the load and see whether a
// second one waits for it.
func (h *Holder) installUnconfirmed(ctx context.Context, b *controlv1.PolicyBundle, keys bundle.Keyring, compile compiler) error {
	if h.store == nil {
		return ErrNoFloorStore
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	next, err := h.loadPinned(b, keys, compile)
	if err != nil {
		return err
	}
	if cur := h.current.Load(); cur != nil && cur.ref.GetDigest() == next.ref.GetDigest() {
		return nil
	}
	f, err := h.store.Floor(ctx, h.pin)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFloorRead, err)
	}
	v := StartVerdict{BundleSerial: next.serial, FloorSerial: f.serial}
	if err := floorAdmits(f, next); err != nil {
		return v.refuse(err).Cause
	}
	if f.hasSerial && next.serial > f.serial {
		return v.refuse(fmt.Errorf("%w: %w", ErrAboveFloorUnbound, ErrStatementMissing)).Cause
	}
	if err := h.admit(next); err != nil {
		return err
	}
	h.verify(f.latestIssuedAt)
	next.verified = h.verified
	h.current.Store(next)
	return nil
}

// InstallConfirmed loads b and publishes it confirmed at st's issuedAt: a new
// bundle, or the current one renewed. st must name b's bundle id, serial and
// digest (ErrStatementUnbound), the pin and the rollback rules of
// InstallUnconfirmed apply, and the store must raise the floor to st, judged at now, before
// anything is published: a raise the store refuses or fails is ErrFloorRaise,
// wrapping the store's error, and leaves the current snapshot as it was.
func (h *Holder) InstallConfirmed(ctx context.Context, b *controlv1.PolicyBundle, keys bundle.Keyring, st Statement, now time.Time) error {
	return h.InstallConfirmedAt(ctx, b, keys, st, At(now))
}

// InstallConfirmedAt is InstallConfirmed judged at the reading now gives
// once the store holds its lock; an error now returns refuses the raise as
// the store's refusal would.
func (h *Holder) InstallConfirmedAt(ctx context.Context, b *controlv1.PolicyBundle, keys bundle.Keyring, st Statement, now Reading) error {
	if h.store == nil {
		return ErrNoFloorStore
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	next, err := h.loadPinned(b, keys, match.Compile)
	if err != nil {
		return err
	}
	return h.confirm(ctx, next, st, now)
}

// Confirm confirms the current snapshot at st's issuedAt, as InstallConfirmed
// does with the current bundle, so st must name it. With no current snapshot
// it is ErrNoBundle.
func (h *Holder) Confirm(ctx context.Context, st Statement, now time.Time) error {
	return h.ConfirmAt(ctx, st, At(now))
}

// ConfirmAt is Confirm judged at the reading now gives once the store holds
// its lock, as InstallConfirmedAt is.
func (h *Holder) ConfirmAt(ctx context.Context, st Statement, now Reading) error {
	if h.store == nil {
		return ErrNoFloorStore
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	cur := h.current.Load()
	if cur == nil {
		return ErrNoBundle
	}
	return h.confirm(ctx, cur, st, now)
}

// Unconfirm publishes the current snapshot again with no confirmation, so the
// kernel decides it stale, keeping its NotBefore, and withdraws the
// confirmation it held: Confirm and InstallConfirmed refuse every statement
// issued no later than it with ErrConfirmationWithdrawn until one issued after
// it is accepted. On a holder with no snapshot it does nothing.
func (h *Holder) Unconfirm() {
	h.mu.Lock()
	defer h.mu.Unlock()
	cur := h.current.Load()
	if cur == nil {
		return
	}

	if cur.confirmedAt.After(h.withdrawn) {
		h.withdrawn = cur.confirmedAt
	}
	unconfirmed := *cur
	unconfirmed.confirmedAt = time.Time{}
	h.current.Store(&unconfirmed)
}

// loadPinned loads b with no confirmation and refuses a bundle of another id
// than the pin. mu is held.
func (h *Holder) loadPinned(b *controlv1.PolicyBundle, keys bundle.Keyring, compile compiler) (*Snapshot, error) {
	next, err := load(b, keys, time.Time{}, compile)
	if err != nil {
		return nil, err
	}
	if id := next.ref.GetBundleId(); id != h.pin {
		return nil, fmt.Errorf("%w: %q", ErrBundlePin, id)
	}
	return next, nil
}

// confirm publishes snap confirmed by st once the store raised the floor to
// st. Every refusal comes before the raise, and the raise before the
// publish. mu is held.
func (h *Holder) confirm(ctx context.Context, snap *Snapshot, st Statement, now Reading) error {
	if err := bound(st, snap); err != nil {
		return err
	}
	if !h.withdrawn.IsZero() && !st.issuedAt.After(h.withdrawn) {
		return fmt.Errorf("%w: issued %s, withdrawn %s", ErrConfirmationWithdrawn, FormatIssuedAt(st.issuedAt), FormatIssuedAt(h.withdrawn))
	}
	cur := h.current.Load()
	renewal := cur != nil && cur.ref.GetDigest() == snap.ref.GetDigest()
	if !renewal {
		if err := h.check(snap); err != nil {
			return err
		}
	}
	raised, err := h.store.RaiseAt(ctx, st, now)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFloorRaise, err)
	}
	if !raised.holds(st) {
		return fmt.Errorf("%w: the store returned a floor at serial %d issued %s", ErrFloorRaise, raised.serial, FormatIssuedAt(raised.issuedAt))
	}
	confirmed := *snap
	if renewal {
		confirmed = *cur
	} else {
		h.record(snap)
	}
	confirmed.confirmedAt = st.issuedAt
	h.verify(raised.latestIssuedAt)
	confirmed.verified = h.verified
	h.withdrawn = time.Time{}
	h.current.Store(&confirmed)
	return nil
}
