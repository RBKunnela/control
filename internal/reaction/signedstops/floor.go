package signedstops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// Floor is a plane's stop list floor: the directory its account owns, for
// its tenant and project.
type Floor struct {
	dir, tenant, project string
}

// NewFloor is the floor in dir for tenant and project, or ErrOptions.
func NewFloor(dir, tenant, project string) (Floor, error) {
	if dir == "" || tenant == "" || project == "" {
		return Floor{}, ErrOptions
	}
	return Floor{dir: dir, tenant: tenant, project: project}, nil
}

// Take holds l, a 2.0 list a judge accepted from content, to the floor and
// raises the floor to l's header and accepted part, waiting for the floor's
// lock until ctx ends. A plane calls it whenever its accepted part grows. It
// refuses what Hold refuses, and with stoplist.ErrFloor a floor it cannot
// read or raise.
func (f Floor) Take(ctx context.Context, l reaction.List, content []byte) (policystate.StopsFloor, error) {
	h := l.Header().Signed
	if h.Digest == "" {
		return policystate.StopsFloor{}, fmt.Errorf("%w: the list's header is not signed", stoplist.ErrFloor)
	}
	stored, err := policystate.ReadStops(f.dir, f.tenant, f.project)
	if err != nil {
		return policystate.StopsFloor{}, fmt.Errorf("%w: %w", stoplist.ErrFloor, err)
	}
	if err := Hold(stored, l, content); err != nil {
		return policystate.StopsFloor{}, err
	}
	p := l.Prefix()
	raised, err := policystate.RaiseStops(ctx, f.dir, policystate.StopsFloor{
		Tenant: f.tenant, Project: f.project, Serial: h.Serial, Digest: h.Digest, Length: p.Length(), Prefix: sumDigest(p.Sum()),
	})
	if err != nil {
		return policystate.StopsFloor{}, floorRefusal(err)
	}
	return raised, nil
}

// Hold holds l, a 2.0 list a judge accepted from content, to a floor as
// stored, writing nothing: its header as Check does, and at the floor's
// serial its accepted part, which must begin with the floor's. A part
// shorter than the floor's, or one whose first bytes of the floor's length
// are others, is lines the plane accepted cut or changed: stoplist.ErrChain.
func Hold(stored policystate.StopsFloor, l reaction.List, content []byte) error {
	h := l.Header().Signed
	if err := Check(stored, h); err != nil {
		return err
	}
	if !stored.HasSerial() || h.Serial != stored.Serial {
		return nil
	}
	if l.Prefix().Length() < stored.Length || int64(len(content)) < stored.Length {
		return fmt.Errorf("%w: the list accepted is %d bytes, the floor holds %d of serial %d",
			stoplist.ErrChain, l.Prefix().Length(), stored.Length, h.Serial)
	}
	if sumDigest(sha256.Sum256(content[:stored.Length])) != stored.Prefix {
		return fmt.Errorf("%w: the first %d bytes of the list are not those the floor holds of serial %d",
			stoplist.ErrChain, stored.Length, h.Serial)
	}
	return nil
}

// Check holds h to a floor as stored, writing nothing: a lower serial, the
// floor's serial with another head, and a higher serial whose previous head
// is not the floor's when the floor holds one are refused.
func Check(stored policystate.StopsFloor, h reaction.HeaderSigned) error {
	switch {
	case !stored.HasSerial():
		return nil
	case h.Serial < stored.Serial:
		return fmt.Errorf("%w: serial %d, the floor's %d", stoplist.ErrBelowFloor, h.Serial, stored.Serial)
	case h.Serial == stored.Serial && h.Digest != stored.Digest:
		return fmt.Errorf("%w: serial %d", stoplist.ErrForked, h.Serial)
	case h.Serial > stored.Serial && h.Previous != stored.Digest:
		return fmt.Errorf("%w: serial %d over the floor's %d", stoplist.ErrChain, h.Serial, stored.Serial)
	}
	return nil
}

// sumDigest is a SHA-256 as the floor file writes it.
func sumDigest(sum [sha256.Size]byte) string { return "sha256:" + hex.EncodeToString(sum[:]) }

func floorRefusal(err error) error {
	switch {
	case errors.Is(err, policystate.ErrStopsBelowFloor):
		return fmt.Errorf("%w: %w", stoplist.ErrBelowFloor, err)
	case errors.Is(err, policystate.ErrStopsForked):
		return fmt.Errorf("%w: %w", stoplist.ErrForked, err)
	case errors.Is(err, policystate.ErrStopsRewritten):
		return fmt.Errorf("%w: %w", stoplist.ErrChain, err)
	}
	return fmt.Errorf("%w: %w", stoplist.ErrFloor, err)
}
