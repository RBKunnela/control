package adapterkit

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/guardana/control/internal/gateway"
)

// RunTokenHeader is the header an HTTP request presents its run token in
// (ADR-0034). Nothing else a request carries selects a run.
const RunTokenHeader = "Run-Token"

// HeaderToken is the one Run-Token value of h. None, or an empty one, is
// missing; two are malformed, since a proxy and the plane could each read
// another.
func HeaderToken(h http.Header) (string, gateway.RunCause) {
	values := h.Values(RunTokenHeader)
	switch {
	case len(values) > 1:
		return "", gateway.RunMalformed
	case len(values) == 0 || values[0] == "":
		return "", gateway.RunMissing
	}
	return values[0], ""
}

// Resolve asks runs about token for who at now. A refusal naming one of
// gateway.RunCauses is that cause; any other error, a refusal naming none
// (the empty cause included, which would read as no refusal), or a run
// without an id, is unreadable. The empty token is missing and is never
// asked about.
func Resolve(ctx context.Context, runs gateway.RunResolver, token string, who gateway.RunIdentity, now time.Time) (gateway.OpenedRun, gateway.RunCause) {
	if token == "" {
		return gateway.OpenedRun{}, gateway.RunMissing
	}
	run, err := runs.Resolve(ctx, token, who, now)
	if err != nil {
		var refusal *gateway.RunRefusal
		if errors.As(err, &refusal) && slices.Contains(gateway.RunCauses(), refusal.Cause) {
			return gateway.OpenedRun{}, refusal.Cause
		}
		return gateway.OpenedRun{}, gateway.RunUnreadable
	}
	if run.ID == "" {
		return gateway.OpenedRun{}, gateway.RunUnreadable
	}
	return run, ""
}

// RunCounter counts refused run tokens by the position of their cause in
// gateway.RunCauses, so no count is ever keyed by a run.
type RunCounter struct {
	causes []gateway.RunCause
	n      []atomic.Uint64
}

// NewRunCounter returns a counter at zero for every cause.
func NewRunCounter() *RunCounter {
	causes := gateway.RunCauses()
	return &RunCounter{causes: causes, n: make([]atomic.Uint64, len(causes))}
}

// Count adds one refusal; a cause outside the set, which Resolve never
// returns, is counted as unreadable rather than panicking a handler.
func (c *RunCounter) Count(cause gateway.RunCause) {
	i := slices.Index(c.causes, cause)
	if i < 0 {
		i = slices.Index(c.causes, gateway.RunUnreadable)
	}
	c.n[i].Add(1)
}

// Snapshot returns every cause of gateway.RunCauses with its count, zero
// included.
func (c *RunCounter) Snapshot() map[gateway.RunCause]uint64 {
	out := make(map[gateway.RunCause]uint64, len(c.causes))
	for i, cause := range c.causes {
		out[cause] = c.n[i].Load()
	}
	return out
}
