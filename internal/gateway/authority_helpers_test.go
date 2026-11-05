package gateway_test

import (
	"context"
	"errors"
	"time"

	"github.com/guardana/control/internal/gateway"
)

// bindingKeeper is a memory store, or a fake embedding one, that says which
// binding it keeps an approval under.
type bindingKeeper interface {
	BindingOf(approvalID string) (gateway.Binding, bool)
}

// findAuthority is the directory kind's authority as a test wires it: the
// claims are what the store's Find hands out under the binding the memory
// store keeps the approval under, so a store a test made lie, fail or wait
// in Find does the same to the authority.
type findAuthority struct {
	store gateway.ApprovalStore
	keep  bindingKeeper
	clock func() time.Time
}

func (f *findAuthority) Answers(ctx context.Context, approvalID string) gateway.AnswerBatch {
	binding, ok := f.keep.BindingOf(approvalID)
	if !ok {
		return gateway.AnswerBatch{State: gateway.BatchComplete}
	}
	helds, err := f.store.Find(ctx, binding, f.clock())
	if err != nil && !errors.Is(err, gateway.ErrNoApproval) {
		return gateway.AnswerBatch{}
	}
	out := gateway.AnswerBatch{State: gateway.BatchComplete}
	for _, h := range helds {
		if h.Approval.GetApprovalId() == approvalID {
			out.Claimed = append(out.Claimed, h.Approval)
		}
	}
	return out
}

func (f *findAuthority) Status(context.Context) gateway.AuthorityStatus {
	return gateway.AuthorityStatus{Kind: gateway.AuthorityDirectory, Health: gateway.AuthorityUsable}
}

// withFindAuthority gives cfg the directory kind over its own store where a
// test named no authority. keep is asked for bindings when the store cannot
// say them itself.
func withFindAuthority(cfg *gateway.Config, keep bindingKeeper) {
	if cfg.AuthorityKind == "" && cfg.Authority == nil {
		cfg.AuthorityKind = gateway.AuthorityDirectory
	}
	if cfg.Authority != nil || cfg.Approvals == nil {
		return
	}
	if k, ok := cfg.Approvals.(bindingKeeper); ok {
		keep = k
	}
	cfg.Authority = &findAuthority{store: cfg.Approvals, keep: keep, clock: cfg.Clock}
}
