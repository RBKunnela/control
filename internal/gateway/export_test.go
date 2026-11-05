package gateway

import "github.com/guardana/control/internal/core/approval"

// SetStops replaces p's stop source after New, which reaches a plane New
// refuses: one that serves local runs under a stop list.
func SetStops(p *Pipeline, s StopSource) { p.cfg.Stops = s }

// BindingOf is the binding m keeps approvalID under, which a test authority
// asks the store's Find about.
func (m *MemoryApprovals) BindingOf(approvalID string) (Binding, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for binding, records := range m.held {
		for _, r := range records {
			if r.held.Approval.GetApprovalId() == approvalID {
				return binding, true
			}
		}
	}
	return "", false
}

// Binding is the binding a test authority names.
type Binding = approval.Binding
