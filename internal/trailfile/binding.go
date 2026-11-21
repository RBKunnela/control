package trailfile

import (
	"bytes"
	"fmt"
	"strconv"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
)

// binding is the tenant and project a log is bound to. The zero binding is a
// trail file's, which is bound to none.
type binding struct{ tenant, project string }

// refuses reports whether an event of tenant and project is of another than
// b, which a log bound to b refuses to take and refuses at open.
func (b binding) refuses(tenant, project string) bool {
	return b != (binding{}) && (tenant != b.tenant || project != b.project)
}

func (b binding) refusesEvent(ev *controlv1.Event) bool {
	return b.refuses(ev.GetTenantId(), ev.GetProjectId())
}

// trails refuses a read of a log holding a trail of another tenant or
// project than b.
func (b binding) trails(trails []Trail) error {
	for _, tr := range trails {
		if b.refuses(tr.TenantID, tr.ProjectID) {
			return fmt.Errorf("%w: %w: request %s of tenant %s, project %s", ErrDamaged, ErrBinding,
				strconv.Quote(tr.RequestID), strconv.Quote(tr.TenantID), strconv.Quote(tr.ProjectID))
		}
	}
	return nil
}

// lines refuses whole lines of a log holding an event of another tenant or
// project than b. A line that is not one event is left to its reader.
func (b binding) lines(raw []byte) error {
	number := 0
	for line := range bytes.Lines(raw) {
		number++
		events, err := evidence.DecodeJSONL(bytes.NewReader(line), 1)
		if err == nil && b.refusesEvent(events[0]) {
			return fmt.Errorf("%w: %w: line %d", ErrDamaged, ErrBinding, number)
		}
	}
	return nil
}
