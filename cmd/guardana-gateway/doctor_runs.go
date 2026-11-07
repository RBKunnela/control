package main

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/runs/signedruns"
)

// doctorRunsBound is the most records doctor reads of a signed layout.
const doctorRunsBound = 1 << 16

// doctorPlaneOwned lets the check read a records/ the plane's own account
// owns. Only a test sets it, where one account owns every directory.
var doctorPlaneOwned = false

// openRunsCheck opens the runs directory for a check, which writes nothing
// there: unsigned as run opens it, and a signed layout judged against the
// roster file as the plane's ports would judge it, refusing a records/ the
// plane's own account owns as run does.
func (d *examination) openRunsCheck() (*runs.Plane, error) {
	if d.cfg.Approvals.Authority != gatewayconfig.AuthoritySigned {
		return runs.OpenPlane(d.cfg.Resolve(d.cfg.Runs.Dir))
	}
	root, err := readRouteKey(d.cfg.Resolve(d.cfg.Trust.RootPublicKey))
	if err != nil {
		return nil, fmt.Errorf("trust.root_public_key: %w", err)
	}
	roster, err := d.roster(root)
	if err != nil {
		return nil, fmt.Errorf("trust.roster: %w", err)
	}
	return runs.OpenSignedPlane(d.cfg.Resolve(d.cfg.Runs.Dir), runs.SignedOptions{
		Judge:      signedruns.Roster{Document: roster, Tenant: listenerTenant(d.cfg), Project: d.cfg.ProjectID},
		PlaneOwned: doctorPlaneOwned})
}

// signedRunsLine is what doctor says of a signed layout: how many records it
// holds, how many count and by whom they were signed, and how many count for
// nothing, by cause. It names no run.
func signedRunsLine(path string, s runs.Survey) string {
	refused := 0
	causes := make([]string, 0, len(s.Refused))
	for _, c := range runs.RecordCauses() {
		if n := s.Refused[c]; n > 0 {
			refused += n
			causes = append(causes, fmt.Sprintf("%s %d", c, n))
		}
	}
	signers := make([]string, 0, len(s.Signers))
	for subject, n := range s.Signers {
		signers = append(signers, fmt.Sprintf("%s %d", oneLine(subject), n))
	}
	slices.Sort(signers)
	line := fmt.Sprintf("a signed layout in %s: %d record(s), %d open, %d closed, %d expired, signed by %d operator(s)",
		path, s.Records, s.Open, s.Closed, s.Expired, len(s.Signers))
	if len(signers) > 0 {
		line += " (" + strings.Join(signers, ", ") + ")"
	}
	if refused > 0 {
		line += fmt.Sprintf("; %d count for nothing and refuse their calls (%s)", refused, strings.Join(causes, ", "))
	}
	if !s.Complete {
		line += fmt.Sprintf("; only the first %d were read", doctorRunsBound)
	}
	return line
}

// signedRuns is the runs verdict under the signed authority.
func (d *examination) signedRuns(ctx context.Context) (string, string, string) {
	path := filepath.ToSlash(d.cfg.Resolve(d.cfg.Runs.Dir))
	plane, err := d.openRunsCheck()
	if err != nil {
		return verdictFail, "runs", fmt.Sprintf("runs.dir: %v; run refuses to start on it", err)
	}
	s, err := plane.Inspect(ctx, doctorRunsBound, time.Now())
	if cerr := plane.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return verdictFail, "runs", fmt.Sprintf("runs.dir: %v", err)
	}
	return verdictOK, "runs", signedRunsLine(path, s) + "; a record counts only once an operator granted operate signed it for this records/ (ADR-0076)"
}
