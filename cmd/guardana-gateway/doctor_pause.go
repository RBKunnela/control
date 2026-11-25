package main

import (
	"fmt"
	"path/filepath"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/pause/signedpause"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/trust"
)

// signedPauseFile is pauseFile under the signed authority: the file read as
// the plane reads it, held to the plane's binding as the plane's judge holds
// it, its signature checked against the roster file, its signer's grant and
// its serial against the pause floor, which is read and never raised: a
// check that raised it would be a start. It returns the entries in force, or
// the line that fails.
func (d *examination) signedPauseFile() ([]pause.Entry, string, error) {
	path := d.cfg.Resolve(d.cfg.Pause.File)
	f, err := pause.Inspect(path)
	if err != nil {
		return nil, "", err
	}
	body := f.Body
	root, err := readRouteKey(d.cfg.Resolve(d.cfg.Trust.RootPublicKey))
	if err != nil {
		return nil, "", fmt.Errorf("trust.root_public_key: %w", err)
	}
	roster, err := d.roster(root)
	if err != nil {
		return nil, "", fmt.Errorf("trust.roster: %w", err)
	}
	subject, err := pauseSigner(d.cfg, roster, f)
	if err != nil {
		return nil, "", err
	}
	floor, err := policystate.ReadPause(d.cfg.Resolve(d.cfg.Pause.FloorDir), d.cfg.TenantID, d.cfg.ProjectID)
	switch {
	case err != nil:
		return nil, "", fmt.Errorf("pause.floor_dir: %w", err)
	case body.Serial < floor.Serial:
		return nil, "", fmt.Errorf("%w: serial %d, the floor's %d", pause.ErrBelowFloor, body.Serial, floor.Serial)
	case body.Serial == floor.Serial && body.Digest != floor.Digest:
		return nil, "", fmt.Errorf("%w: serial %d", pause.ErrForked, body.Serial)
	}
	return body.Entries, fmt.Sprintf("signed by %s (key %s) for this pause file at serial %d, the floor at %d",
		oneLine(subject), body.KeyID, body.Serial, floor.Serial), nil
}

// pauseSigner is the subject of the operator key of roster that signed f,
// refusing as the plane's judge would short of its floor: f held to the
// binding of cfg's plane and pause file, then vouched for by roster.
func pauseSigner(cfg *gatewayconfig.Config, roster trust.Document, f pause.Signed) (string, error) {
	binding, err := signedpause.NewBinding(cfg.PlaneID, cfg.TenantID, cfg.ProjectID, cfg.Resolve(cfg.Pause.File))
	if err != nil {
		return "", err
	}
	return binding.Vouched(roster, f)
}

// signedPauseVerdict is pauseFile's verdict over what signedPauseFile found.
func (d *examination) signedPauseVerdict() (string, string, string) {
	path := filepath.ToSlash(d.cfg.Resolve(d.cfg.Pause.File))
	entries, signer, err := d.signedPauseFile()
	if err != nil {
		return verdictFail, "pause", fmt.Sprintf("%s cannot be taken under the signed authority: %s; run refuses to start on it", path, oneLine(err.Error()))
	}
	d.pauseEntries = entries
	stray := strayEntries(entries, targetsOf(d.cfg, nil, false))
	shares, unknown := d.printCoverage(entries, stray)
	state := pause.Clear
	if len(entries) > 0 {
		state = pause.Paused
	}
	return coverageVerdict(unknown), "pause", fmt.Sprintf("%s is %s: %d entry(ies), %d naming a provider this configuration does not have; %s; %s; read every %s",
		path, state, len(entries), len(stray), signer, shares, d.cfg.Pause.PollInterval)
}
