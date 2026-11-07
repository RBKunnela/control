package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/trust"
)

// What a dev state directory holds for the signed authority, each named from
// the directory.
const (
	stateInbox    = "inbox"
	stateTrust    = "trust"
	stateRootKey  = "trust/root.pub"
	stateRoster   = "trust/roster.json"
	stateTrustFlr = "trust/floors"
	stateOperator = "operator"
)

// The roster dev signs: one id, one operator.
const (
	devRosterID = "dev"
	devOperator = "dev-operator"
)

// operatorKeyFile is the dev operator's private key file under st.
func (s devState) operatorKeyFile() string {
	return filepath.Join(s.path(stateOperator), policykey.PrivateFile)
}

// layOutTrust makes the dev plane's signed authority under its state: a
// trust root drawn here, whose public half is written and whose private half
// is cleared once it signed; a roster naming one operator, who may approve
// in tenant and project; the operator's key pair, the roster's floor, the
// pause floor and a pause file the operator signed, pausing nothing, each
// through the approver's binary, which holds the code that writes them; and
// an empty inbox. The operator's key is
// kept in the state directory, readable by this account alone, so the dev
// plane's own account can approve: a dev plane is no separation of duties.
func (d *devPlane) layOutTrust(ctx context.Context, control sibling, tenant, project string) error {
	st := d.state
	for _, sub := range []string{stateInbox, stateTrust} {
		if err := os.Mkdir(st.path(sub), 0o700); err != nil {
			return err
		}
	}
	if _, err := control.run(ctx, "policy", "keygen", "--out", st.path(stateOperator)); err != nil {
		return fmt.Errorf("making the dev operator's key: %w", err)
	}
	operator, err := readRouteKey(filepath.Join(st.path(stateOperator), policykey.PublicFile))
	if err != nil {
		return fmt.Errorf("reading the dev operator's public key: %w", err)
	}
	if err := signDevRoster(st, operator, tenant, project); err != nil {
		return err
	}
	if _, err := control.run(ctx, "operators", "floor", "init", "--roster-id", devRosterID, st.path(stateTrustFlr)); err != nil {
		return fmt.Errorf("creating the roster's floor: %w", err)
	}
	if err := os.Mkdir(filepath.Dir(st.path(statePause)), 0o700); err != nil {
		return err
	}
	if _, err := control.run(ctx, "pause", "floor", "init", "--tenant", tenant, "--project", project, st.path(statePauseFlr)); err != nil {
		return fmt.Errorf("creating the pause floor: %w", err)
	}
	if _, err := control.run(ctx, "pause", "init", "--key", st.operatorKeyFile(), "--tenant", tenant, "--project", project, st.path(statePause)); err != nil {
		return fmt.Errorf("creating the pause file: %w", err)
	}
	return nil
}

// signDevRoster signs the roster naming operator under a root drawn for it.
func signDevRoster(st devState, operator ed25519.PublicKey, tenant, project string) error {
	root, err := newKey()
	if err != nil {
		return err
	}
	defer clear(root)
	source, err := canon.Canonicalize(map[string]any{
		"kind": trust.DocumentKind, "rosterId": devRosterID, "serial": 1,
		"keys": []any{map[string]any{
			"keyId": policykey.KeyID(operator), "alg": "ed25519", "role": "operator", "subject": devOperator,
			"publicKey": base64.StdEncoding.EncodeToString(operator),
			"grants":    []any{map[string]any{"tenant": tenant, "project": project, "level": "operate"}},
		}},
	})
	if err != nil {
		return err
	}
	env, _, err := trust.SignDocument(source, time.Now().UTC().Truncate(time.Second), trust.MaxLifetime, root)
	if err != nil {
		return fmt.Errorf("signing the dev roster: %w", err)
	}
	raw, err := trust.MarshalFile(env)
	if err != nil {
		return err
	}
	if err := os.WriteFile(st.path(stateRoster), raw, 0o600); err != nil {
		return err
	}
	return os.WriteFile(st.path(stateRootKey), []byte(policykey.FormatPublic(publicHalf(root))+"\n"), 0o600)
}

// devSignedStart is the signed start check of a dev plane. The plane's own
// account wrote the trust root, the roster and the operator's key, so the
// placement a served plane is held to guards nothing here; what it holds the
// configuration to instead is that every key of the signed authority names
// what dev laid out under st.
func devSignedStart(st devState) func(*gatewayconfig.Config) error {
	return func(cfg *gatewayconfig.Config) error {
		for _, k := range []struct{ key, got, want string }{
			{"trust.root_public_key", cfg.Resolve(cfg.Trust.RootPublicKey), st.path(stateRootKey)},
			{"trust.roster", cfg.Resolve(cfg.Trust.Roster), st.path(stateRoster)},
			{"trust.floor_dir", cfg.Resolve(cfg.Trust.FloorDir), st.path(stateTrustFlr)},
			{"approvals.inbox_dir", cfg.Resolve(cfg.Approvals.InboxDir), st.path(stateInbox)},
			{"pause.file", cfg.Resolve(cfg.Pause.File), st.path(statePause)},
			{"pause.floor_dir", cfg.Resolve(cfg.Pause.FloorDir), st.path(statePauseFlr)},
		} {
			if k.got != k.want {
				return fmt.Errorf("%s is %s, and a dev plane takes only the one dev laid out at %s", k.key, k.got, k.want)
			}
		}
		if cfg.Trust.RosterID != devRosterID {
			return errors.New("trust.roster_id is not the dev roster's")
		}
		return nil
	}
}
