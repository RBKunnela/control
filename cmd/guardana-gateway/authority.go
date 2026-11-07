package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"strings"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/approvals/inbox"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/trust"
)

// trustOpenTimeout bounds the roster's first read at start: trust.Open runs
// one lookup on the context it is given and keeps nothing it answered, so a
// floor directory that never answers would otherwise hold the start forever.
var trustOpenTimeout = 5 * time.Second

// claimAuthority is the approvals directory as the directory kind's
// authority: the record filed under an approval id, whose approver id is a
// claim the plane judges.
type claimAuthority struct{ plane *approvals.Plane }

var _ gateway.ApprovalAuthority = (*claimAuthority)(nil)

func (a *claimAuthority) Answers(ctx context.Context, approvalID string) gateway.AnswerBatch {
	rec, err := a.plane.Claim(ctx, approvalID)
	switch {
	case errors.Is(err, approvals.ErrNoApproval):
		return gateway.AnswerBatch{State: gateway.BatchComplete}
	case err != nil:
		return gateway.AnswerBatch{}
	}
	return gateway.AnswerBatch{State: gateway.BatchComplete, Claimed: []*controlv1.Approval{rec.Approval}}
}

func (a *claimAuthority) Status(context.Context) gateway.AuthorityStatus {
	return gateway.AuthorityStatus{Kind: gateway.AuthorityDirectory, Health: gateway.AuthorityUsable}
}

// inboxAuthority is the signed kind's inbox as its authority: the signed
// answers filed for an approval, none of which it vouches for.
type inboxAuthority struct{ inbox *inbox.Inbox }

var _ gateway.ApprovalAuthority = (*inboxAuthority)(nil)

func (a *inboxAuthority) Answers(ctx context.Context, approvalID string) gateway.AnswerBatch {
	batch, err := a.inbox.Read(ctx, approvalID)
	switch {
	case err != nil, batch.Unjudged:
		return gateway.AnswerBatch{}
	case batch.Truncated:
		return gateway.AnswerBatch{State: gateway.BatchTruncated}
	}
	return gateway.AnswerBatch{State: gateway.BatchComplete, Signed: batch.Envelopes}
}

func (a *inboxAuthority) Status(context.Context) gateway.AuthorityStatus {
	s := gateway.AuthorityStatus{Kind: gateway.AuthoritySigned, Counts: a.inbox.Counts()}
	if a.inbox.Usable() {
		s.Health = gateway.AuthorityUsable
	}
	return s
}

// signedPorts is what the signed kind judges an answer with: the trust
// roster, and the authenticator and the authorizer that read it.
type signedPorts struct {
	roster trust.Roster
	authn  operators.Authenticator
	authz  operators.Authorizer
}

// The start checks of the signed kind, each a variable so a test reaches the
// plane that passes them on a machine whose files its own account owns.
var (
	notPlaneWritable     = gatewayconfig.CheckNotPlaneWritable
	environmentOverrides = gatewayconfig.EnvironmentOverrides
)

// checkSignedStart refuses a start under the signed kind that the plane's own
// account could turn: a configuration file, a trust root key file, a pause
// file or the runs directory's records/ it may write, or a directory on
// their path it may write, and any key the environment set, since that
// account sets its own environment when it restarts (ADR-0073).
func checkSignedStart(cfg *gatewayconfig.Config) error {
	if keys := environmentOverrides(cfg); len(keys) > 0 {
		return fmt.Errorf("approvals.authority: signed, and the environment sets %s; the plane's own account sets its environment, so under signed every key is read from the configuration file alone (ADR-0073)",
			strings.Join(keys, ", "))
	}
	checked := []struct{ key, path string }{
		{"the configuration file", cfg.File()},
		{"trust.root_public_key", cfg.Resolve(cfg.Trust.RootPublicKey)},
	}
	if cfg.Pause.File != "" {
		checked = append(checked, struct{ key, path string }{"pause.file", cfg.Resolve(cfg.Pause.File)})
	}
	if cfg.Runs.Dir != "" {
		checked = append(checked, struct{ key, path string }{"runs.dir", filepath.Join(cfg.Resolve(cfg.Runs.Dir), runs.RecordsDir)})
	}
	for _, f := range checked {
		if err := notPlaneWritable(f.path); err != nil {
			return fmt.Errorf("%s: under the signed authority the plane's own account may not be able to change it: %w (ADR-0073)", f.key, err)
		}
	}
	return nil
}

// pinnedKey is one key the plane pins for an authority other than the trust
// roster, read from the configuration.
type pinnedKey struct {
	name string
	read func(*gatewayconfig.Config) (ed25519.PublicKey, bool, error)
}

// pinnedKeys is every key the plane pins besides the trust root. Each one is
// handed to the roster as a key no roster may name, so no operator key can
// also sign a policy, a freshness statement, a route or a lift. A key the
// configuration gains is added here, or the registry test fails.
var pinnedKeys = []pinnedKey{
	{"policy.public_key", func(c *gatewayconfig.Config) (ed25519.PublicKey, bool, error) {
		k, err := policykey.ParsePublic(c.Policy.PublicKey)
		return k, true, err
	}},
	{"policy.freshness_public_key", func(c *gatewayconfig.Config) (ed25519.PublicKey, bool, error) {
		k, err := policykey.ParsePublic(c.Policy.FreshnessPublicKey)
		return k, true, err
	}},
	{"reaction.public_key", func(c *gatewayconfig.Config) (ed25519.PublicKey, bool, error) {
		if c.Reaction.PublicKey == "" {
			return nil, false, nil
		}
		k, err := readRouteKey(c.Resolve(c.Reaction.PublicKey))
		return k, true, err
	}},
	{"the route's lift_public_key", func(c *gatewayconfig.Config) (ed25519.PublicKey, bool, error) {
		if c.Reaction.Route == "" {
			return nil, false, nil
		}
		route, err := readRoute(c)
		return route.LiftKey(), err == nil, err
	}},
}

// otherKeys reads every pinned key the configuration sets.
func otherKeys(cfg *gatewayconfig.Config) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, k := range pinnedKeys {
		key, set, err := k.read(cfg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k.name, err)
		}
		if set {
			out = append(out, key)
		}
	}
	return out, nil
}

// openSigned makes the start checks, checkSignedStart's where startCheck is
// nil, and opens the roster, the authenticator
// and the authorizer. The roster id is the configuration file's alone, so a
// floor directory that lists several ids never lets a roster of another one
// in, and the roster's first read is held to a timeout.
func openSigned(ctx context.Context, cfg *gatewayconfig.Config, startCheck func(*gatewayconfig.Config) error) (*signedPorts, error) {
	if startCheck == nil {
		startCheck = checkSignedStart
	}
	if err := startCheck(cfg); err != nil {
		return nil, err
	}
	root, err := readRouteKey(cfg.Resolve(cfg.Trust.RootPublicKey))
	if err != nil {
		return nil, fmt.Errorf("trust.root_public_key: %w", err)
	}
	others, err := otherKeys(cfg)
	if err != nil {
		return nil, err
	}
	authnKind, err := operators.ParseAuthenticatorKind(cfg.Operators.AuthenticatorKind)
	if err != nil {
		return nil, fmt.Errorf("operators.authenticator.kind: %w", err)
	}
	authzKind, err := operators.ParseAuthorizerKind(cfg.Operators.AuthorizerKind)
	if err != nil {
		return nil, fmt.Errorf("operators.authorizer.kind: %w", err)
	}
	opening, cancel := context.WithTimeout(ctx, trustOpenTimeout)
	defer cancel()
	roster, err := trust.Open(opening, trust.Config{
		Kind: trust.KindFile, Root: root, RosterID: cfg.Trust.RosterID,
		Path: cfg.Resolve(cfg.Trust.Roster), FloorDir: cfg.Resolve(cfg.Trust.FloorDir),
		Others: others, Clock: time.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("trust: %w", err)
	}
	authn, err := operators.NewAuthenticator(authnKind, roster, operators.Bounds{})
	if err != nil {
		return nil, fmt.Errorf("operators.authenticator: %w", err)
	}
	authz, err := operators.NewAuthorizer(authzKind, roster, operators.Bounds{})
	if err != nil {
		return nil, fmt.Errorf("operators.authorizer: %w", err)
	}
	return &signedPorts{roster: roster, authn: authn, authz: authz}, nil
}

// openAuthority opens what the configured authority answers from, after the
// approvals directory a non-memory authority holds its records in is open.
func (p *plane) openAuthority(ctx context.Context) error {
	switch p.cfg.Approvals.Authority {
	case gatewayconfig.AuthorityDirectory:
		p.authority, p.authorityKind = &claimAuthority{plane: p.records}, gateway.AuthorityDirectory
		return nil
	case gatewayconfig.AuthoritySigned:
		ports, err := openSigned(ctx, p.cfg, p.signedStart)
		if err != nil {
			return err
		}
		in, err := inbox.OpenInbox(p.cfg.Resolve(p.cfg.Approvals.InboxDir))
		if err != nil {
			return fmt.Errorf("approvals.inbox_dir: %w", err)
		}
		p.signed, p.inbox = ports, in
		p.authority, p.authorityKind = &inboxAuthority{inbox: in}, gateway.AuthoritySigned
		return nil
	}
	memory, ok := p.store.(*gateway.MemoryApprovals)
	if !ok {
		return fmt.Errorf("approvals.authority: %s holds no store in this process", p.cfg.Approvals.Authority)
	}
	p.authority, p.authorityKind = memory, gateway.AuthorityDirectory
	return nil
}

// authorityHealth is the approval authority on the health page: the
// configured kind, whether it can be read, and the causes the authority and
// the plane counted. Under memory and directory it says the approver is a
// claim.
func (p *plane) authorityHealth(ctx context.Context, answers map[string]uint64) map[string]any {
	out := map[string]any{"kind": p.cfg.Approvals.Authority, "state": "unavailable", "refused": orEmpty(answers)}
	if p.authority != nil {
		s := p.authority.Status(ctx)
		if s.Health == gateway.AuthorityUsable {
			out["state"] = "usable"
		}
		out["counts"] = orEmpty(s.Counts)
	}
	if p.cfg.Approvals.Authority != gatewayconfig.AuthoritySigned {
		out["limits"] = []string{"the approver is an unauthenticated claim: anyone who may write where answers are read approves"}
	}
	if p.inbox != nil {
		n, more, err := p.inbox.Entries()
		out["inbox_entries"], out["inbox_full"] = n, more
		if err != nil {
			out["state"] = "unavailable"
		}
	}
	return out
}

// pruneInbox removes the answer files of approvals no longer held, older than
// one approval lifetime. A hold whose record cannot be read counts as held, so
// nothing an approver filed for it is removed.
func (p *plane) pruneInbox(ctx context.Context, now time.Time) (inbox.Pruned, error) {
	if p.inbox == nil {
		return inbox.Pruned{}, nil
	}
	return p.inbox.Prune(ctx, now, p.cfg.Approvals.TTL, func(approvalID string) bool {
		_, err := p.records.Claim(ctx, approvalID)
		return !errors.Is(err, approvals.ErrNoApproval)
	})
}

// trustHealth and operatorsHealth are the trust roster and the operator ports
// on the health page, each "not_configured" outside the signed kind.
func (p *plane) trustHealth(ctx context.Context) map[string]any {
	if p.signed == nil {
		return map[string]any{"state": "not_configured"}
	}
	s := p.signed.roster.Status(ctx)
	state := "unavailable"
	if s.Health == trust.HealthUsable {
		state = "usable"
	}
	counts := map[string]uint64{}
	for c, n := range s.Counts {
		counts[string(c)] = n
	}
	return map[string]any{
		"kind": string(s.Kind), "state": state, "roster_id": s.RosterID, "serial": s.Serial,
		"last": string(s.Last), "counts": counts,
	}
}

// operatorsHealth is the authenticator and the authorizer, each usable only
// while the roster they read is.
func (p *plane) operatorsHealth(ctx context.Context) map[string]any {
	if p.signed == nil {
		return map[string]any{"authenticator": map[string]any{"state": "not_configured"}, "authorizer": map[string]any{"state": "not_configured"}}
	}
	usable := p.signed.roster.Status(ctx).Health == trust.HealthUsable
	return map[string]any{"authenticator": portHealth(p.signed.authn.Status(), usable), "authorizer": portHealth(p.signed.authz.Status(), usable)}
}

func portHealth(s operators.Status, usable bool) map[string]any {
	counts := map[string]uint64{}
	for c, n := range s.Counts {
		counts[string(c)] = n
	}
	state := "unavailable"
	if usable {
		state = "usable"
	}
	return map[string]any{"kind": s.Kind, "state": state, "counts": counts}
}

func orEmpty(m map[string]uint64) map[string]uint64 {
	if m == nil {
		return map[string]uint64{}
	}
	return maps.Clone(m)
}
