package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/guardana/control/internal/approvals/inbox"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/trust"
)

// The doctor keys of the approval authority's ports, as scripts/ports.txt
// names them.
const (
	doctorTrust         = "trust"
	doctorAuthenticator = "operators.authenticator"
	doctorAuthorizer    = "operators.authorizer"
	doctorAuthority     = "approvals.authority"
)

// notSigned is what each of the signed kind's ports reports under another
// authority.
func (d *examination) notSigned(key string) (string, string, string) {
	return verdictOK, key, fmt.Sprintf("not read: approvals.authority is %s, which authenticates no operator", d.cfg.Approvals.Authority)
}

// trust reports the start checks the signed kind makes and the roster as the
// file and the floor hold it, without raising the floor: a check that wrote it
// would be a start.
func (d *examination) trust(context.Context) (string, string, string) {
	if d.cfg.Approvals.Authority != gatewayconfig.AuthoritySigned {
		return d.notSigned(doctorTrust)
	}
	if err := checkSignedStart(d.cfg); err != nil {
		return verdictFail, doctorTrust, err.Error()
	}
	root, err := readRouteKey(d.cfg.Resolve(d.cfg.Trust.RootPublicKey))
	if err != nil {
		return verdictFail, doctorTrust, "trust.root_public_key: " + err.Error()
	}
	others, err := otherKeys(d.cfg)
	if err != nil {
		return verdictFail, doctorTrust, err.Error()
	}
	if err := trust.CheckRoot(root, others...); err != nil {
		return verdictFail, doctorTrust, "trust.root_public_key: " + err.Error()
	}
	doc, err := d.roster(root)
	if err != nil {
		return verdictFail, doctorTrust, "trust.roster: " + err.Error()
	}
	floor, err := policystate.ReadAuthority(d.cfg.Resolve(d.cfg.Trust.FloorDir), d.cfg.Trust.RosterID)
	if err != nil {
		return verdictFail, doctorTrust, "trust.floor_dir: " + err.Error()
	}
	if floor.Serial > doc.Serial() {
		return verdictFail, doctorTrust, fmt.Sprintf("trust.roster: serial %d is below the floor's %d (%s)", doc.Serial(), floor.Serial, trust.CauseBelowFloor)
	}
	return verdictOK, doctorTrust, fmt.Sprintf(
		"roster %s serial %d names %d key(s) and verifies under the pinned root; the floor holds serial %d; %d other pinned key(s) no roster may name; the configuration file and the root key file are not the plane's to change, and the environment sets no key",
		doc.ID(), doc.Serial(), len(doc.Keys()), floor.Serial, len(others))
}

// roster reads the roster file and verifies it under root, of the configured
// id and usable now, as the roster port would before it raised the floor.
func (d *examination) roster(root ed25519.PublicKey) (trust.Document, error) {
	raw, err := files.ReadRegular(d.cfg.Resolve(d.cfg.Trust.Roster), trust.MaxFileBytes, 0)
	if err != nil {
		return trust.Document{}, err
	}
	env, err := trust.ParseFile(raw)
	if err != nil {
		return trust.Document{}, err
	}
	doc, err := trust.VerifyDocument(env, root)
	if err != nil {
		return trust.Document{}, err
	}
	if doc.ID() != d.cfg.Trust.RosterID {
		return trust.Document{}, fmt.Errorf("the roster is %s and trust.roster_id is %s; the plane takes no roster of another id (%s)",
			doc.ID(), d.cfg.Trust.RosterID, trust.CauseOtherRoster)
	}
	return doc, doc.UsableAt(time.Now())
}

// authenticator and authorizer say how each signed answer is judged.
func (d *examination) authenticator(context.Context) (string, string, string) {
	if d.cfg.Approvals.Authority != gatewayconfig.AuthoritySigned {
		return d.notSigned(doctorAuthenticator)
	}
	kind, err := operators.ParseAuthenticatorKind(d.cfg.Operators.AuthenticatorKind)
	if err != nil {
		return verdictFail, doctorAuthenticator, err.Error()
	}
	return verdictOK, doctorAuthenticator, fmt.Sprintf(
		"%s: an answer counts only signed by an operator key of the roster, each lookup within %s and at most %d at once",
		kind, operators.DefaultTimeout, operators.DefaultInFlight)
}

func (d *examination) authorizer(context.Context) (string, string, string) {
	if d.cfg.Approvals.Authority != gatewayconfig.AuthoritySigned {
		return d.notSigned(doctorAuthorizer)
	}
	kind, err := operators.ParseAuthorizerKind(d.cfg.Operators.AuthorizerKind)
	if err != nil {
		return verdictFail, doctorAuthorizer, err.Error()
	}
	return verdictOK, doctorAuthorizer, fmt.Sprintf(
		"%s: an approval or a rejection counts only from an operator granted operate or admin over the held call's own tenant and project in the roster held when it is read",
		kind)
}

// authority says where an answer is taken from and what it proves.
func (d *examination) authority(context.Context) (string, string, string) {
	switch d.cfg.Approvals.Authority {
	case gatewayconfig.AuthoritySigned:
		dir := d.cfg.Resolve(d.cfg.Approvals.InboxDir)
		in, err := inbox.OpenInbox(dir)
		if err != nil {
			return verdictFail, doctorAuthority, "approvals.inbox_dir: " + err.Error()
		}
		n, more, entriesErr := in.Entries()
		if err := errors.Join(entriesErr, in.Close()); err != nil {
			return verdictUnknown, doctorAuthority, "approvals.inbox_dir opened and could not be listed: " + err.Error()
		}
		found := fmt.Sprintf(
			"signed: answers are read from %s, which holds %d of at most %d name(s), at most %d per approval and %d bytes each, and each is authenticated, compared with its hold and authorized before it counts; a valid rejection wins",
			filepath.ToSlash(dir), n, inbox.MaxInboxEntries, inbox.MaxAnswersPerApproval, inbox.MaxAnswerFileBytes)
		if more {
			return verdictUnknown, doctorAuthority, found + "; the inbox is past its bound, so every signed hold is read as truncated"
		}
		return verdictOK, doctorAuthority, found
	case gatewayconfig.AuthorityDirectory:
		return verdictOK, doctorAuthority, fmt.Sprintf(
			"directory: answers are claims written into %s; the approver is an unauthenticated claim, and anyone who may write that directory approves",
			filepath.ToSlash(d.cfg.Resolve(d.cfg.Approvals.Dir)))
	}
	return verdictOK, doctorAuthority, "memory: answers are claims made in this process; the approver is an unauthenticated claim, and nothing outside this process answers"
}
