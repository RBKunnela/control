package operators

import (
	"bytes"

	"github.com/guardana/control/internal/trust"
)

// Act is something an operator does that a plane checks. It is a closed set.
type Act string

// ActApprove answers a held call: an approval or a rejection.
const ActApprove Act = "approve"

// ActPause signs a plane's whole pause document, which pauses and lifts.
const ActPause Act = "pause"

// ActRoute signs a v1alpha2 reaction route: which findings may stop a run
// of one project. It is the admin level's.
const ActRoute Act = "route"

// ActStops signs a stop list's header, which starts or carries a list.
const ActStops Act = "stops"

// ActLift signs a lift, which ends the stops of one run on one list.
const ActLift Act = "lift"

// ActRun signs a run's record, which opens the run, and its closed record,
// which closes it.
const ActRun Act = "run"

// AnswerPayloadType is the DSSE payload type an approval answer is signed
// under.
const AnswerPayloadType = "application/vnd.agent-approval-answer+json"

// PausePayloadType is the DSSE payload type a pause document is signed under.
const PausePayloadType = "application/vnd.agent-pause+json"

// RunPayloadType is the DSSE payload type a run record is signed under.
const RunPayloadType = "application/vnd.agent-run-record+json"

// actRule is the payload type an act is signed under and the level a grant
// needs to permit it.
type actRule struct {
	payloadType string
	level       trust.Level
}

// The payload types of the three stop acts.
const (
	RoutePayloadType       = "application/vnd.agent-reaction-route.v1alpha2+json"
	StopsHeaderPayloadType = "application/vnd.agent-stop-list-header+json"
	LiftPayloadType        = "application/vnd.agent-reaction-lift.v1alpha2+json"
)

var acts = map[Act]actRule{
	ActRoute:   {payloadType: RoutePayloadType, level: trust.LevelAdmin},
	ActStops:   {payloadType: StopsHeaderPayloadType, level: trust.LevelOperate},
	ActLift:    {payloadType: LiftPayloadType, level: trust.LevelOperate},
	ActApprove: {payloadType: AnswerPayloadType, level: trust.LevelOperate},
	ActPause:   {payloadType: PausePayloadType, level: trust.LevelOperate},
	ActRun:     {payloadType: RunPayloadType, level: trust.LevelOperate},
}

// Cause says why an answer is not a positive one. It is a closed set,
// counted per cause.
type Cause string

// The causes.
const (
	CauseNone Cause = ""
	// The ports the answer depends on.
	CauseRosterUnavailable Cause = "roster_unavailable"
	CauseLate              Cause = "late"
	CauseBusy              Cause = "busy"
	CauseCanceled          Cause = "canceled"
	CauseVetoUnavailable   Cause = "veto_unavailable"
	// The statement.
	CauseAct         Cause = "act"
	CausePayloadType Cause = "payload_type"
	CauseSignatures  Cause = "signatures"
	CauseTooLarge    Cause = "too_large"
	CauseUnknownKey  Cause = "unknown_key"
	CauseRole        Cause = "role"
	CauseSignature   Cause = "signature"
	CauseBody        Cause = "body"
	CauseAlg         Cause = "alg"
	CauseKeyID       Cause = "key_id"
	// The authority.
	CauseNotAuthenticated Cause = "not_authenticated"
	CauseScope            Cause = "scope"
	CauseRevoked          Cause = "revoked"
	CauseNoGrant          Cause = "no_grant"
	CauseVeto             Cause = "veto"
)

// AuthState is what an authentication answered. The zero AuthState is
// AuthUnavailable.
type AuthState uint8

// The authentication states.
const (
	// AuthUnavailable is no answer: the roster, or the time to ask it, ran
	// out. It is never read as a refusal that could be retried into a pass.
	AuthUnavailable AuthState = iota
	// AuthRefused is a statement no roster key signed as the act needs.
	AuthRefused
	// AuthAuthenticated is a statement a roster's operator key signed.
	AuthAuthenticated
)

// Authentication is an authenticator's answer. Only this package builds an
// authenticated one, from a verified signature, so the zero value and every
// value from elsewhere is unavailable.
type Authentication struct {
	state  AuthState
	cause  Cause
	act    Act
	issuer string
	key    trust.Key
	body   []byte
}

func authUnavailable(c Cause) Authentication { return Authentication{cause: c} }

func authRefused(c Cause) Authentication { return Authentication{state: AuthRefused, cause: c} }

// State is what the authentication answered.
func (a Authentication) State() AuthState { return a.state }

// Cause is why the answer is not authenticated.
func (a Authentication) Cause() Cause { return a.cause }

// Act is the act the statement was signed for.
func (a Authentication) Act() Act { return a.act }

// Issuer is who vouches for the subject: the roster, as "roster/<id>".
func (a Authentication) Issuer() string { return a.issuer }

// Subject is the operator the key belongs to.
func (a Authentication) Subject() string { return a.key.Subject() }

// KeyID is the id of the key that signed.
func (a Authentication) KeyID() string { return a.key.ID() }

// Body is the statement's verified body, the consumer's to read.
func (a Authentication) Body() []byte { return bytes.Clone(a.body) }

// PermState is what an authorization answered. The zero PermState is
// PermUnavailable.
type PermState uint8

// The permission states.
const (
	PermUnavailable PermState = iota
	PermDenied
	PermPermitted
)

// Permission is an authorizer's answer. Only this package builds a
// permitted one.
type Permission struct {
	state        PermState
	cause        Cause
	grant        trust.Grant
	rosterSerial int64
}

func permUnavailable(c Cause) Permission { return Permission{cause: c} }

func permDenied(c Cause) Permission { return Permission{state: PermDenied, cause: c} }

// State is what the authorization answered.
func (p Permission) State() PermState { return p.state }

// Cause is why the answer is not permitted.
func (p Permission) Cause() Cause { return p.cause }

// Grant is the grant that permitted the act, and the zero Grant otherwise.
func (p Permission) Grant() trust.Grant { return p.grant }

// RosterSerial is the serial of the roster whose grant permitted the act.
func (p Permission) RosterSerial() int64 { return p.rosterSerial }

// Request is what an operator asks to do: an act over one tenant's one
// project.
type Request struct {
	Act             Act
	Tenant, Project string
}
