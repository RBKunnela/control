package reaction

import "fmt"

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass. No refusal quotes the value it refused.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// LineError is a list refused at one of its lines: the judge accepts every
// line before Line.
type LineError struct {
	Line int64
	Err  error
}

// Error names the line and the refusal.
func (e *LineError) Error() string { return fmt.Sprintf("line %d: %v", e.Line, e.Err) }

// Unwrap is the refusal.
func (e *LineError) Unwrap() error { return e.Err }

// The route document's refusals.
const (
	ErrRouteTooLarge     Error = "reaction: the route is over its bound"
	ErrRouteJSON         Error = "reaction: the route is not one strict JSON object"
	ErrRouteRepeated     Error = "reaction: the route names a member twice"
	ErrRouteKind         Error = "reaction: the route's kind is not " + RouteKind
	ErrRouteMember       Error = "reaction: the route holds a member its format does not have, or lacks one it requires"
	ErrRouteValue        Error = "reaction: a route member holds a value of the wrong type, form or length"
	ErrRouteSerial       Error = "reaction: the route's serial is not an integer from 1 to 2^53-1"
	ErrRouteScope        Error = "reaction: the route's scope is not " + ScopeRun
	ErrRouteRules        Error = "reaction: the route holds no rule, or more than its bound"
	ErrRouteRuleRepeated Error = "reaction: the route names one rule twice"
	ErrRouteLifetime     Error = "reaction: a rule's expires_seconds is not an integer from 60 to the longest run lifetime"
	ErrRouteNotCanonical Error = "reaction: the signed route is not its own canonical form"
	ErrRouteRuleStops    Error = "reaction: the route names a rule that may not stop a run"
)

// The lift payload's refusals.
const (
	ErrLiftTooLarge     Error = "reaction: the lift is over its bound"
	ErrLiftJSON         Error = "reaction: the lift is not one strict JSON object"
	ErrLiftRepeated     Error = "reaction: the lift names a member twice"
	ErrLiftKind         Error = "reaction: the lift's kind is not " + LiftKind
	ErrLiftMember       Error = "reaction: the lift holds a member its format does not have, or lacks one it requires"
	ErrLiftValue        Error = "reaction: a lift member holds a value of the wrong type, form or length"
	ErrLiftVersion      Error = "reaction: the lift's version is not one this build reads"
	ErrLiftLine         Error = "reaction: the lift's through_line is not an integer from 1 to 2^53-1"
	ErrLiftNotCanonical Error = "reaction: the signed lift is not its own canonical form"
)

// The signed envelope's refusals, the route's and the lift's apart.
const (
	ErrRoutePayloadType Error = "reaction: the envelope's payload type is not the route's"
	ErrRouteSignatures  Error = "reaction: a route carries exactly one signature"
	ErrRouteKey         Error = "reaction: the route's keyid selects no usable route key"
	ErrRouteSignature   Error = "reaction: the route's signature does not verify"
	ErrLiftPayloadType  Error = "reaction: the envelope's payload type is not the lift's"
	ErrLiftSignatures   Error = "reaction: a lift carries exactly one signature"
	ErrLiftKey          Error = "reaction: the lift's keyid selects no usable lift key"
	ErrLiftSignature    Error = "reaction: the lift's signature does not verify"
	ErrSigningKey       Error = "reaction: the private key cannot sign"
	ErrKeySize          Error = "reaction: a public key is not 32 bytes"
	ErrKeysEqual        Error = "reaction: two keys that must differ are equal"
)

// Route.Permits's refusals of a stop's claim.
const (
	ErrClaimTenant   Error = "reaction: the stop's tenant is not the route's"
	ErrClaimRule     Error = "reaction: the stop's procedure and rule are no rule of the route"
	ErrClaimTimes    Error = "reaction: the stop's created_at and expires_at are not two usable times in order"
	ErrClaimLifetime Error = "reaction: the stop lasts longer than its rule allows"
)

// ErrStopSuperseded is CheckCurrent's refusal of a stop a writer would
// append.
const ErrStopSuperseded Error = "reaction: the stop names a rule version a later one superseded"

// Eligible's refusals of a finding.
const (
	ErrFindingSource  Error = "reaction: the finding's source is not DETERMINISTIC"
	ErrFindingVerdict Error = "reaction: the finding's verdict is not CONFIRMED"
	ErrRunUnknown     Error = "reaction: the finding names no opened run the runs directory holds"
	ErrRunTenant      Error = "reaction: the finding's tenant is not its run's"
	ErrRunProject     Error = "reaction: the finding's project is not its run's"
	ErrRunClosed      Error = "reaction: the finding's run is closed"
	ErrRunExpired     Error = "reaction: the finding's run is expired at the time given"
	ErrRunExpiry      Error = "reaction: the finding's run holds no usable expiry"
	ErrClock          Error = "reaction: the time given is not a usable time"
)
