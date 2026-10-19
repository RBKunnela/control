package hookbridge

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code can reassign one and turn a refusal into a
// pass. None quotes an event, a token or a tool's input.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// Profile refusals.
const (
	// ErrProfile is a profile this format cannot read.
	ErrProfile Error = "hookbridge: not a valid hook profile"
	// ErrProfileVersion is a hook profile of a version this package does not
	// read.
	ErrProfileVersion Error = "hookbridge: a hook profile version this bridge does not read"
	// ErrUnknownProfile is an id no built-in profile has.
	ErrUnknownProfile Error = "hookbridge: no such profile"
)

// Event refusals.
const (
	// ErrNoProfile is an event read without a profile.
	ErrNoProfile Error = "hookbridge: no profile"
	// ErrEventTooLarge is an event over the profile's max_event_bytes.
	ErrEventTooLarge Error = "hookbridge: the event is over its bound"
	// ErrEventEncoding is an event that is not valid UTF-8.
	ErrEventEncoding Error = "hookbridge: the event is not valid UTF-8"
	// ErrEventMalformed is an event that is not one JSON object, names a
	// member twice, or holds a member the profile reads in a shape it cannot
	// be.
	ErrEventMalformed Error = "hookbridge: the event is malformed"
	// ErrUnknownEvent is an event name the profile does not map to a phase.
	ErrUnknownEvent Error = "hookbridge: an event the profile does not name"
	// ErrNoCallID is an event without the runtime's id of the tool call.
	ErrNoCallID Error = "hookbridge: the event carries no call id"
	// ErrNoSession is an event without the runtime's session id.
	ErrNoSession Error = "hookbridge: the event carries no session id"
	// ErrNoInput is an admit event without a tool input.
	ErrNoInput Error = "hookbridge: the event carries no tool input"
	// ErrInputNotObject is a tool input that is not a JSON object.
	ErrInputNotObject Error = "hookbridge: the tool input is not an object"
)

// ErrNotConfigured is Pre or Post called without a profile, a client, a
// store or a run token.
const ErrNotConfigured Error = "hookbridge: a profile, a client, a store and a run token are required"

// Store refusals.
const (
	// ErrNoStoreDir is a store with no directory; there is no default.
	ErrNoStoreDir Error = "hookbridge: no store directory"
	// ErrStoreNotOwnerOnly is a store directory another account owns or may
	// enter, read or write.
	ErrStoreNotOwnerOnly Error = "hookbridge: the store directory is not this account's alone"
	// ErrNoEntry is a claim of a call no entry is published for, or whose
	// entry another claimer took.
	ErrNoEntry Error = "hookbridge: no entry for this call"
	// ErrEntry is an entry that cannot be published or read: an empty key
	// part, an empty handle, no expiry, or a body this store did not write.
	ErrEntry Error = "hookbridge: not a valid store entry"
)
