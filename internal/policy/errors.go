package policy

import "github.com/guardana/control/internal/policy/bundle"

// Error is a refusal by Sign, Load or a Holder, matched with errors.Is. Each
// check Load runs has its own. They are constants, so no other code in the
// binary can reassign one and turn a refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// Load's refusals, one per check, in the order Load runs the checks.
const (
	// ErrNoBundle is a nil bundle.
	ErrNoBundle Error = "policy: no bundle"
	// ErrTooLarge is a canonical over the parser's bound of 1 MiB, refused
	// before the bundle is copied or hashed.
	ErrTooLarge Error = "policy: canonical is over a bound"
	// ErrUnknownField is a field this build does not know, on the bundle, its
	// ref or the ref's created_at. The runtime keeps a known field sent with
	// another wire type among the unknown ones, so that is refused too.
	ErrUnknownField Error = "policy: the bundle carries a field this build does not know"
	// ErrSignatureAlg is any signature_alg but the one value it may hold.
	ErrSignatureAlg Error = "policy: signature_alg is not " + bundle.SignatureAlg
	// ErrKey is a key_id that selects no pinned key this build can use: an
	// unknown or empty id, a key of the wrong size or a key of small order. It
	// wraps the bundle package's own refusal.
	ErrKey Error = "policy: key_id selects no usable pinned key"
	// ErrSignature is a signature that does not verify. It wraps the bundle
	// package's own refusal.
	ErrSignature Error = "policy: the signature does not verify"
	// ErrDocument is canonical bytes that are not a policy document the kernel
	// can run. It wraps the refusal of the parse or of the compile.
	ErrDocument Error = "policy: canonical is not a valid policy document"
	// ErrNotCanonical is a document that is not its own canonical form, which
	// would give one policy two digests.
	ErrNotCanonical Error = "policy: canonical is not its own canonical form"
	// ErrDigest is a ref.digest that is not the digest of canonical.
	ErrDigest Error = "policy: ref.digest is not the digest of canonical"
	// ErrMismatch is a ref.bundle_id, ref.version or max_stale_seconds that
	// differs from what the signed document says.
	ErrMismatch Error = "policy: a field outside canonical differs from the document"
	// ErrCreatedAt is a ref.created_at that is set: no creation time is signed,
	// so any value there is the sender's word alone.
	ErrCreatedAt Error = "policy: ref.created_at is set, and no creation time is signed"
)

// Sign's own refusals, beside ErrDocument for a document Parse refuses.
const (
	// ErrSigningKey is a private key that cannot sign: one of the wrong size,
	// or one whose public half is not its seed's. It wraps the bundle
	// package's own refusal.
	ErrSigningKey Error = "policy: the private key cannot sign"
	// ErrObligationParams is a document that parses, and would load, holding
	// an obligation parameter the catalogue does not declare for its type, a
	// missing required one or a value outside its grammar. It wraps the
	// rules package's refusal; Load never returns it.
	ErrObligationParams Error = "policy: an obligation's parameters are not the catalogue's"
)

// A Holder's refusals of a bundle that passed every check of Load.
const (
	// ErrRollback is a serial below one installed before for its bundle id.
	ErrRollback Error = "policy: a serial below one installed for this bundle id"
	// ErrSerialReused is a serial installed before for its bundle id, with
	// another digest.
	ErrSerialReused Error = "policy: a serial installed for this bundle id with another digest"
	// ErrBundlePin is a bundle whose id is not the one the Holder was pinned
	// to.
	ErrBundlePin Error = "policy: the bundle id is not the one this holder is pinned to"
)

// VerifyStatement's refusals of a freshness statement (ADR-0038), in the order
// it runs its checks.
const (
	// ErrStatementPayloadType is an envelope whose payload type is not
	// bundle.StatementPayloadType.
	ErrStatementPayloadType Error = "policy: the envelope's payload type is not the freshness statement's"
	// ErrStatementSignatures is an envelope with no signature or more than one.
	ErrStatementSignatures Error = "policy: a freshness statement carries exactly one signature"
	// ErrStatementTooLarge is a statement body over MaxStatementBytes.
	ErrStatementTooLarge Error = "policy: the freshness statement is over its bound"
	// ErrStatementKey is a keyid that selects no pinned freshness key this
	// build can use. It wraps the bundle package's own refusal.
	ErrStatementKey Error = "policy: the statement's keyid selects no usable pinned freshness key"
	// ErrStatementSignature is a statement signature that does not verify. It
	// wraps the bundle package's own refusal.
	ErrStatementSignature Error = "policy: the statement's signature does not verify"
	// ErrStatementJSON is a body that is not one strict JSON object of plain
	// members: a syntax error, trailing data, invalid UTF-8, an unpaired
	// surrogate or an integer outside the JSON-safe range.
	ErrStatementJSON Error = "policy: the statement body is not one strict JSON object"
	// ErrStatementRepeatedMember is a member named twice, which a decoder would
	// read as its last value.
	ErrStatementRepeatedMember Error = "policy: the statement body names a member twice"
	// ErrStatementKind is a kind other than StatementKind.
	ErrStatementKind Error = "policy: the statement's kind is not " + StatementKind
	// ErrStatementUnknownMember is a member the statement format does not have.
	ErrStatementUnknownMember Error = "policy: the statement body holds a member the format does not have"
	// ErrStatementMissingMember is a member the statement format requires and
	// the body does not hold.
	ErrStatementMissingMember Error = "policy: the statement body lacks a member the format requires"
	// ErrStatementValue is a bundleId, serial or digest of the wrong type or
	// form.
	ErrStatementValue Error = "policy: a statement member holds a value of the wrong type or form"
	// ErrStatementIssuedAt is an issuedAt in any spelling but
	// YYYY-MM-DDTHH:MM:SSZ, or one that names the zero time.
	ErrStatementIssuedAt Error = "policy: issuedAt is not YYYY-MM-DDTHH:MM:SSZ"
)

// The floor's and the confirming holder's refusals (ADR-0038).
const (
	// ErrFloorInvalid is a floor that names no bundle id or holds values no
	// accepted statement could have left, the zero Floor among them.
	ErrFloorInvalid Error = "policy: not a floor"
	// ErrFloorBundle is a statement or a bundle of another bundle id than the
	// floor's.
	ErrFloorBundle Error = "policy: the bundle id is not the floor's"
	// ErrStatementFuture is a statement dated after the clock reading it is
	// judged at.
	ErrStatementFuture Error = "policy: the statement is dated after the clock"
	// ErrClockBehindFloor is a clock reading earlier than the latest issuedAt
	// the floor holds.
	ErrClockBehindFloor Error = "policy: the clock reads earlier than the latest issuedAt the floor holds"
	// ErrBelowFloor is a statement at or below the floor's serial and
	// issuedAt other than the floor's own, or a bundle below the floor's
	// serial.
	ErrBelowFloor Error = "policy: at or below the floor"
	// ErrFloorSerialReused is the floor's serial with another digest.
	ErrFloorSerialReused Error = "policy: the floor's serial with another digest"
	// ErrAboveFloorUnbound is a bundle above the floor's serial with no
	// statement bound to it that the floor takes.
	ErrAboveFloorUnbound Error = "policy: a bundle above the floor with no statement the floor takes"
	// ErrStatementMissing is a bundle no verified statement is bound to.
	ErrStatementMissing Error = "policy: no verified statement is bound to the bundle"
	// ErrStatementUnbound is a statement naming another bundle id, serial or
	// digest than the bundle it was to confirm.
	ErrStatementUnbound Error = "policy: the statement names another bundle id, serial or digest"
	// ErrFloorRaise is a raise the floor store did not make, or made to a
	// floor that is not the statement's. It wraps the store's refusal, and
	// nothing was installed.
	ErrFloorRaise Error = "policy: the floor was not raised to the statement, so nothing was installed"
	// ErrNoFloorStore is an entry point called on a holder made without a
	// floor store, the zero Holder among them, or NewFloorHolder given none.
	ErrNoFloorStore Error = "policy: this holder has no floor store"
	// ErrFloorRead is a floor the store could not read. It wraps the store's
	// error, and nothing was installed.
	ErrFloorRead Error = "policy: the floor store could not be read, so nothing was installed"
	// ErrConfirmationWithdrawn is a statement issued no later than the
	// confirmation Unconfirm withdrew: only a statement issued after it
	// confirms the holder again.
	ErrConfirmationWithdrawn Error = "policy: the statement is not newer than the confirmation that was withdrawn"
)
