package approvals

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The vocabulary an approval store answers a plane in. It is the gateway's
// ApprovalStore vocabulary, one sentinel per documented refusal, so a caller
// translates rather than interprets.
const (
	// ErrNoApproval is a binding nothing approves: no record, a record no
	// approver has approved, or one resolved not-resumed.
	ErrNoApproval Error = "approvals: no approval for this binding"
	// ErrApprovalConsumed is an approval an earlier execution already used.
	ErrApprovalConsumed Error = "approvals: the approval was consumed"
	// ErrApprovalExpired is an approval at or past its expiry at the clock it
	// was compared with.
	ErrApprovalExpired Error = "approvals: the approval has expired"
	// ErrApprovalRejected is an approval an approver refused. It is returned
	// beside the record that was read.
	ErrApprovalRejected Error = "approvals: the approval was rejected"
	// ErrMultiUse is a record marked multi-use, which this store does not
	// honour.
	ErrMultiUse Error = "approvals: a multi-use approval is not honoured"
	// ErrZeroTime is a clock reading of zero, which would pass every expiry.
	ErrZeroTime Error = "approvals: the clock reads zero"
	// ErrInvalidHold is a hold with no approval, no approval id, no request
	// id, no binding, no requested time, no expiry, or one whose parts
	// disagree.
	ErrInvalidHold Error = "approvals: a held request needs an approval, an approval id, a request id, a binding, a requested time and an expiry"
	// ErrAlreadyHeld is a second hold of one request id under one binding, or
	// of one approval id.
	ErrAlreadyHeld Error = "approvals: this request is already held under this binding"
)

// The vocabulary of an answer.
const (
	// ErrApprovalAnswer is an answer that is neither APPROVED with an
	// approver nor REJECTED.
	ErrApprovalAnswer Error = "approvals: an answer is APPROVED with an approver, or REJECTED"
	// ErrApprovalAnswered is an answer to a record an approver answered
	// already.
	ErrApprovalAnswered Error = "approvals: the approval was answered already"
	// ErrOutcomeUnknown is a write that failed after its name was linked,
	// where the name was gone before it could be taken back. Another process
	// unlinked it, and may have acted on it first.
	ErrOutcomeUnknown Error = "approvals: the name was gone before it could be taken back, so whether it was read is unknown"
	// ErrResolved is an attempt to resolve a record the plane has resolved
	// already. Resolve does not answer it: the outcome its caller asked for
	// is the outcome on disk.
	ErrResolved Error = "approvals: the record is resolved already"
	// ErrResolution is a resolution a store may not be told to write. Only
	// the consuming path marks a record spent, because that record is the
	// plane's proof that an execution happened.
	ErrResolution Error = "approvals: a store resolves a record as not resumed and nothing else"
	// ErrApproverID is an approver id that is empty, over MaxApproverIDBytes,
	// holds a code point no identifier may hold, or reads as the reserved
	// authn: prefix, with approval.ErrReservedApproverID beside it.
	ErrApproverID Error = "approvals: the approver id is empty, too long, holds a refused code point, or spells the reserved authn: prefix"
	// ErrReason is a reason over MaxReasonBytes, or one holding a control
	// character or invalid UTF-8.
	ErrReason Error = "approvals: the reason is too long, or holds a control character"
	// ErrDecidedAt is a record answered before it was requested or after it
	// expired.
	ErrDecidedAt Error = "approvals: the record was decided outside the window it was held for"
	// ErrExpiryWindow is a record whose expiry stands further from its request
	// than the longest window this plane could have minted.
	ErrExpiryWindow Error = "approvals: the record expires further from its request than the plane could mint"
)

// The vocabulary of the directory and of a record on disk. Each refusal is its
// own sentinel: a caller that cannot tell a truncated record from an unknown
// field cannot report what an operator has to fix.
const (
	// ErrClosed is an operation on a handle nobody opened, or one already
	// closed. The zero value of either handle answers it.
	ErrClosed Error = "approvals: the store is not open"
	// ErrLocked is an OpenPlane of a directory another plane holds.
	ErrLocked Error = "approvals: the directory is held by another plane"
	// ErrNoLock is a platform with no file lock. Both handles refuse to open
	// rather than serve a directory nothing holds.
	ErrNoLock Error = "approvals: this platform has no file lock, so the directory cannot be held"
	// ErrPermissions is a directory a group or the world may write.
	ErrPermissions Error = "approvals: the directory is group- or world-writable"
	// ErrOwner is a directory another account owns: its approvals would be
	// that account's.
	ErrOwner Error = "approvals: the directory is not owned by this account"
	// ErrDirectoryChanged is a directory that is no longer the one a handle
	// opened: another directory at its name, another owner, or a mode a group
	// or the world may write. Every call of either handle judges it first.
	ErrDirectoryChanged Error = "approvals: the directory changed since it was opened"
	// ErrNotAStore is a directory that is not an approvals store: no marker
	// and not empty, or a marker this build cannot read.
	ErrNotAStore Error = "approvals: the directory is not an approvals store"
	// ErrForeignFile is a file under the directory that is neither a record,
	// a projection, the marker nor a temporary file, any entry that is not a
	// regular file whatever it is called, and a file read that another
	// account owns or a group or the world may write.
	ErrForeignFile Error = "approvals: a file under the directory is not the store's"
	// ErrTooManyRecords is a directory holding more records than the bound
	// allows. A hold is refused; a listing says it is incomplete.
	ErrTooManyRecords Error = "approvals: the directory holds more records than the bound allows"
	// ErrRecordTooLarge is a record whose body is over the bound, in either
	// direction.
	ErrRecordTooLarge Error = "approvals: the record is larger than the bound allows"
	// ErrTruncated is a file too short for the record it claims.
	ErrTruncated Error = "approvals: the record is truncated"
	// ErrCorrupt is a record whose framing does not check: a wrong magic, a
	// checksum that does not match the body, or bytes past the body's end.
	ErrCorrupt Error = "approvals: the record does not check"
	// ErrUnknownField is a record carrying a field this build cannot name.
	// Reading it as if the field were absent would silently drop what a
	// writer thought mattered.
	ErrUnknownField Error = "approvals: the record carries an unknown field"
	// ErrFieldType is a record whose field holds a value of another type.
	ErrFieldType Error = "approvals: a field of the record holds the wrong type"
	// ErrSchemaVersion is a record whose schema version has a major this
	// build does not understand, or none at all.
	ErrSchemaVersion Error = "approvals: the record's schema version is not one this build reads"
	// ErrMalformed is a record body that is not one JSON object of one
	// record, or one whose resolution this build cannot name.
	ErrMalformed Error = "approvals: the record is malformed"
	// ErrNameMismatch is a record whose file name disagrees with what the
	// record carries inside, or whose state disagrees with its resolution.
	ErrNameMismatch Error = "approvals: the record's file name disagrees with the record"
	// ErrRecordMismatch is a record that disagrees with itself: an approval
	// naming another request, a binding that is not the one its digests make,
	// or two live records for one request.
	ErrRecordMismatch Error = "approvals: the record disagrees with itself"
	// ErrRecordName is an approval id that cannot name a file.
	ErrRecordName Error = "approvals: the approval id cannot name a file"
	// ErrInvalidOption is an option outside its range.
	ErrInvalidOption Error = "approvals: invalid option"
)
