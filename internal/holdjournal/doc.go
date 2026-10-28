// Package holdjournal is the plane's own durable record of its own holds: a
// directory of small files written by the plane alone, under the directory's
// exclusive lock, so that a hold lost to a restart can be closed on its own
// trail instead of standing at its request for approval for good (ADR-0016).
//
// The journal has its own directory. Never the spool's, which the spool owns
// and locks, and never the approvals directory, which an approver may write:
// whoever writes this directory can already write the evidence, so nobody but
// the plane writes it.
//
// An entry is held, resuming or closing, and one write order is what makes
// held worth anything. It is the caller's to keep: the entry is recorded after
// the request for approval is appended, every append that would move that
// trail past it is preceded by a flip out of held, and the entry is forgotten
// once that trail can take nothing more. So held means the trail stands at its
// request for approval and can still be closed; any other state, and anything
// that will not decode, mean this plane cannot say, and are reported rather
// than acted on.
//
// An entry carries no envelope and no decision. A lost hold is closed, never
// resumed, and keeping what a retry would be compared against would widen what
// the plane holds on disk for behaviour nobody asked for.
//
// # What a refusal means to the gateway
//
// This package never imports the gateway. The adapter that satisfies the
// gateway's HoldJournal translates:
//
//	ErrEntry, ErrRequestName, ErrSchemaVersion, ErrEntryTooLarge -> ErrHoldEntry
//	ErrRecorded                                                  -> ErrHoldRecorded
//	ErrNoEntry                                                   -> ErrNoHoldEntry
//	ErrFlip                                                      -> ErrHoldFlip
//	ErrMaybeRecorded                                             -> ErrHoldMaybeRecorded
//
// Every other refusal travels as itself: the directory, the lock, a bound or a
// file that will not decode are not the entry's fault, and an operator acts on
// each of them differently. The pipeline refuses a hold on any error at all,
// so a refusal nobody translated still fails closed.
package holdjournal
