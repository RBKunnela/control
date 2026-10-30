package approvals

import (
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/pkg/contract"
)

const (
	// MaxApproverIDBytes bounds the approver's claimed name. It is an
	// unauthenticated claim, so the only thing bounded about it is what it
	// can cost a record and a listing.
	MaxApproverIDBytes = approval.MaxApproverIDBytes
	// MaxReasonBytes bounds the approver's reason.
	MaxReasonBytes = 1024
)

// CheckApproverID holds the approver's claimed name to the contract's
// identifier rule, so a value that records one thing and displays another
// never reaches an Approval, and refuses a name that reads as the reserved
// authn: prefix: nothing in this store authenticates an approver, so nothing
// it holds may say one was.
func CheckApproverID(id string) error {
	if id == "" || len(id) > MaxApproverIDBytes {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrApproverID, len(id), MaxApproverIDBytes)
	}
	if err := contract.CheckIdentifier(id); err != nil {
		return fmt.Errorf("%w: %w", ErrApproverID, err)
	}
	if err := approval.CheckClaimedApproverID(id); err != nil {
		return fmt.Errorf("%w: %w", ErrApproverID, err)
	}
	return nil
}

// checkReason holds the approver's reason to valid UTF-8 and to no control
// character at all, the line feed and the tab included: a reason is one line
// of a record and one line of a listing, and a reason that can end either is
// a reason that can forge the next one.
func checkReason(reason string) error {
	if len(reason) > MaxReasonBytes {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrReason, len(reason), MaxReasonBytes)
	}
	if !utf8.ValidString(reason) {
		return fmt.Errorf("%w: not valid UTF-8", ErrReason)
	}
	for i, r := range reason {
		if unicode.Is(unicode.Cc, r) {
			return fmt.Errorf("%w: a control character U+%04X at byte %d", ErrReason, r, i)
		}
	}
	return nil
}

// checkApprover holds the approver id a record carries to what Answer
// enforces before it reaches an Approval.
func (r Record) checkApprover() error {
	if id := r.Approval.GetApproverId(); id != "" {
		return CheckApproverID(id)
	}
	return nil
}

// checkTimes holds a record's three times to each other and to the longest
// window this plane could have minted.
//
// The window bound does not make a forged record impossible — write access to
// the directory is the approval authority — it bounds how long one stands: a
// forger cannot give a record an expiry further from its request than the
// plane's own, so a forged record is pruned like any other.
func (r Record) checkTimes(maxWindow time.Duration) error {
	a := r.Approval
	if a.GetRequestedAt() == nil || a.GetExpiresAt() == nil {
		return fmt.Errorf("%w: a record carries a requested time and an expiry", ErrInvalidHold)
	}
	requested, expires := a.GetRequestedAt().AsTime(), a.GetExpiresAt().AsTime()
	if window := expires.Sub(requested); window > maxWindow {
		return fmt.Errorf("%w: %s, limit %s", ErrExpiryWindow, window, maxWindow)
	}
	if a.GetDecidedAt() == nil {
		return nil
	}
	if decided := a.GetDecidedAt().AsTime(); decided.Before(requested) || decided.After(expires) {
		return fmt.Errorf("%w: decided %s, requested %s, expires %s",
			ErrDecidedAt, decided.Format(time.RFC3339Nano), requested.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano))
	}
	return nil
}
