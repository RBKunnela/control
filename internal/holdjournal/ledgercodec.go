package holdjournal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/internal/core/approval"
)

// LedgerSchemaVersion is the mark shape and the ledger directory's layout this
// build writes. A mark or a marker whose major differs is refused.
const LedgerSchemaVersion = "1.0"

// The bounds of what a mark names. A request id is bounded as an entry's is;
// the rest are far above what the plane writes and keep one mark small.
const (
	MaxLedgerApprovalIDBytes = 128
	MaxLedgerBindingBytes    = 256
	MaxLedgerProofBytes      = 512
)

// Mark is what the ledger says became of one approval. Its zero value is no
// mark this build knows, which nothing reads as either.
type Mark uint8

const (
	// MarkUnknown is no mark this build knows.
	MarkUnknown Mark = iota
	// MarkConsumed is an approval a plane spent.
	MarkConsumed
	// MarkNotResumed is an approval a plane gave up on.
	MarkNotResumed
)

// String names the mark as a mark spells it.
func (m Mark) String() string {
	switch m {
	case MarkUnknown:
		return "unknown"
	case MarkConsumed:
		return "consumed"
	case MarkNotResumed:
		return "not_resumed"
	}
	return "mark(" + strconv.Itoa(int(m)) + ")"
}

// suffix is the file name a mark takes after the names of what it marks.
func (m Mark) suffix() string {
	switch m {
	case MarkConsumed:
		return ".consumed"
	case MarkNotResumed:
		return ".not-resumed"
	}
	return ""
}

// LedgerEntry is one mark as it stands on disk.
type LedgerEntry struct {
	SchemaVersion string
	Mark          Mark
	Binding       approval.Binding
	RequestID     string
	ApprovalID    string
	// Proof is what the plane recorded beside a spend; empty for any other
	// mark.
	Proof string
	// Written is the plane's clock when the mark was made, which the sweep
	// prunes by.
	Written time.Time
}

// ledgerMagic opens every framed mark, as magic opens an entry.
const ledgerMagic = "SPENTLGR"

type wireMark struct {
	SchemaVersion string `json:"schema_version"`
	Mark          string `json:"mark"`
	Binding       string `json:"binding"`
	RequestID     string `json:"request_id"`
	ApprovalID    string `json:"approval_id"`
	Proof         string `json:"proof"`
	Written       string `json:"written"`
}

var markKeys = []string{"schema_version", "mark", "binding", "request_id", "approval_id", "proof", "written"}

// checkMarkNames refuses a mark that does not name one binding, one request
// and one approval within their bounds.
func checkMarkNames(b approval.Binding, req, appr string) error {
	switch {
	case b == "" || len(b) > MaxLedgerBindingBytes:
		return fmt.Errorf("%w: a binding of %d bytes, limit %d", ErrLedgerEntry, len(b), MaxLedgerBindingBytes)
	case req == "" || len(req) > MaxRequestIDBytes:
		return fmt.Errorf("%w: a request id of %d bytes, limit %d", ErrLedgerEntry, len(req), MaxRequestIDBytes)
	case appr == "" || len(appr) > MaxLedgerApprovalIDBytes:
		return fmt.Errorf("%w: an approval id of %d bytes, limit %d", ErrLedgerEntry, len(appr), MaxLedgerApprovalIDBytes)
	}
	return nil
}

// check holds a mark to what it claims about itself, in either direction.
func (e LedgerEntry) check() error {
	if err := checkSchemaVersion(e.SchemaVersion); err != nil {
		return err
	}
	if err := checkMarkNames(e.Binding, e.RequestID, e.ApprovalID); err != nil {
		return err
	}
	switch {
	case e.Written.IsZero():
		return fmt.Errorf("%w: the mark is not dated", ErrLedgerEntry)
	case len(e.Proof) > MaxLedgerProofBytes:
		return fmt.Errorf("%w: a proof of %d bytes, limit %d", ErrLedgerEntry, len(e.Proof), MaxLedgerProofBytes)
	case e.Mark == MarkConsumed && e.Proof == "":
		return fmt.Errorf("%w: a spend records its proof", ErrLedgerEntry)
	case e.Mark == MarkNotResumed && e.Proof != "":
		return fmt.Errorf("%w: only a spend records a proof", ErrLedgerEntry)
	case e.Mark != MarkConsumed && e.Mark != MarkNotResumed:
		return fmt.Errorf("%w: mark %s", ErrLedgerEntry, e.Mark)
	}
	return nil
}

// markName is the file name of a mark: the binding's digest, then the digest
// of the request and approval ids, then the mark. No id reaches the name, so
// none can name a file outside the directory, and the binding's digest leads
// so a lookup reads only the marks under its binding.
func markName(b approval.Binding, req, appr string, m Mark) string {
	return bindingPrefix(b) + keyDigest(req, appr) + m.suffix()
}

func bindingPrefix(b approval.Binding) string {
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:]) + "-"
}

// keyDigest digests the two ids length-prefixed, so no two pairs share one.
func keyDigest(req, appr string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d:%s%d:%s", len(req), req, len(appr), appr)
	return hex.EncodeToString(h.Sum(nil))
}

// isMarkName reports whether name is one this package writes for a mark: two
// lower-case sha256 digests and a mark's suffix.
func isMarkName(name string) bool {
	for _, m := range []Mark{MarkConsumed, MarkNotResumed} {
		body, ok := strings.CutSuffix(name, m.suffix())
		if !ok {
			continue
		}
		left, right, ok := strings.Cut(body, "-")
		return ok && isDigest(left) && isDigest(right)
	}
	return false
}

func isDigest(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// encodeMark frames e. It refuses a mark that does not check and a body over
// maxBody, so nothing is written that decodeMark would refuse to read.
func encodeMark(e LedgerEntry, maxBody int) ([]byte, error) {
	if err := e.check(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(wireMark{
		SchemaVersion: e.SchemaVersion,
		Mark:          e.Mark.String(),
		Binding:       string(e.Binding),
		RequestID:     e.RequestID,
		ApprovalID:    e.ApprovalID,
		Proof:         e.Proof,
		Written:       e.Written.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrEntryTooLarge, len(body), maxBody)
	}
	out := make([]byte, headerBytes+len(body))
	copy(out, ledgerMagic)
	binary.BigEndian.PutUint32(out[len(ledgerMagic):], uint32(len(body))) //nolint:gosec // G115: the bound above is far below the field
	binary.BigEndian.PutUint32(out[len(ledgerMagic)+4:], checksum(body))
	copy(out[headerBytes:], body)
	return out, nil
}

// decodeMark reads one framed mark, refusing it as decodeEntry refuses an
// entry.
func decodeMark(data []byte, maxBody int) (LedgerEntry, error) {
	body, err := unframe(data, ledgerMagic, maxBody)
	if err != nil {
		return LedgerEntry{}, err
	}
	if err := checkMembers(body, markKeys...); err != nil {
		return LedgerEntry{}, err
	}
	var w wireMark
	if err := json.Unmarshal(body, &w); err != nil {
		var typed *json.UnmarshalTypeError
		if errors.As(err, &typed) {
			return LedgerEntry{}, fmt.Errorf("%w: %q holds a %s", ErrFieldType, cause(typed.Field), typed.Value)
		}
		return LedgerEntry{}, fmt.Errorf("%w: %s", ErrMalformed, cause(err.Error()))
	}
	if err := checkSchemaVersion(w.SchemaVersion); err != nil {
		return LedgerEntry{}, err
	}
	m := MarkUnknown
	for _, known := range []Mark{MarkConsumed, MarkNotResumed} {
		if known.String() == w.Mark {
			m = known
		}
	}
	if m == MarkUnknown {
		return LedgerEntry{}, fmt.Errorf("%w: mark %q", ErrMalformed, cause(w.Mark))
	}
	written, err := time.Parse(time.RFC3339Nano, w.Written)
	if err != nil || written.UTC().Format(time.RFC3339Nano) != w.Written {
		return LedgerEntry{}, fmt.Errorf("%w: the time written %q is not spelled as this build writes it", ErrMalformed, cause(w.Written))
	}
	e := LedgerEntry{
		SchemaVersion: w.SchemaVersion, Mark: m, Binding: approval.Binding(w.Binding),
		RequestID: w.RequestID, ApprovalID: w.ApprovalID, Proof: w.Proof, Written: written,
	}
	if err := e.check(); err != nil {
		return LedgerEntry{}, err
	}
	return e, nil
}
