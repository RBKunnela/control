package observe

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/pkg/contract"
)

// connectionIDDomain separates a connection's id from every other SHA-256
// the product takes, the id of a span among them.
const connectionIDDomain = "observation-id:connection:1"

// MaxHostBytes bounds a connection's host, as DNS bounds a name.
const MaxHostBytes = 253

// ConnectionID derives a connection observation's id from its content: "obs-"
// and the first 32 lowercase hex digits of SHA-256 over the domain, the
// tenant, project and source ids, the event time's seconds and nanos, the
// host, and the connection's port, method, HTTP status, bytes sent, bytes
// received and caller. Each is preceded by its length as eight big-endian
// bytes, and a number is written in decimal. A connection read twice keeps
// its id, and two that differ in any of these do not share one.
func ConnectionID(o *observev1.Observation) string {
	c, t := o.GetConnection(), o.GetEventTime()
	fields := []string{
		connectionIDDomain,
		o.GetTenantId(), o.GetProjectId(), o.GetSource().GetSourceId(),
		strconv.FormatInt(t.GetSeconds(), 10), strconv.FormatInt(int64(t.GetNanos()), 10),
		o.GetSubject().GetName(),
		strconv.FormatUint(uint64(c.GetPort()), 10), c.GetMethod(), strconv.FormatUint(uint64(c.GetHttpStatus()), 10),
		strconv.FormatUint(c.GetBytesSent(), 10), strconv.FormatUint(c.GetBytesReceived(), 10),
		c.GetCaller(),
	}
	h := sha256.New()
	var n [8]byte
	for _, s := range fields {
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	return observationIDPrefix + hex.EncodeToString(h.Sum(nil)[:16])
}

// checkConnection holds an observation whose subject is a connection to the
// one form an importer writes: a connection member, no trace, span or run,
// basis none, stage indirect, an event time, a host, a method, status and
// caller an importer keeps, none of the members a span's observation fills,
// and the id of its content. The id covers every member but the receive
// time, the source's digest, trust and kind, and the caller basis, so an id
// the log already holds with other content in the rest is another connection.
func checkConnection(o *observev1.Observation) error {
	c := o.GetConnection()
	if c == nil {
		return fmt.Errorf("%w: connection: required for a subject of kind %s", ErrLine, observev1.SubjectKind_SUBJECT_KIND_CONNECTION)
	}
	if err := checkUnattributed(o); err != nil {
		return err
	}
	if err := checkHost(o.GetSubject().GetName()); err != nil {
		return fmt.Errorf("%w: subject.name: %w", ErrLine, err)
	}
	if member := spanMember(o); member != "" {
		return fmt.Errorf("%w: %s: set on a connection", ErrLine, member)
	}
	if err := checkConnectionValues(c); err != nil {
		return err
	}
	if o.GetObservationId() != ConnectionID(o) {
		return fmt.Errorf("%w: observation_id: %s is not the id of its connection's content",
			ErrLine, quoted(o.GetObservationId(), maxIdentifierBytes))
	}
	return nil
}

// connectionMethods are the methods a connection keeps. Any other token is
// dropped: an agent can choose it, so kept it would be a channel into the log.
var connectionMethods = map[string]bool{
	"CONNECT": true, "GET": true, "HEAD": true, "POST": true, "PUT": true,
	"PATCH": true, "DELETE": true, "OPTIONS": true, "TRACE": true,
}

// ConnectionMethod reports a method a connection keeps: one of CONNECT, GET,
// HEAD, POST, PUT, PATCH, DELETE, OPTIONS and TRACE.
func ConnectionMethod(m string) bool { return connectionMethods[m] }

// ConnectionStatus reports an HTTP status a connection keeps: 0, the log
// saying nothing, or 100 to 599.
func ConnectionStatus(n uint64) bool { return n == 0 || (n >= 100 && n <= 599) }

// addressCaller is the one form a caller under CALLER_BASIS_ADDRESS takes
// here: the characters an IP address and port are spelled with. Reading the
// address down to its one spelling is the importer's, which net/netip serves.
func addressCaller(s string) bool {
	return s != "" && strings.Trim(s, "0123456789abcdef.:[]") == ""
}

// checkConnectionValues holds the method, status and caller to what an
// importer keeps: a listed method or none, a status ConnectionStatus takes,
// and a caller that is copyable text, an address's characters under an
// address basis, and present under any basis but none.
func checkConnectionValues(c *observev1.Connection) error {
	caller, basis := c.GetCaller(), CallerBasisOf(c.GetCallerBasis())
	switch {
	case c.GetMethod() != "" && !ConnectionMethod(c.GetMethod()):
		return fmt.Errorf("%w: connection.method: %s is not a method a connection keeps", ErrLine, quoted(c.GetMethod(), maxIdentifierBytes))
	case !ConnectionStatus(uint64(c.GetHttpStatus())):
		return fmt.Errorf("%w: connection.http_status: %d is neither 0 nor 100 to 599", ErrLine, c.GetHttpStatus())
	case caller == "" && basis != observev1.CallerBasis_CALLER_BASIS_NONE:
		return fmt.Errorf("%w: connection.caller_basis: %s with no caller", ErrLine, c.GetCallerBasis())
	case caller != "" && !CopyableText(caller):
		return fmt.Errorf("%w: connection.caller: not text a record keeps", ErrLine)
	case caller != "" && basis == observev1.CallerBasis_CALLER_BASIS_ADDRESS && !addressCaller(caller):
		return fmt.Errorf("%w: connection.caller: %s is not an address, under %s", ErrLine, quoted(caller, maxIdentifierBytes), basis)
	}
	return nil
}

// CopyableText holds a string copied from an input into a record to
// ADR-0040's rules: at most MaxTextBytes, not only whitespace, and every rune
// printable.
func CopyableText(s string) bool {
	if len(s) > MaxTextBytes || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if !printable(r) {
			return false
		}
	}
	return true
}

// printable refuses what can hide or reshape text where a record is shown:
// control and format characters, line and paragraph separators, private use,
// noncharacters, and U+FFFD, which a lone surrogate escape decodes to.
func printable(r rune) bool {
	switch {
	case unicode.IsControl(r), unicode.In(r, unicode.Cf, unicode.Co, unicode.Zl, unicode.Zp):
		return false
	case r == utf8.RuneError, r >= 0xFDD0 && r <= 0xFDEF, r&0xFFFE == 0xFFFE:
		return false
	}
	return true
}

// checkUnattributed holds a connection to what it can say of its run in this
// contract, which is nothing, and to the one stage and time it has.
func checkUnattributed(o *observev1.Observation) error {
	corr := o.GetCorrelation()
	switch {
	case corr.GetTraceId() != "" || corr.GetSpanId() != "" || corr.GetParentSpanId() != "" || corr.GetRunId() != "":
		return fmt.Errorf("%w: correlation: a connection names no trace, span or run", ErrLine)
	case corr.GetBasis() != observev1.Basis_BASIS_NONE:
		return fmt.Errorf("%w: correlation.basis: %s on a connection, want %s", ErrLine, corr.GetBasis(), observev1.Basis_BASIS_NONE)
	case o.GetStage() != observev1.Stage_STAGE_INDIRECT:
		return fmt.Errorf("%w: stage: %s on a connection, want %s", ErrLine, o.GetStage(), observev1.Stage_STAGE_INDIRECT)
	case o.GetEventTime() == nil:
		return fmt.Errorf("%w: event_time: required on a connection", ErrLine)
	}
	return nil
}

// checkHost is the codec's coarse check of a host: present, bounded and in
// the one spelling a destination host has. Reading a log's value down to that
// spelling is the importer's.
func checkHost(host string) error {
	switch {
	case host == "":
		return errors.New("required")
	case len(host) > MaxHostBytes:
		return fmt.Errorf("%d bytes, limit %d", len(host), MaxHostBytes)
	}
	if err := contract.CheckHost(host); err != nil {
		return fmt.Errorf("%s is not a host: %w", quoted(host, MaxHostBytes), err)
	}
	return nil
}

// spanMember names the first member set on o that only a span's observation
// fills, or "".
func spanMember(o *observev1.Observation) string {
	s := o.GetSubject()
	switch {
	case s.GetOperation() != "":
		return "subject.operation"
	case s.GetProvider() != "":
		return "subject.provider"
	case s.GetServerAddress() != "":
		return "subject.server_address"
	case o.GetOutcome() != nil:
		return "outcome"
	case o.GetSource().GetConvention() != nil:
		return "source.convention"
	case o.GetContentAttributesDropped() != 0:
		return "content_attributes_dropped"
	}
	return ""
}

// checkRefusedBy holds a report's refusals by reason to its total: each
// reason counts at least one line, and together they are refused.
func checkRefusedBy(c *observev1.ImportCounts) error {
	by := c.GetRefusedBy()
	if len(by) == 0 {
		return nil
	}
	var sum uint64
	for reason, n := range by {
		if n == 0 {
			return fmt.Errorf("%w: counts.refused_by: %s counts no line", ErrLine, quoted(reason, maxIdentifierBytes))
		}
		next, carry := bits.Add64(sum, n, 0)
		if carry != 0 {
			return fmt.Errorf("%w: counts.refused_by: the reasons overflow a count", ErrLine)
		}
		sum = next
	}
	if sum != c.GetRefused() {
		return fmt.Errorf("%w: counts.refused_by: the reasons do not sum to refused (%d)", ErrLine, c.GetRefused())
	}
	return nil
}
