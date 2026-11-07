package reaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/pkg/contract"
)

const (
	// ListVersion is the one version a stop list line may name, in this one
	// spelling, as a lift's.
	ListVersion = "1.0"
	// SignedListVersion is the version of every line of a stop list judged
	// against a v1alpha2 route: its header signed by an operator, its stops
	// and covered lines naming the project, and its lifts v1alpha2.
	SignedListVersion = "2.0"
	// MaxLineBytes bounds one line of a stop list, its newline left out.
	MaxLineBytes = 64 << 10
	// MaxFindingIDBytes bounds the finding id a line names.
	MaxFindingIDBytes = 128
	// MaxLiftEnvelopeBytes bounds the envelope a lift line carries. The
	// base64 of a lift of MaxLiftBytes and one signature fit within it.
	MaxLiftEnvelopeBytes = 8192
	// EntryIDPrefix begins every entry id.
	EntryIDPrefix = "stp-"
)

// entryIDDomain separates the entry id's hash from every other SHA-256 the
// product takes.
const entryIDDomain = "agent-reaction-stop-entry/v1\n"

// LineKind is what one line of a stop list is.
type LineKind uint8

// The four kinds of line. The zero value is no kind.
const (
	KindHeader LineKind = iota + 1
	KindStop
	KindCovered
	KindLift
)

// The kind member's spelling of each line kind.
const (
	kindHeader  = "header"
	kindStop    = "stop"
	kindCovered = "covered"
	kindLift    = "lift"
)

const (
	memberRouteSerial = "route_serial"
	memberEntryID     = "entry_id"
	memberFindingID   = "finding_id"
	memberProcVersion = "procedure_version"
	memberProcDigest  = "procedure_digest"
	memberCreatedAt   = "created_at"
	memberExpiresAt   = "expires_at"
	memberEnvelope    = "envelope"
)

// The refusals of one line, whatever its place in the list.
const (
	ErrLineTooLong   Error = "reaction: a stop list line is over its bound"
	ErrLineJSON      Error = "reaction: a stop list line is not one strict JSON object"
	ErrLineRepeat    Error = "reaction: a stop list line names a member twice"
	ErrLineKind      Error = "reaction: a stop list line's kind is none of header, stop, covered and lift"
	ErrLineMember    Error = "reaction: a stop list line holds a member its kind does not have, or lacks one it requires"
	ErrLineVersion   Error = "reaction: a stop list line's version is not one this build reads"
	ErrLineValue     Error = "reaction: a stop list line member holds a value of the wrong type, form or length"
	ErrLineTime      Error = "reaction: a stop list line's time is not spelled YYYY-MM-DDTHH:MM:SSZ"
	ErrEntryID       Error = "reaction: a stop's entry_id is not the one its finding id derives"
	ErrLineCanonical Error = "reaction: a stop list line is not spelled in its canonical form"
)

// Header is a stop list's first line: the list's own id and the route it is
// judged against.
type Header struct {
	ListID      string
	RouteID     string
	RouteSerial int64
	RouteDigest string
	// Signed is what an operator signed of a 2.0 header, and the zero value
	// in a 1.0 one.
	Signed HeaderSigned
}

// HeaderFor is the header of a list with listID judged against r.
func HeaderFor(r Route, listID string) Header {
	return Header{ListID: listID, RouteID: r.id, RouteSerial: r.serial, RouteDigest: r.digest}
}

// Stop is a stop line: one finding stops one run of one tenant from
// CreatedAt until ExpiresAt, unless a lift ends it first.
type Stop struct {
	EntryID, TenantID, RunID, FindingID string
	// ProjectID and Scope are set in a 2.0 line and empty in a 1.0 one.
	ProjectID, Scope                               string
	ProcedureID, ProcedureVersion, ProcedureDigest string
	RuleID, RuleVersion                            string
	CreatedAt, ExpiresAt                           time.Time
}

// Claim is what the stop says of itself that a route judges.
func (s Stop) Claim() StopClaim {
	return StopClaim{
		TenantID: s.TenantID, ProjectID: s.ProjectID, Scope: s.Scope, ProcedureID: s.ProcedureID, ProcedureVersion: s.ProcedureVersion,
		ProcedureDigest: s.ProcedureDigest, RuleID: s.RuleID, RuleVersion: s.RuleVersion,
		CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
	}
}

// Covered is a covered line: a finding about a run an earlier stop names,
// written so the finding is named and never becomes a stop of its own.
type Covered struct {
	FindingID, TenantID, RunID string
	// ProjectID is set in a 2.0 line and empty in a 1.0 one.
	ProjectID string
	CreatedAt time.Time
}

// LiftLine is a lift line: the run and line its clear fields name, and the
// signed lift that must name the same.
type LiftLine struct {
	RunID       string
	ThroughLine int64
	Envelope    Envelope
}

// Line is one line of a stop list as ParseLine read it; only the member
// Kind names is set.
type Line struct {
	Kind    LineKind
	Version string
	// HeaderEnvelope is a 2.0 header line's signed envelope.
	HeaderEnvelope Envelope
	Header         Header
	Stop           Stop
	Covered        Covered
	Lift           LiftLine
}

// EntryID is "stp-" and the first 32 lowercase hex digits of SHA-256 over
// the entry id's domain and findingID.
func EntryID(findingID string) string {
	sum := sha256.Sum256([]byte(entryIDDomain + findingID))
	return EntryIDPrefix + hex.EncodeToString(sum[:16])
}

func lineRefusals() docRefusals {
	return docRefusals{json: ErrLineJSON, repeated: ErrLineRepeat, kind: ErrLineKind, member: ErrLineMember}
}

// ParseLine reads one stop list line, its newline left out: one strict JSON
// object of at most MaxLineBytes, of one of the four kinds, with version
// ListVersion and exactly the members its kind has. It judges the line alone;
// Judge judges its place in the list.
func ParseLine(raw []byte) (Line, error) {
	if n := len(raw); n > MaxLineBytes {
		return Line{}, fmt.Errorf("%w: %d bytes, limit %d", ErrLineTooLong, n, MaxLineBytes)
	}
	o, err := readObject(raw, lineRefusals())
	if err != nil {
		return Line{}, err
	}
	kind, _ := strictjson.String(o[memberKind])
	v, ok := strictjson.String(o[memberVersion])
	if ok && v != ListVersion && v != SignedListVersion {
		return Line{}, ErrLineVersion
	}
	l, err := readKind(o, kind, v)
	if err != nil {
		return Line{}, err
	}
	// The members are read; what is left to refuse is invalid UTF-8 or an
	// unpaired surrogate, which a decoded string hides, and any spelling but
	// the canonical one, which two readers of one list could part over.
	canonical, err := canonicalOf(raw, ErrLineJSON)
	if err != nil {
		return Line{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return Line{}, ErrLineCanonical
	}
	return l, nil
}

// readKind reads the members of a line of kind at version v.
func readKind(o strictjson.Object, kind, v string) (Line, error) {
	l := Line{Version: v}
	signed := v == SignedListVersion
	var err error
	switch kind {
	case kindHeader:
		l.Kind = KindHeader
		if signed {
			l.Header, l.HeaderEnvelope, err = readSignedHeaderLine(o)
		} else {
			err = readHeader(o, &l.Header)
		}
	case kindStop:
		l.Kind, err = KindStop, readStop(o, signed, &l.Stop)
	case kindCovered:
		l.Kind, err = KindCovered, readCovered(o, signed, &l.Covered)
	case kindLift:
		l.Kind, err = KindLift, readLiftLine(o, &l.Lift)
	default:
		return Line{}, ErrLineKind
	}
	return l, err
}

func lineMembers(o strictjson.Object, names ...string) error {
	all := append([]string{memberKind, memberVersion}, names...)
	if err := members(o, lineRefusals(), all, all); err != nil {
		return err
	}
	if _, ok := strictjson.String(o[memberVersion]); !ok {
		return ErrLineVersion
	}
	return nil
}

func readHeader(o strictjson.Object, h *Header) error {
	if err := lineMembers(o, memberListID, memberRouteID, memberRouteSerial, memberRouteDigest); err != nil {
		return err
	}
	var ok bool
	if h.ListID, ok = identifier(o[memberListID], MaxListIDBytes); !ok {
		return fmt.Errorf("%w: %s", ErrLineValue, memberListID)
	}
	if h.RouteID, ok = strictjson.String(o[memberRouteID]); !ok || !policy.ValidID(h.RouteID) {
		return fmt.Errorf("%w: %s", ErrLineValue, memberRouteID)
	}
	if h.RouteSerial, ok = integer(o[memberRouteSerial], 1, policy.MaxSerial); !ok {
		return fmt.Errorf("%w: %s", ErrLineValue, memberRouteSerial)
	}
	return digestOf(o, memberRouteDigest, &h.RouteDigest)
}

func readStop(o strictjson.Object, signed bool, s *Stop) error {
	names := []string{memberEntryID, memberTenantID, memberRunID, memberFindingID, memberProcedure,
		memberProcVersion, memberProcDigest, memberRuleID, memberRuleVer, memberCreatedAt, memberExpiresAt}
	if signed {
		names = append(names, memberProjectID, memberScope)
	}
	if err := lineMembers(o, names...); err != nil {
		return err
	}
	if err := readRunFields(o, &s.FindingID, &s.TenantID, &s.RunID); err != nil {
		return err
	}
	if signed {
		if err := readStopScope(o, s); err != nil {
			return err
		}
	}
	if err := readStopRule(o, s); err != nil {
		return err
	}
	if err := timeOf(o, memberCreatedAt, &s.CreatedAt); err != nil {
		return err
	}
	if err := timeOf(o, memberExpiresAt, &s.ExpiresAt); err != nil {
		return err
	}
	entryID, ok := strictjson.String(o[memberEntryID])
	if !ok || entryID != EntryID(s.FindingID) {
		return ErrEntryID
	}
	s.EntryID = entryID
	return nil
}

// readStopRule reads the procedure and the rule a stop names.
func readStopRule(o strictjson.Object, s *Stop) error {
	for _, f := range [...]struct {
		name string
		into *string
	}{
		{memberProcedure, &s.ProcedureID}, {memberProcVersion, &s.ProcedureVersion},
		{memberRuleID, &s.RuleID}, {memberRuleVer, &s.RuleVersion},
	} {
		if err := identifierOf(o, f.name, contract.MaxStringBytes, f.into); err != nil {
			return err
		}
	}
	digest, ok := strictjson.String(o[memberProcDigest])
	if !ok || !procedureDigest(digest) {
		return fmt.Errorf("%w: %s", ErrLineValue, memberProcDigest)
	}
	s.ProcedureDigest = digest
	return nil
}

// readStopScope reads the project and the scope a 2.0 stop names.
func readStopScope(o strictjson.Object, s *Stop) error {
	if err := identifierOf(o, memberProjectID, MaxProjectIDBytes, &s.ProjectID); err != nil {
		return err
	}
	if scope, ok := strictjson.String(o[memberScope]); !ok || scope != ScopeRun {
		return fmt.Errorf("%w: %s", ErrLineValue, memberScope)
	}
	s.Scope = ScopeRun
	return nil
}

func readCovered(o strictjson.Object, signed bool, c *Covered) error {
	names := []string{memberFindingID, memberTenantID, memberRunID, memberCreatedAt}
	if signed {
		names = append(names, memberProjectID)
	}
	if err := lineMembers(o, names...); err != nil {
		return err
	}
	if err := readRunFields(o, &c.FindingID, &c.TenantID, &c.RunID); err != nil {
		return err
	}
	if signed {
		if err := identifierOf(o, memberProjectID, MaxProjectIDBytes, &c.ProjectID); err != nil {
			return err
		}
	}
	return timeOf(o, memberCreatedAt, &c.CreatedAt)
}

func readLiftLine(o strictjson.Object, l *LiftLine) error {
	if err := lineMembers(o, memberRunID, memberThrough, memberEnvelope); err != nil {
		return err
	}
	if err := identifierOf(o, memberRunID, MaxRunIDBytes, &l.RunID); err != nil {
		return err
	}
	var ok bool
	if l.ThroughLine, ok = integer(o[memberThrough], 1, policy.MaxSerial); !ok {
		return fmt.Errorf("%w: %s", ErrLineValue, memberThrough)
	}
	raw := o[memberEnvelope]
	if len(raw) == 0 || raw[0] != '{' {
		return fmt.Errorf("%w: %s", ErrLineValue, memberEnvelope)
	}
	env, err := policykey.ParseEnvelope(raw, MaxLiftEnvelopeBytes)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrLineValue, memberEnvelope, err)
	}
	l.Envelope = env
	return nil
}

func readRunFields(o strictjson.Object, finding, tenant, run *string) error {
	if err := identifierOf(o, memberFindingID, MaxFindingIDBytes, finding); err != nil {
		return err
	}
	if err := identifierOf(o, memberTenantID, MaxTenantIDBytes, tenant); err != nil {
		return err
	}
	return identifierOf(o, memberRunID, MaxRunIDBytes, run)
}

func identifierOf(o strictjson.Object, name string, limit int, into *string) error {
	v, ok := identifier(o[name], limit)
	if !ok {
		return fmt.Errorf("%w: %s", ErrLineValue, name)
	}
	*into = v
	return nil
}

func digestOf(o strictjson.Object, name string, into *string) error {
	v, ok := strictjson.String(o[name])
	if !ok || !canon.ValidDigest(v) {
		return fmt.Errorf("%w: %s", ErrLineValue, name)
	}
	*into = v
	return nil
}

func timeOf(o strictjson.Object, name string, into *time.Time) error {
	s, ok := strictjson.String(o[name])
	if !ok {
		return fmt.Errorf("%w: %s", ErrLineTime, name)
	}
	t, err := policy.ParseIssuedAt(s)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrLineTime, name)
	}
	*into = t
	return nil
}
