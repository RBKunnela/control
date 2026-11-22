package reaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"slices"
	"time"

	"github.com/guardana/control/internal/policy"
)

const (
	// MaxListBytes bounds a stop list, a torn last line included.
	MaxListBytes = 4 << 20
	// MaxListLines bounds the lines of a stop list, its header included.
	MaxListLines = 20000
)

// The refusals of a stop list as a whole, or of a line in its place.
const (
	ErrListTooLarge  Error = "reaction: the stop list is over its bound of bytes"
	ErrListLines     Error = "reaction: the stop list is over its bound of lines"
	ErrListRoute     Error = "reaction: the stop list's header names another route than the plane's"
	ErrListHeader    Error = "reaction: the stop list's header is not the one accepted before"
	ErrListShrunk    Error = "reaction: the stop list is shorter than the prefix accepted before"
	ErrListRewritten Error = "reaction: the stop list does not begin with the prefix accepted before"
	ErrHeaderPlace   Error = "reaction: the header is not the stop list's first line, or not its only header"
	ErrFindingAgain  Error = "reaction: a finding id is named by two lines"
	ErrCoveredRun    Error = "reaction: a covered line names another tenant or project than the route's"
	ErrStopRefused   Error = "reaction: a stop is one the route does not permit"
	ErrDatedAhead    Error = "reaction: a line's created_at is later than the plane's clock and its tolerance"
	ErrLiftOrder     Error = "reaction: a lift names a line at or after itself"
	ErrLiftAgain     Error = "reaction: a lift names a scope, subject and line an earlier lift named"
	ErrLiftUnsigned  Error = "reaction: a lift's envelope does not verify under the route's lift key"
	ErrLiftMismatch  Error = "reaction: a lift's signed run, line, list or route is not what its line and header name"
	ErrJudgeClock    Error = "reaction: the plane's clock or tolerance is not usable"
	ErrListVersion   Error = "reaction: a stop list line's version is not the one its route's lists are written in"
)

// judging is one judge's walk over a list's new lines.
type judging struct {
	// ctx holds the voucher's answers about the lines walked.
	ctx       context.Context
	route     Route
	now       time.Time
	tolerance time.Duration
	header    Header
	signer    Signer
	seen      seen
	firstNew  int
	lifted    bool
}

// Judge judges content, a stop list as read at the plane's clock now, against
// route, given the prefix accepted before (the zero Prefix at first) and a
// tolerance of one poll interval. Bytes after the last newline are a line
// being written and are left out. It refuses a route CheckStopping refuses,
// however it was read; a list over MaxListBytes or MaxListLines; one whose
// header line is not the accepted one's, by its version's refusal where that
// is not the route's lists'; one that is
// shorter than the accepted prefix or does not begin with it; a header that
// is not line 1 alone or names another route; a line ParseLine refuses; a
// finding id two lines name; a stop the route does not permit; a covered line
// naming another tenant than the route's; a created_at later than now plus
// tolerance; and a lift naming a line at or after itself, naming a run and
// line again, that does not verify under the route's lift key, or whose
// signed run, line, list id and route digest are not its line's and the
// header's. A refusal returns no List: a list is accepted whole or not.
func Judge(route Route, accepted Prefix, content []byte, now time.Time, tolerance time.Duration) (List, error) {
	complete, lines, err := judgeable(route, CheckStopping, false, content, now, tolerance)
	if err != nil {
		return List{}, err
	}
	sum, err := extends(accepted, complete)
	if err != nil {
		return List{}, otherVersion(route, complete, err)
	}
	return walk(context.Background(), route, List{}, complete, lines, sum, now, tolerance)
}

// JudgeFrom is Judge from the prefix of from, the List the judge before
// returned (the zero List at first), judging only the lines after it. It
// accepts and refuses what Judge would over the whole of content at now: the
// prefix's SHA-256 is checked again, its header held to route and its latest
// created_at to now plus tolerance, and nothing else a line accepted before
// was held to depends on the clock. Under a signed route the voucher is asked
// again about the route, the header and a lift of each signer, and a signer
// it no longer takes, or no answer, refuses the list.
func JudgeFrom(route Route, from List, content []byte, now time.Time, tolerance time.Duration) (List, error) {
	return JudgeFromContext(context.Background(), route, from, content, now, tolerance)
}

// JudgeFromContext is JudgeFrom whose questions to the voucher asked again
// are held to ctx: one ended before they are answered refuses the list as a
// voucher that cannot answer.
func JudgeFromContext(ctx context.Context, route Route, from List, content []byte, now time.Time, tolerance time.Duration) (List, error) {
	complete, lines, err := judgeable(route, CheckStopping, false, content, now, tolerance)
	if err != nil {
		return List{}, err
	}
	sum, err := extends(from.prefix, complete)
	if err != nil {
		return List{}, otherVersion(route, complete, err)
	}
	if from.seen == nil {
		if err := vouchAgain(ctx, route, nil); err != nil {
			return List{}, err
		}
		return walk(ctx, route, List{}, complete, lines, sum, now, tolerance)
	}
	if h := from.header; h.RouteID != route.id || h.RouteSerial != route.serial || h.RouteDigest != route.digest {
		return List{}, fmt.Errorf("line 1: %w", ErrListRoute)
	}
	if from.seen.latest.After(now.Add(tolerance)) {
		return List{}, fmt.Errorf("line %d: %w", from.seen.latestLine, ErrDatedAhead)
	}
	if err := vouchAgain(ctx, route, from.seen); err != nil {
		return List{}, err
	}
	if int64(len(complete)) == from.prefix.length {
		return from, nil
	}
	return walk(ctx, route, from, complete, lines, sum, now, tolerance)
}

// JudgeCarrySource is Judge from the zero Prefix with no tolerance past now,
// of the list a carry reads, against the route that list was written under,
// which it holds to CheckCarrySource in place of CheckStopping, and which may
// be a v1alpha2 route, whose list is 2.0. Nothing but a carry calls it.
func JudgeCarrySource(route Route, content []byte, now time.Time) (List, error) {
	complete, lines, err := judgeable(route, CheckCarrySource, true, content, now, 0)
	if err != nil {
		return List{}, err
	}
	sum, err := extends(Prefix{}, complete)
	if err != nil {
		return List{}, err
	}
	return walk(context.Background(), route, List{}, complete, lines, sum, now, 0)
}

// judgeable is content's complete lines and their count, refused when route,
// its rules, clock or tolerance cannot judge it or it is over a bound. A
// v1alpha2 route judges a list only as the source of a carry: anywhere else
// it is ErrRouteUpgrade. The carry's rules are passed in, so a plane's binary
// never links them.
func judgeable(route Route, rules func(Route) error, carrySource bool, content []byte, now time.Time,
	tolerance time.Duration) ([]byte, int64, error) {
	if route.digest == "" {
		return nil, 0, fmt.Errorf("%w: no route was read", ErrListRoute)
	}
	if err := rules(route); err != nil {
		return nil, 0, err
	}
	if err := formatJudges(route, carrySource); err != nil {
		return nil, 0, err
	}
	if !policy.UsableTime(now) || tolerance < 0 {
		return nil, 0, ErrJudgeClock
	}
	if n := len(content); n > MaxListBytes {
		return nil, 0, fmt.Errorf("%w: %d bytes, limit %d", ErrListTooLarge, n, MaxListBytes)
	}
	complete := content[:bytes.LastIndexByte(content, '\n')+1]
	lines := bytes.Count(complete, []byte{'\n'})
	if lines > MaxListLines {
		return nil, 0, fmt.Errorf("%w: %d lines, limit %d", ErrListLines, lines, MaxListLines)
	}
	return complete, int64(lines), nil
}

// formatJudges refuses route unless its format judges a list here: a
// v1alpha2 route only as a carry's source, and a signed route only as a
// voucher took it.
func formatJudges(route Route, carrySource bool) error {
	switch route.format {
	case FormatV1Alpha1:
		return nil
	case FormatV1Alpha2Carry:
		if !carrySource {
			return ErrRouteUpgrade
		}
		if route.voucher == nil {
			return fmt.Errorf("%w: the route was not taken through VerifySignedCarrySource", ErrNoVoucher)
		}
		return nil
	case FormatV1Alpha3:
		if route.voucher == nil {
			return fmt.Errorf("%w: the route was not taken through VerifySignedRoute", ErrNoVoucher)
		}
		return nil
	}
	return fmt.Errorf("%w: no route was read", ErrListRoute)
}

// extends refuses complete unless it begins with the accepted prefix, naming
// a changed header before a shorter or rewritten list, and returns the
// SHA-256 of complete, taken in the same pass.
func extends(accepted Prefix, complete []byte) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	h := sha256.New()
	if accepted.length > 0 {
		if err := checkPrefix(accepted, complete, h); err != nil {
			return sum, err
		}
	}
	h.Write(complete[accepted.length:])
	h.Sum(sum[:0])
	return sum, nil
}

// otherVersion is err, a refusal of complete's prefix, or, where it is a
// changed header whose version is not route's lists', a refusal of line 1
// that names both versions and what to do, so a list of another format put
// in place of the accepted one says so at every read.
func otherVersion(route Route, complete []byte, err error) error {
	if !errors.Is(err, ErrListHeader) {
		return err
	}
	l, perr := ParseLine(complete[:bytes.IndexByte(complete, '\n')])
	want, verr := listVersion(route.format)
	if perr != nil || verr != nil || l.Version == want {
		return err
	}
	return &LineError{Line: 1, Err: versionSwap{got: l.Version, want: want}}
}

// versionSwap is a list of version got where the accepted list, of version
// want, stood. Putting the accepted list back is always a way out; a carry
// is one only from the version a carry takes.
type versionSwap struct{ got, want string }

func (e versionSwap) Error() string {
	msg := fmt.Sprintf("reaction: a %s stop list in place of the accepted %s one is not served: put the accepted list back", e.got, e.want)
	if errors.Is(e.refusal(), ErrListUpgrade) {
		msg += ", or carry this one into " + e.want + " with stops init --carry"
	}
	return msg
}

func (e versionSwap) refusal() error { return versionRefusal(1, e.got, e.want) }

func (e versionSwap) Unwrap() []error { return []error{ErrListHeader, e.refusal()} }

// checkPrefix refuses complete unless it begins with accepted, and leaves h
// having hashed the prefix.
func checkPrefix(accepted Prefix, complete []byte, h hash.Hash) error {
	first := bytes.IndexByte(complete, '\n')
	if first < 0 {
		return ErrListShrunk
	}
	if sha256.Sum256(complete[:first]) != accepted.header {
		return ErrListHeader
	}
	if int64(len(complete)) < accepted.length {
		return ErrListShrunk
	}
	h.Write(complete[:accepted.length])
	if !bytes.Equal(h.Sum(nil), accepted.sum[:]) {
		return ErrListRewritten
	}
	return nil
}

// walk judges the lines of complete after from's prefix, from adds to and
// sum is complete's SHA-256, the voucher's answers held to ctx.
func walk(ctx context.Context, route Route, from List, complete []byte, lines int64, sum [sha256.Size]byte, now time.Time, tolerance time.Duration) (List, error) {
	if lines == 0 {
		return List{}, fmt.Errorf("%w: the list holds no line", ErrHeaderPlace)
	}
	j := judging{ctx: ctx, route: route, now: now, tolerance: tolerance, header: from.header, signer: from.signer, seen: from.seen.fork()}
	j.firstNew = len(j.seen.stops)
	rest := complete[from.prefix.length:]
	for n := from.usage.Lines + 1; len(rest) > 0; n++ {
		end := bytes.IndexByte(rest, '\n')
		if err := j.line(n, rest[:end]); err != nil {
			return List{}, &LineError{Line: n, Err: err}
		}
		rest = rest[end+1:]
	}
	l := List{
		header: j.header,
		signer: j.signer,
		usage:  Usage{Bytes: int64(len(complete)), Lines: lines},
		prefix: Prefix{length: int64(len(complete)), sum: sum, header: from.prefix.header},
		seen:   &j.seen,
	}
	if from.seen == nil {
		l.prefix.header = sha256.Sum256(complete[:bytes.IndexByte(complete, '\n')])
	}
	if !j.lifted {
		l.entries = append(slices.Clip(from.entries), j.seen.stops[j.firstNew:]...)
		return l, nil
	}
	for _, e := range j.seen.stops {
		if !endedBy(e, e.Target(), j.seen.through[e.Target()]) {
			l.entries = append(l.entries, e)
		}
	}
	return l, nil
}

// versionRefusal is the refusal of line n of version v under a route whose
// lists are want: a 2.0 header under a v1alpha3 route is a list to carry,
// and any other line of another version is one its list does not hold.
func versionRefusal(n int64, v, want string) error {
	switch {
	case n == 1 && v == SignedListVersion && want == SignedListVersionV3:
		return ErrListUpgrade
	case n == 1:
		return fmt.Errorf("%w: %s, and the route's lists are %s", ErrListVersion, v, want)
	}
	return fmt.Errorf("%w: a line of version %s in a list whose header is %s", ErrListVersion, v, want)
}

func (j *judging) line(n int64, raw []byte) error {
	l, err := ParseLine(raw)
	if err != nil {
		return err
	}
	if (n == 1) != (l.Kind == KindHeader) {
		return ErrHeaderPlace
	}
	want, err := listVersion(j.route.format)
	if err != nil {
		return err
	}
	if l.Version != want {
		return versionRefusal(n, l.Version, want)
	}
	switch l.Kind {
	case KindHeader:
		return j.headerLine(l.Header, l.HeaderEnvelope)
	case KindStop:
		return j.stopLine(n, l.Stop)
	case KindCovered:
		return j.coveredLine(n, l.Covered)
	default:
		return j.liftLine(n, l.Lift)
	}
}

func (j *judging) headerLine(h Header, env Envelope) error {
	if h.RouteID != j.route.id || h.RouteSerial != j.route.serial || h.RouteDigest != j.route.digest {
		return ErrListRoute
	}
	switch j.route.format {
	case FormatV1Alpha1:
	case FormatV1Alpha2Carry, FormatV1Alpha3:
		signer, err := judgeSignedHeader(j.ctx, j.route, h, env)
		if err != nil {
			return err
		}
		j.signer = signer
		j.seen.took(vouchedDoc{line: 1, kind: VouchHeader, env: env, bound: h.Signed.binding(j.route.format), signer: signer})
	default:
		return fmt.Errorf("%w: no route was read", ErrListRoute)
	}
	j.header = h
	return nil
}

func (j *judging) stopLine(n int64, s Stop) error {
	if err := j.named(n, s.FindingID, s.CreatedAt); err != nil {
		return err
	}
	if err := j.route.permitsListed(s.Claim()); err != nil {
		return fmt.Errorf("%w: %w", ErrStopRefused, err)
	}
	j.seen.stops = append(j.seen.stops, Entry{Line: n, Stop: s})
	return nil
}

// coveredLine takes a finding the list names and will not stop again, about
// any run of the route's tenant: when a finding is covered rather than a stop
// is the writer's rule, not the list's.
func (j *judging) coveredLine(n int64, c Covered) error {
	if err := j.named(n, c.FindingID, c.CreatedAt); err != nil {
		return err
	}
	if c.TenantID != j.route.tenantID || c.ProjectID != j.route.projectID {
		return ErrCoveredRun
	}
	return nil
}

// named refuses a finding id named before and a created_at past the
// tolerance, and records the finding id.
func (j *judging) named(n int64, findingID string, created time.Time) error {
	if j.seen.findings[findingID] {
		return ErrFindingAgain
	}
	if created.After(j.now.Add(j.tolerance)) {
		return ErrDatedAhead
	}
	j.seen.findings[findingID] = true
	if created.After(j.seen.latest) {
		j.seen.latest, j.seen.latestLine = created, n
	}
	return nil
}
