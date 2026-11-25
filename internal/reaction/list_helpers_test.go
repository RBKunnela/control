package reaction_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/supervise"
)

// clock0 is the plane's clock in most list tests, and poll its poll interval.
var clock0 = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

const poll = 30 * time.Second

var refundOnce struct {
	sync.Once
	digest string
	err    error
}

// refundDigest is the digest supervise gives the refund example's procedure,
// the spelling a finding record carries.
func refundDigest(t testing.TB) string {
	t.Helper()
	refundOnce.Do(func() {
		raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "refund-supervision", "refund.procedure.json"))
		if err != nil {
			refundOnce.err = err
			return
		}
		p, err := supervise.ReadProcedure(raw)
		if err != nil {
			refundOnce.err = err
			return
		}
		refundOnce.digest = p.Digest()
	})
	if refundOnce.err != nil {
		t.Fatalf("the refund procedure: %v", refundOnce.err)
	}
	return refundOnce.digest
}

// listRouteDoc is a route for the refund procedure: STEP_OUTSIDE_PROCEDURE
// stops for at most an hour, RESOURCE_OUTSIDE_RUN as long as its run.
func listRouteDoc(digest string) string {
	return withLift(`{"kind":"reaction-route/v1alpha1","route_id":"refunds","serial":3,"tenant_id":"acme","scope":"run",` +
		`"lift_public_key":"LIFTKEY","rules":[` +
		`{"procedure_id":"refund","version":"1","digest":"` + digest + `","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","expires_seconds":3600},` +
		`{"procedure_id":"refund","version":"1","digest":"` + digest + `","rule_id":"RESOURCE_OUTSIDE_RUN","rule_version":"1"}]}`)
}

// listRoute is the route stop lists are judged against.
func listRoute(t testing.TB) reaction.Route {
	t.Helper()
	r, err := reaction.ParseRoute([]byte(listRouteDoc(refundDigest(t))))
	if err != nil {
		t.Fatalf("ParseRoute: %v", err)
	}
	return r
}

// listBuilder writes a stop list line by line through the package's own
// marshalling; the tests judge what it wrote against literal expectations.
type listBuilder struct {
	t      testing.TB
	route  reaction.Route
	listID string
	lines  [][]byte
}

func newList(t testing.TB, r reaction.Route) *listBuilder {
	t.Helper()
	b := &listBuilder{t: t, route: r, listID: "list-1"}
	b.add(reaction.HeaderFor(r, b.listID).Marshal())
	return b
}

func (b *listBuilder) add(line []byte, err error) int64 {
	b.t.Helper()
	if err != nil {
		b.t.Fatalf("line %d: %v", len(b.lines)+1, err)
	}
	b.lines = append(b.lines, line)
	return int64(len(b.lines))
}

// raw appends a line as given.
func (b *listBuilder) raw(line string) { b.add([]byte(line), nil) }

func stopOf(t testing.TB, finding, run string, created time.Time, life time.Duration) reaction.Stop {
	return reaction.Stop{
		EntryID: reaction.EntryID(finding), TenantID: "acme", RunID: run, FindingID: finding,
		ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: refundDigest(t),
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: created, ExpiresAt: created.Add(life),
	}
}

// stop appends a stop of run for finding, created at created and lasting
// life, and returns its line number.
func (b *listBuilder) stop(finding, run string, created time.Time, life time.Duration) int64 {
	b.t.Helper()
	return b.add(stopOf(b.t, finding, run, created, life).Marshal())
}

func (b *listBuilder) covered(finding, run string, created time.Time) {
	b.t.Helper()
	b.add(reaction.Covered{FindingID: finding, TenantID: "acme", RunID: run, CreatedAt: created}.Marshal())
}

// lift appends a lift of run through line, signed under the route's lift
// key for this list and route.
func (b *listBuilder) lift(run string, through int64) {
	b.t.Helper()
	b.add(liftLineOf(b.t, liftKey(), b.listID, b.route.Digest(), run, through, through).Marshal())
}

// liftLineOf is a lift line whose clear fields name run and line, carrying a
// lift signed by key for list, route digest, run and signedLine.
func liftLineOf(t testing.TB, key []byte, list, routeDigest, run string, line, signedLine int64) reaction.LiftLine {
	t.Helper()
	env, err := reaction.SignLift(reaction.Lift{
		Version: "1.0", ListID: list, RouteDigest: routeDigest, RunID: run, ThroughLine: signedLine,
	}, key)
	if err != nil {
		t.Fatalf("SignLift: %v", err)
	}
	return reaction.LiftLine{RunID: run, ThroughLine: line, Envelope: env}
}

func (b *listBuilder) bytes() []byte { return b.prefixOf(len(b.lines)) }

// prefixOf is the list's first n lines.
func (b *listBuilder) prefixOf(n int) []byte {
	var out bytes.Buffer
	for _, l := range b.lines[:n] {
		out.Write(l)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// judge judges content from nothing accepted at clock0 with one poll of
// tolerance.
func judge(t testing.TB, content []byte) (reaction.List, error) {
	t.Helper()
	return reaction.Judge(listRoute(t), reaction.Prefix{}, content, clock0, poll)
}

func mustJudge(t testing.TB, content []byte) reaction.List {
	t.Helper()
	l, err := judge(t, content)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	return l
}

// judgeRefusals is every sentinel a Judge refusal can match of its own.
func judgeRefusals() []error {
	return []error{
		reaction.ErrListTooLarge, reaction.ErrListLines, reaction.ErrListRoute, reaction.ErrListHeader,
		reaction.ErrListShrunk, reaction.ErrListRewritten, reaction.ErrHeaderPlace, reaction.ErrFindingAgain,
		reaction.ErrCoveredRun, reaction.ErrStopRefused, reaction.ErrDatedAhead, reaction.ErrLiftOrder,
		reaction.ErrLiftAgain, reaction.ErrLiftUnsigned, reaction.ErrLiftMismatch, reaction.ErrJudgeClock,
		reaction.ErrLineTooLong, reaction.ErrLineJSON, reaction.ErrLineRepeat, reaction.ErrLineKind,
		reaction.ErrLineMember, reaction.ErrLineVersion, reaction.ErrLineValue, reaction.ErrLineTime,
		reaction.ErrEntryID, reaction.ErrLineCanonical,
	}
}

// entryRuns is the run and line of each entry, as "run@line".
func entryRuns(es []reaction.Entry) string {
	parts := make([]string, 0, len(es))
	for _, e := range es {
		parts = append(parts, e.RunID+"@"+strconv.FormatInt(e.Line, 10))
	}
	return strings.Join(parts, ",")
}
