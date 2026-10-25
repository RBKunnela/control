package gateway_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
)

// The codes the tests expect, typed from the registry page. The package under
// test spells its own; codes_test.go holds both spellings to the registry.
const (
	codePolicyUnavailable       = "POLICY_UNAVAILABLE"
	codeInvalidFieldValue       = "INVALID_FIELD_VALUE"
	codeRuleAllow               = "RULE_ALLOW"
	codeRuleDeny                = "RULE_DENY"
	codeApprovalRequired        = "APPROVAL_REQUIRED"
	codeObligationsAttached     = "OBLIGATIONS_ATTACHED"
	codeObligationNotUnderstood = "OBLIGATION_NOT_UNDERSTOOD"
	codeFailOpenRead            = "FAIL_OPEN_READ_CONFIGURED"
	codeLockdown                = "LOCKDOWN"
	codeEvidenceUnavailable     = "EVIDENCE_UNAVAILABLE"
	codeExecutedArgsMismatch    = "EXECUTED_ARGS_MISMATCH"
	codeApprovalExpired         = "APPROVAL_EXPIRED"
	codeApprovalRejected        = "APPROVAL_REJECTED"
	codeApprovalAlreadyUsed     = "APPROVAL_ALREADY_USED"
	codeApprovalNotResumed      = "APPROVAL_NOT_RESUMED"
	codeApprovalStateUnknown    = "APPROVAL_STATE_UNKNOWN"
	codeDelegationExpired       = "DELEGATION_EXPIRED"
	codeActionUnclassified      = "ACTION_UNCLASSIFIED"
	codeApprovalDigestMismatch  = "APPROVAL_DIGEST_MISMATCH"
	codeApprovalBundleMismatch  = "APPROVAL_BUNDLE_MISMATCH"
	codeMalformedInput          = "MALFORMED_INPUT"
	codePolicyStale             = "POLICY_STALE"
)

const (
	modeObserve  = controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	modeApprove  = controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE
	modeEnforce  = controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE
	modeLockdown = controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN

	verdictAllow         = controlv1.Verdict_VERDICT_ALLOW
	verdictDeny          = controlv1.Verdict_VERDICT_DENY
	verdictApproval      = controlv1.Verdict_VERDICT_REQUIRE_APPROVAL
	verdictObligations   = controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS
	verdictIndeterminate = controlv1.Verdict_VERDICT_INDETERMINATE

	kindProposed          = controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED
	kindDecided           = controlv1.EventKind_EVENT_KIND_POLICY_DECIDED
	kindApprovalRequested = controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED
	kindApprovalDecided   = controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED
	kindApprovalExpired   = controlv1.EventKind_EVENT_KIND_APPROVAL_EXPIRED
	kindStarted           = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
	kindCompleted         = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
	kindFailed            = controlv1.EventKind_EVENT_KIND_ACTION_FAILED
	kindBlocked           = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED

	approved = controlv1.ApprovalState_APPROVAL_STATE_APPROVED
	rejected = controlv1.ApprovalState_APPROVAL_STATE_REJECTED
)

type fakeAdapter struct {
	name string
	caps gateway.Capabilities
}

func (a fakeAdapter) Name() string                       { return a.name }
func (a fakeAdapter) Capabilities() gateway.Capabilities { return a.caps }

var enforcing = gateway.Capabilities{ObserveRequest: true, ObserveResult: true, Enforcement: gateway.EnforcementInline}

// snapshotSource serves one snapshot and counts how often it was asked.
type snapshotSource struct {
	mu    sync.Mutex
	snap  *policy.Snapshot
	calls atomic.Int64
}

func (s *snapshotSource) Current() *policy.Snapshot {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap
}

// set installs snap, as a holder publishes a renewal or a newer bundle.
func (s *snapshotSource) set(snap *policy.Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap = snap
}

// pauseSource serves a settable pause snapshot and counts how often it was
// asked; a harness starts with the disabled one.
type pauseSource struct {
	mu    sync.Mutex
	snap  pause.Snapshot
	calls atomic.Int64
}

func (s *pauseSource) Current() pause.Snapshot {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap
}

func (s *pauseSource) set(snap pause.Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap = snap
}

// clock is a settable clock, so a test moves time past an expiry.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// failingSink refuses the kinds in refuse and stores the rest; recording
// every append it was asked for, refused or not. before runs outside the lock
// before the append of the kind it names, so a test can act while one append
// is in flight.
type failingSink struct {
	mu      sync.Mutex
	refuse  map[controlv1.EventKind]bool
	before  map[controlv1.EventKind]func()
	failAll bool
	asked   []controlv1.EventKind
	kept    evidence.MemorySink
}

var errSink = errors.New("sink: refused")

func (s *failingSink) Append(ctx context.Context, e *controlv1.Event) error {
	s.mu.Lock()
	hook := s.before[e.GetKind()]
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	s.mu.Lock()
	s.asked = append(s.asked, e.GetKind())
	refused := s.failAll || s.refuse[e.GetKind()]
	s.mu.Unlock()
	if refused {
		return errSink
	}
	return s.kept.Append(ctx, e)
}

// hook registers what runs before the next append of kind.
func (s *failingSink) hook(kind controlv1.EventKind, run func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.before == nil {
		s.before = map[controlv1.EventKind]func(){}
	}
	s.before[kind] = run
}

// refuseKind refuses kind from now on, while another append may be in flight.
func (s *failingSink) refuseKind(kind controlv1.EventKind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse[kind] = true
}

func (s *failingSink) askedFor() []controlv1.EventKind {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.asked)
}

func (s *failingSink) fail(all bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAll = all
}

// base is the clock reading the tests admit at.
func base() time.Time {
	return time.Date(2026, time.September, 11, 12, 0, 0, 123456789, time.UTC)
}

// harness is a pipeline with every collaborator reachable from the test.
type harness struct {
	p      *gateway.Pipeline
	sink   *failingSink
	store  *gateway.MemoryApprovals
	policy *snapshotSource
	pause  *pauseSource
	clock  *clock
	ids    *atomic.Int64
	// run is the opened run admit sends every call under; nil sends none.
	run *gateway.OpenedRun
}

func newIDs(n *atomic.Int64) func() string {
	return func() string { return "id-" + strconv.FormatInt(n.Add(1), 10) }
}

// validConfig is a configuration New accepts: ENFORCE, no snapshot yet, a
// memory sink and store, a fixed clock and numbered ids.
func validConfig(t *testing.T) gateway.Config {
	t.Helper()
	var n atomic.Int64
	return gateway.Config{
		Mode:          modeEnforce,
		Adapter:       fakeAdapter{name: "fake", caps: enforcing},
		KernelOptions: core.Options{MaxStale: time.Minute},
		Policy:        &snapshotSource{},
		Pause:         gateway.PauseDisabled(),
		Stops:         gateway.StopsDisabled(),
		Sink:          &evidence.MemorySink{},
		Approvals:     &gateway.MemoryApprovals{},
		Clock:         func() time.Time { return base() },
		NewID:         newIDs(&n),
		ApprovalTTL:   10 * time.Minute,
		RetryAfter:    5 * time.Second,
		MaxHeld:       16,
		MaxOpen:       16,
		MaxRuns:       16,
	}
}

// build makes a harness in mode over snap; mut edits the config first.
func build(t *testing.T, mode controlv1.EnforcementMode, snap *policy.Snapshot, mut ...func(*gateway.Config)) *harness {
	t.Helper()
	h := &harness{
		sink:   &failingSink{refuse: map[controlv1.EventKind]bool{}},
		store:  &gateway.MemoryApprovals{},
		policy: &snapshotSource{snap: snap},
		pause:  &pauseSource{snap: pause.DisabledSnapshot()},
		clock:  &clock{now: base()},
		ids:    &atomic.Int64{},
	}
	caps := enforcing
	caps.Obligations = []string{"cap_rate"}
	cfg := gateway.Config{
		Mode:          mode,
		Adapter:       fakeAdapter{name: "fake", caps: caps},
		KernelOptions: core.Options{MaxStale: 10 * time.Minute},
		Policy:        h.policy,
		Pause:         h.pause,
		Stops:         gateway.StopsDisabled(),
		Sink:          h.sink,
		Approvals:     h.store,
		Clock:         h.clock.read,
		NewID:         newIDs(h.ids),
		ApprovalTTL:   10 * time.Minute,
		RetryAfter:    5 * time.Second,
		MaxHeld:       16,
		MaxOpen:       16,
		MaxRuns:       16,
	}
	for _, m := range mut {
		m(&cfg)
	}
	p, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("New refused a configuration this test builds as valid: %v", err)
	}
	h.p = p
	return h
}

func (h *harness) admit(env *controlv1.ActionEnvelope, args []byte) gateway.Disposition {
	a := admission(env, args)
	a.Run = h.run
	return h.p.Admit(context.Background(), a)
}

func admission(env *controlv1.ActionEnvelope, args []byte) gateway.Admission {
	return gateway.Admission{Envelope: env, Arguments: args}
}

func (h *harness) events() []*controlv1.Event { return h.sink.kept.Events() }

// kinds lists the kinds the sink kept, in order.
func (h *harness) kinds() []controlv1.EventKind {
	events := h.events()
	out := make([]controlv1.EventKind, len(events))
	for i, e := range events {
		out[i] = e.GetKind()
	}
	return out
}

// trailOf returns the kept events of one request, in order.
func (h *harness) trailOf(requestID string) []*controlv1.Event {
	var out []*controlv1.Event
	for _, e := range h.events() {
		if e.GetRequestId() == requestID {
			out = append(out, e)
		}
	}
	return out
}

func kindsOf(events []*controlv1.Event) []controlv1.EventKind {
	out := make([]controlv1.EventKind, len(events))
	for i, e := range events {
		out[i] = e.GetKind()
	}
	return out
}

func readEnvelope() *controlv1.ActionEnvelope {
	return &controlv1.ActionEnvelope{
		SchemaVersion: "1.0",
		RequestId:     "req-1",
		ProjectId:     "proj-1",
		TenantId:      "tenant-1",
		Environment:   "prod",
		OccurredAt:    timestamppb.New(time.Date(2026, time.September, 11, 11, 59, 0, 0, time.UTC)),
		Principal:     &controlv1.Principal{Id: "user-1", TenantId: "tenant-1"},
		Agent:         &controlv1.Agent{Id: "agent-1"},
		Action:        &controlv1.Action{Name: "orders.read", Effect: controlv1.EffectClass_EFFECT_CLASS_READ, Provider: "orders"},
		Resource:      &controlv1.Resource{Type: "order", Id: "ord-1", TenantId: "tenant-1", Environment: "prod"},
		Context:       &controlv1.RunContext{RunId: "run-1", SessionId: "sess-1"},
	}
}

func writeEnvelope() *controlv1.ActionEnvelope {
	env := readEnvelope()
	env.Action = &controlv1.Action{Name: "orders.update", Effect: controlv1.EffectClass_EFFECT_CLASS_WRITE, Provider: "orders"}
	return env
}

// refundEnvelope is a TRANSACT whose arguments hash is the hash of args.
func refundEnvelope(t *testing.T, args []byte) *controlv1.ActionEnvelope {
	t.Helper()
	env := readEnvelope()
	env.Action = &controlv1.Action{Name: "refund", Effect: controlv1.EffectClass_EFFECT_CLASS_TRANSACT, Provider: "payments"}
	env.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(t, args)}
	return env
}

func refundArgs() []byte { return []byte(`{"amount": 1250, "currency": "EUR", "ssn": "x"}`) }

func argumentsHash(t *testing.T, args []byte) string {
	t.Helper()
	h, err := canon.ArgumentsHashV1(args)
	if err != nil {
		t.Fatalf("ArgumentsHashV1: %v", err)
	}
	return h
}

// Rules, as JSON, for document below.
const (
	allowReads     = `{"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}}`
	allowWrites    = `{"id":"allow-writes","effect":"ALLOW","when":{"action":{"effect":["WRITE"]}}}`
	denyWrites     = `{"id":"deny-writes","effect":"DENY","when":{"action":{"effect":["WRITE"]}}}`
	approveRefunds = `{"id":"approve-refunds","effect":"REQUIRE_APPROVAL","obligations":[{"type":"cap_amount","params":{"max":"1000"}}],"when":{"action":{"name":["refund"]}}}`
	// cappedRefunds rewrites the arguments and leaves one advisory
	// obligation for the adapter.
	cappedRefunds = `{"id":"capped-refunds","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"cap_rate","advisory":true},{"type":"redact_fields","params":{"fields":"ssn"}},{"type":"cap_amount","params":{"max":"1000"}}],"when":{"action":{"name":["refund"]}}}`
	// unappliableRefunds asks to cap a member the arguments do not hold.
	unappliableRefunds = `{"id":"unappliable-refunds","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"cap_amount","params":{"max":"1000","field":"total"}}],"when":{"action":{"name":["refund"]}}}`
)

func document(rules ...string) []byte {
	return []byte(`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"payments","version":"2026-09-11.1","serial":7,"maxStaleSeconds":600},"rules":[` +
		strings.Join(rules, ",") + `]}`)
}

func key() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
}

func pinned() bundle.Keyring {
	return bundle.Keyring{"k1": ed25519.PublicKey(slices.Clone(key()[ed25519.SeedSize:]))}
}

// snapshot signs a document of rules in memory and loads it at base.
func snapshot(t *testing.T, rules ...string) *policy.Snapshot {
	t.Helper()
	return snapshotAt(t, base(), rules...)
}

// snapshotAt signs a document of rules in memory and loads it at at.
func snapshotAt(t *testing.T, at time.Time, rules ...string) *policy.Snapshot {
	t.Helper()
	b, err := policy.Sign(document(rules...), key(), "k1")
	if err != nil {
		t.Fatalf("Sign refused a document this test builds as valid: %v", err)
	}
	snap, err := policy.Load(b, pinned(), at)
	if err != nil {
		t.Fatalf("Load refused a bundle this test builds as valid: %v", err)
	}
	return snap
}

// expectBlock asserts a block with verdict and the one code, from pdp.
func expectBlock(t *testing.T, d gateway.Disposition, verdict controlv1.Verdict, code, pdp string) {
	t.Helper()
	if d.Action != core.Block {
		t.Errorf("Action = %d, want Block", d.Action)
	}
	if d.Decision.GetVerdict() != verdict {
		t.Errorf("Verdict = %s, want %s", d.Decision.GetVerdict(), verdict)
	}
	if !slices.Contains(d.Decision.GetReasonCodes(), code) {
		t.Errorf("ReasonCodes = %v, want %s among them", d.Decision.GetReasonCodes(), code)
	}
	if d.Decision.GetPdpType() != pdp {
		t.Errorf("PdpType = %q, want %q", d.Decision.GetPdpType(), pdp)
	}
	if d.AuthorizedArgs != nil || d.AuthorizedDigest != "" || d.Pending != nil || d.Obligations != nil {
		t.Errorf("a block handed out arguments, a pending state or obligations: %+v", d)
	}
}

func expectKinds(t *testing.T, got, want []controlv1.EventKind) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("kinds = %v, want %v", got, want)
	}
}

// pendingID is the approval a pending disposition names, or "" when it names
// none.
func pendingID(d gateway.Disposition) string {
	if d.Pending == nil {
		return ""
	}
	return d.Pending.ApprovalID
}

func result(status controlv1.ResultStatus) *controlv1.ActionResult {
	return &controlv1.ActionResult{SchemaVersion: "1.0", Status: status}
}
