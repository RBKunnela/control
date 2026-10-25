package core_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/pkg/contract"
)

// The codes the tests expect, typed from ADR-0012, the contracts page and the
// registry. The package under test spells its own; codes_test.go holds the two
// spellings to each other and to the registry.
const (
	codeUnsupportedSchema       = "UNSUPPORTED_SCHEMA"
	codeRequiredFieldAbsent     = "REQUIRED_FIELD_ABSENT"
	codeLimitExceeded           = "LIMIT_EXCEEDED"
	codeInvalidFieldValue       = "INVALID_FIELD_VALUE"
	codeMalformedInput          = "MALFORMED_INPUT"
	codeTenantMismatch          = "TENANT_MISMATCH"
	codeTenantUndetermined      = "TENANT_UNDETERMINED"
	codePolicyUnavailable       = "POLICY_UNAVAILABLE"
	codePolicyStale             = "POLICY_STALE"
	codeObligationNotUnderstood = "OBLIGATION_NOT_UNDERSTOOD"
	codeFailOpenRead            = "FAIL_OPEN_READ_CONFIGURED"
	codeRuleAllow               = "RULE_ALLOW"
	codeRuleDeny                = "RULE_DENY"
	codeApprovalRequired        = "APPROVAL_REQUIRED"
	codeObligationsAttached     = "OBLIGATIONS_ATTACHED"
	codeRuleUndetermined        = "RULE_UNDETERMINED"
	codeNoMatchingRule          = "NO_MATCHING_RULE"
	codeDelegationExpired       = "DELEGATION_EXPIRED"
	codeDelegationCycle         = "DELEGATION_CYCLE"
	codeDelegationExceeds       = "DELEGATION_EXCEEDS_PARENT"
	codePDPTimeout              = "PDP_TIMEOUT"
	codePDPUnavailable          = "PDP_UNAVAILABLE"
	codePDPAnswerRefused        = "PDP_ANSWER_REFUSED"
	codePDPDeny                 = "PDP_DENY"
	codePDPAllow                = "PDP_ALLOW"
)

// decisionPoint is the identifier a kernel under test is configured with.
const decisionPoint = "https://pdp.example/access/v1/evaluation"

const (
	verdictAllow         = controlv1.Verdict_VERDICT_ALLOW
	verdictDeny          = controlv1.Verdict_VERDICT_DENY
	verdictApproval      = controlv1.Verdict_VERDICT_REQUIRE_APPROVAL
	verdictObligations   = controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS
	verdictIndeterminate = controlv1.Verdict_VERDICT_INDETERMINATE

	effectRead     = controlv1.EffectClass_EFFECT_CLASS_READ
	effectWrite    = controlv1.EffectClass_EFFECT_CLASS_WRITE
	effectTransact = controlv1.EffectClass_EFFECT_CLASS_TRANSACT

	fresh = controlv1.PolicyFreshness_POLICY_FRESHNESS_FRESH
	stale = controlv1.PolicyFreshness_POLICY_FRESHNESS_STALE
)

// tb is what the helpers need of a test, so that a rapid.T can be one.
type tb interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// base is the clock reading the tests decide at. Its nanoseconds are not
// zero, so a time rounded or truncated anywhere shows.
func base() time.Time {
	return time.Date(2026, time.September, 11, 12, 0, 0, 123456789, time.UTC)
}

// at is the clock reading d after base.
func at(d time.Duration) time.Time { return base().Add(d) }

func timestampOf(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

// fixedClock reads the same instant every time.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// stepClock reads first, then first+step, first+2*step and so on, and counts
// its calls in *calls.
func stepClock(first time.Time, step time.Duration, calls *int) func() time.Time {
	return func() time.Time {
		t := first.Add(time.Duration(*calls) * step)
		*calls++
		return t
	}
}

// ids hands out decision-1, decision-2, ...
func ids() func() string {
	n := 0
	return func() string {
		n++
		return "decision-" + strconv.Itoa(n)
	}
}

// options is a configuration New accepts: ENFORCE, fail-open reads off, a
// ten-minute budget and two applicable obligation types.
func options() core.Options {
	return core.Options{
		Mode:       controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		MaxStale:   10 * time.Minute,
		Applicable: []string{"cap_amount", "redact_fields"},
	}
}

func kernel(t tb, opts core.Options, clock func() time.Time) *core.Kernel {
	t.Helper()
	k, err := core.New(opts, clock, ids())
	if err != nil {
		t.Fatalf("New refused options this test builds as valid: %v", err)
	}
	if k == nil {
		t.Fatalf("New returned neither a kernel nor a refusal")
	}
	return k
}

// kernelAt is a kernel whose clock reads base every time.
func kernelAt(t tb, opts core.Options) *core.Kernel {
	t.Helper()
	return kernel(t, opts, fixedClock(base()))
}

func decide(k *core.Kernel, req core.Request, snap *policy.Snapshot) core.Outcome {
	return k.Decide(context.Background(), req, snap)
}

// request wraps an in-memory envelope, so Decide validates it itself.
func request(env *controlv1.ActionEnvelope) core.Request {
	return core.Request{Envelope: env, Flow: contract.NewFlowState(false, controlv1.Sensitivity_SENSITIVITY_PUBLIC)}
}

// readEnvelope is a valid READ of an order, with the same tenant on both
// sides. Every test that changes one field starts from a fresh one.
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
		Action:        &controlv1.Action{Name: "orders.read", Effect: effectRead, Provider: "orders"},
		Resource:      &controlv1.Resource{Type: "order", Id: "ord-1", TenantId: "tenant-1", Environment: "prod"},
	}
}

// writeEnvelope is a valid WRITE, a material class, on the same order.
func writeEnvelope() *controlv1.ActionEnvelope {
	env := readEnvelope()
	env.Action = &controlv1.Action{Name: "orders.update", Effect: effectWrite, Provider: "orders"}
	return env
}

// refundEnvelope is a valid TRANSACT whose arguments hash is the hash of
// refundArgs, so step 2 passes it.
func refundEnvelope(t tb) *controlv1.ActionEnvelope {
	t.Helper()
	env := readEnvelope()
	env.Action = &controlv1.Action{Name: "refund", Effect: effectTransact, Provider: "payments"}
	env.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(t, refundArgs())}
	return env
}

func refundArgs() []byte { return []byte(`{"amount": 1250, "currency": "EUR"}`) }

func argumentsHash(t tb, args []byte) string {
	t.Helper()
	h, err := canon.ArgumentsHashV1(args)
	if err != nil {
		t.Fatalf("ArgumentsHashV1: %v", err)
	}
	return h
}

// hop is one delegation hop that expires at expires.
func hop(from, to string, scopes []string, expires time.Time) *controlv1.Delegation {
	return &controlv1.Delegation{
		From:      from,
		To:        to,
		Scopes:    scopes,
		IssuedAt:  timestamppb.New(time.Date(2026, time.September, 11, 11, 0, 0, 0, time.UTC)),
		ExpiresAt: timestamppb.New(expires),
	}
}

// Rules, as JSON, for document below. Each is a valid v1alpha1 rule.
const (
	// allowReads matches every READ.
	allowReads = `{"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}}`
	// allowWrites matches every WRITE.
	allowWrites = `{"id":"allow-writes","effect":"ALLOW","when":{"action":{"effect":["WRITE"]}}}`
	// denyArchive matches no envelope of these tests.
	denyArchive = `{"id":"deny-archive","effect":"DENY","when":{"action":{"name":["archive"]}}}`
	// denyGold reads a label the READ envelope does not carry, so it is
	// unknown on it and false on an envelope labelled tier=silver.
	denyGold = `{"id":"deny-gold","effect":"DENY","when":{"resource":{"labels":{"tier":["gold"]}}}}`
	// approveGold is denyGold's effect changed to REQUIRE_APPROVAL.
	approveGold = `{"id":"approve-gold","effect":"REQUIRE_APPROVAL","when":{"resource":{"labels":{"tier":["gold"]}}}}`
	// approveRefunds matches the refund envelope, with a cap.
	approveRefunds = `{"id":"approve-refunds","effect":"REQUIRE_APPROVAL","obligations":[{"type":"cap_amount","params":{"max":"10000"}}],"when":{"action":{"name":["refund"]}}}`
	// cappedReads allows every READ with an obligation the kernel of these
	// tests can apply.
	cappedReads = `{"id":"capped-reads","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"cap_rate","advisory":true},{"type":"redact_fields","params":{"fields":"ssn"}}],"when":{"action":{"effect":["READ"]}}}`
	// sandboxedReads allows every READ with an obligation the kernel of these
	// tests cannot apply, and one it can.
	sandboxedReads = `{"id":"sandboxed-reads","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"redact_fields","params":{"fields":"ssn"}},{"type":"require_sandbox"}],"when":{"action":{"effect":["READ"]}}}`
	// advisorySandboxReads is sandboxedReads with the sandbox advisory.
	advisorySandboxReads = `{"id":"advisory-sandbox-reads","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"require_sandbox","advisory":true}],"when":{"action":{"effect":["READ"]}}}`
	// denyAdminScope denies a delegated call holding the admin scope.
	denyAdminScope = `{"id":"deny-admin-scope","effect":"DENY","when":{"delegation":{"scopes":["admin"]}}}`
	// vetoReads denies every READ the external decision point denies.
	vetoReads = `{"id":"veto-reads","effect":"DENY","when":{"action":{"effect":["READ"]},"external":{"denies":true}}}`
	// vetoGold denies what the decision point denies on a resource labelled
	// tier=gold, and is unknown on one with no label.
	vetoGold = `{"id":"veto-gold","effect":"DENY","when":{"resource":{"labels":{"tier":["gold"]}},"external":{"denies":true}}}`
	// vetoAll denies every call the decision point denies.
	vetoAll = `{"id":"veto-all","effect":"DENY","when":{"external":{"denies":true}}}`
)

// answer is one state the enforcement point can hand in, with the code a
// decision that consulted it carries, typed out.
type answer struct {
	name       string
	external   core.External
	code       string
	unanswered bool
}

func answers() []answer {
	return []answer{
		{"not asked", core.External{}, "", true},
		{"allowed", core.ExternalAllowed(), codePDPAllow, false},
		{"denied", core.ExternalDenied(), codePDPDeny, false},
		{"denied with obligations", core.ExternalDeniedObligations(), codeObligationNotUnderstood, false},
		{"timeout", core.ExternalTimeout(), codePDPTimeout, true},
		{"unavailable", core.ExternalUnavailable(), codePDPUnavailable, true},
		{"answer refused", core.ExternalAnswerRefused(), codePDPAnswerRefused, true},
	}
}

// document is a v1alpha1 policy with these rules, bundle payments serial 7,
// and the author's budget of maxStaleSeconds.
func document(maxStaleSeconds int, rules ...string) []byte {
	return []byte(`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"payments","version":"2026-09-11.1","serial":7,"maxStaleSeconds":` +
		strconv.Itoa(maxStaleSeconds) + `},"rules":[` + strings.Join(rules, ",") + `]}`)
}

// key is the private key whose seed is 32 bytes of 0x01; pinned is the keyring
// that holds its public half under k1.
func key() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
}

func pinned() bundle.Keyring {
	return bundle.Keyring{"k1": ed25519.PublicKey(slices.Clone(key()[ed25519.SeedSize:]))}
}

// snapshotAt signs doc in memory and loads it, confirmed current at loadedAt.
func snapshotAt(t tb, doc []byte, loadedAt time.Time) *policy.Snapshot {
	t.Helper()
	b, err := policy.Sign(doc, key(), "k1")
	if err != nil {
		t.Fatalf("Sign refused a document this test builds as valid: %v", err)
	}
	snap, err := policy.Load(b, pinned(), loadedAt)
	if err != nil {
		t.Fatalf("Load refused a bundle this test builds as valid: %v", err)
	}
	return snap
}

// snapshot is snapshotAt(base) of a document with a 300 s budget.
func snapshot(t tb, rules ...string) *policy.Snapshot {
	t.Helper()
	return snapshotAt(t, document(300, rules...), base())
}

// expect is what a test asserts about an outcome. Zero fields are checked as
// written: a nil codes list means no code at all.
type expect struct {
	verdict controlv1.Verdict
	action  core.EnforcementAction
	codes   []string
}

func check(t tb, got core.Outcome, want expect) {
	t.Helper()
	if got.Decision == nil {
		t.Fatalf("Decision is nil")
	}
	if got.Decision.GetVerdict() != want.verdict {
		t.Errorf("Verdict = %s, want %s", got.Decision.GetVerdict(), want.verdict)
	}
	if got.Action != want.action {
		t.Errorf("Action = %d, want %d", got.Action, want.action)
	}
	if !slices.Equal(got.Decision.GetReasonCodes(), want.codes) {
		t.Errorf("ReasonCodes = %q, want %q", got.Decision.GetReasonCodes(), want.codes)
	}
}
