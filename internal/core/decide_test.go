package core_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/pkg/contract"
)

// failOpen is options with fail-open reads on: a refusal or a kernel DENY has
// to block a READ under it, which is what tells the input rows of the table
// from the availability rows.
func failOpen() core.Options {
	opts := options()
	opts.FailOpenRead = true
	return opts
}

// TestRefusalHandedInMapsBySentinel: each sentinel of the contract's table
// gives its code, INDETERMINATE and Block, on a READ under fail-open, and the
// policy is never consulted: its codes are absent, and the bundle digest is
// still on the decision because a snapshot exists.
func TestRefusalHandedInMapsBySentinel(t *testing.T) {
	cases := []struct {
		refusal error
		code    string
	}{
		{contract.ErrUnsupportedSchema, codeUnsupportedSchema},
		{contract.ErrUnknownField, codeUnsupportedSchema},
		{contract.ErrInvalidEnum, codeUnsupportedSchema},
		{contract.ErrMissingField, codeRequiredFieldAbsent},
		{contract.ErrTooLarge, codeLimitExceeded},
		{contract.ErrInvalidValue, codeInvalidFieldValue},
		{errors.New("decode: not this contract"), codeMalformedInput},
		{&contract.ValidationError{Field: "action.effect", Err: fmt.Errorf("wrapped: %w", contract.ErrInvalidEnum)}, codeUnsupportedSchema},
	}
	k := kernelAt(t, failOpen())
	snap := snapshot(t, allowReads)
	for _, c := range cases {
		req := request(readEnvelope())
		req.Refusal = c.refusal
		out := decide(k, req, snap)
		check(t, out, expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{c.code}})
		d := out.Decision
		if d.GetActionDigest() != "" || len(d.GetPolicyRuleIds()) != 0 || len(d.GetObligations()) != 0 {
			t.Errorf("%v: a refused request carries digest %q, rules %q, obligations %v", c.refusal, d.GetActionDigest(), d.GetPolicyRuleIds(), d.GetObligations())
		}
		if d.GetPolicyBundleDigest() != snap.Ref().GetDigest() || d.GetPolicyFreshness() != fresh || d.GetPolicyLoadedAt() == nil {
			t.Errorf("%v: a decision made with a snapshot carries digest %q, freshness %s, loaded_at %v", c.refusal, d.GetPolicyBundleDigest(), d.GetPolicyFreshness(), d.GetPolicyLoadedAt())
		}
	}
}

// TestInMemoryEnvelopeIsValidated: with no refusal handed in, Decide runs
// contract.Validate itself, on the nil envelope included.
func TestInMemoryEnvelopeIsValidated(t *testing.T) {
	k := kernelAt(t, failOpen())
	snap := snapshot(t, allowReads)
	noRequestID := readEnvelope()
	noRequestID.RequestId = ""
	undeclaredEffect := readEnvelope()
	undeclaredEffect.Action.Effect = controlv1.EffectClass(100)
	unspecifiedEffect := readEnvelope()
	unspecifiedEffect.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
	tooLarge := readEnvelope()
	tooLarge.Principal.Attributes = map[string]string{"k": strings.Repeat("v", contract.MaxEnvelopeBytes)}
	cases := []struct {
		name string
		env  *controlv1.ActionEnvelope
		code string
	}{
		{"nil envelope", nil, codeRequiredFieldAbsent},
		{"no request id", noRequestID, codeRequiredFieldAbsent},
		{"undeclared effect", undeclaredEffect, codeUnsupportedSchema},
		{"unspecified effect", unspecifiedEffect, codeRequiredFieldAbsent},
		{"over the size bound", tooLarge, codeLimitExceeded},
	}
	for _, c := range cases {
		out := decide(k, request(c.env), snap)
		check(t, out, expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{c.code}})
		if out.Decision.GetActionDigest() != "" {
			t.Errorf("%s: a refused envelope was digested", c.name)
		}
	}
	// The accepting twin: the same envelope with nothing wrong passes step 1.
	check(t, decide(k, request(readEnvelope()), snap), expect{verdict: verdictAllow, action: core.Execute, codes: []string{codeRuleAllow}})
}

// TestRequestIDIsCopiedOnlyWhenItPassesTheIdentifierRule: a refusal about the
// identifier never copies it, whether the rule it broke is a character rule or
// the length bound, and a refusal about another field still names the request.
func TestRequestIDIsCopiedOnlyWhenItPassesTheIdentifierRule(t *testing.T) {
	k := kernelAt(t, options())
	otherField := readEnvelope()
	otherField.Action.Name = ""
	tab := readEnvelope()
	tab.RequestId = "req\t1"
	long := readEnvelope()
	long.RequestId = strings.Repeat("r", contract.MaxStringBytes+1)
	atTheBound := readEnvelope()
	atTheBound.RequestId = strings.Repeat("r", contract.MaxStringBytes)
	cases := []struct {
		name string
		env  *controlv1.ActionEnvelope
		code string
		want string
	}{
		{"refused on another field", otherField, codeRequiredFieldAbsent, "req-1"},
		{"a control character", tab, codeInvalidFieldValue, ""},
		{"one byte over the bound", long, codeLimitExceeded, ""},
		{"at the bound", atTheBound, codeRuleAllow, atTheBound.RequestId},
	}
	for _, c := range cases {
		out := decide(k, request(c.env), snapshot(t, allowReads))
		if codes := out.Decision.GetReasonCodes(); len(codes) != 1 || codes[0] != c.code {
			t.Errorf("%s: codes %q, want %s alone", c.name, codes, c.code)
		}
		if got := out.Decision.GetRequestId(); got != c.want {
			t.Errorf("%s: request_id %q, want %q", c.name, got, c.want)
		}
	}
}

// deepArguments is a JSON document of n nested arrays.
func deepArguments(n int) []byte {
	return []byte(strings.Repeat("[", n) + strings.Repeat("]", n))
}

// argumentsOfSize is a JSON document of exactly n bytes.
func argumentsOfSize(t *testing.T, n int) []byte {
	t.Helper()
	const frame = `{"a":""}`
	if n < len(frame) {
		t.Fatalf("cannot build a document of %d bytes", n)
	}
	doc := []byte(`{"a":"` + strings.Repeat("x", n-len(frame)) + `"}`)
	if len(doc) != n {
		t.Fatalf("built %d bytes, want %d", len(doc), n)
	}
	return doc
}

// TestDigestStepRefusals: the two limits are LIMIT_EXCEEDED, at the input one
// past each bound; every other refusal and a hash mismatch are
// INVALID_FIELD_VALUE; each stops the decision before the policy.
func TestDigestStepRefusals(t *testing.T) {
	k := kernelAt(t, failOpen())
	snap := snapshot(t, allowReads)
	wrongHash := readEnvelope()
	wrongHash.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(t, []byte(`{"amount":1}`))}
	cases := []struct {
		name string
		env  *controlv1.ActionEnvelope
		args []byte
		code string
	}{
		{"one byte over the arguments bound", readEnvelope(), argumentsOfSize(t, canon.MaxArgumentsBytes+1), codeLimitExceeded},
		{"one level over the nesting bound", readEnvelope(), deepArguments(contract.MaxNesting + 1), codeLimitExceeded},
		{"a number past the exact range", readEnvelope(), []byte(`{"amount":9007199254740992}`), codeInvalidFieldValue},
		{"a duplicate key", readEnvelope(), []byte(`{"a":1,"a":2}`), codeInvalidFieldValue},
		{"the literal null", readEnvelope(), []byte(`null`), codeInvalidFieldValue},
		{"not JSON", readEnvelope(), []byte(`{`), codeInvalidFieldValue},
		{"a hash of other arguments", wrongHash, []byte(`{"amount":2}`), codeInvalidFieldValue},
	}
	for _, c := range cases {
		req := request(c.env)
		req.AuthorizedArgs = c.args
		out := decide(k, req, snap)
		check(t, out, expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{c.code}})
		if out.Decision.GetActionDigest() != "" {
			t.Errorf("%s: a refused request carries a digest", c.name)
		}
	}
}

// TestDigestStepAccepts: the inputs at each bound and a matching hash pass, and
// the decision carries canon's digest of the clone it decided.
func TestDigestStepAccepts(t *testing.T) {
	k := kernelAt(t, options())
	snap := snapshot(t, allowReads, allowRefunds)
	hashed := readEnvelope()
	hashed.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(t, []byte(`{"amount": 1}`))}
	refund := refundEnvelope(t)
	cases := []struct {
		name string
		env  *controlv1.ActionEnvelope
		args []byte
	}{
		{"at the arguments bound", readEnvelope(), argumentsOfSize(t, canon.MaxArgumentsBytes)},
		{"at the nesting bound", readEnvelope(), deepArguments(contract.MaxNesting)},
		{"no arguments and no hash", readEnvelope(), nil},
		{"a matching hash, spaced differently", hashed, []byte(`{"amount":1}`)},
		{"a TRANSACT with its hash", refund, refundArgs()},
	}
	for _, c := range cases {
		req := request(c.env)
		req.AuthorizedArgs = c.args
		out := decide(k, req, snap)
		if out.Decision.GetVerdict() != verdictAllow {
			t.Errorf("%s: %s %q, want ALLOW", c.name, out.Decision.GetVerdict(), out.Decision.GetReasonCodes())
		}
		want, err := canon.DigestV1(c.env, c.args)
		if err != nil {
			t.Fatalf("%s: DigestV1: %v", c.name, err)
		}
		if got := out.Decision.GetActionDigest(); got != want {
			t.Errorf("%s: action_digest %q, want %q", c.name, got, want)
		}
	}
}

// allowRefunds matches the refund envelope.
const allowRefunds = `{"id":"allow-refunds","effect":"ALLOW","when":{"action":{"name":["refund"]}}}`

// chain is a one-hop delegation from the principal to the agent of
// readEnvelope, expiring at expires, with scopes.
func chain(scopes []string, expires time.Time) []*controlv1.Delegation {
	return []*controlv1.Delegation{hop("user-1", "agent-1", scopes, expires)}
}

// TestDelegationRefusalIsABuiltInDeny: each refusal of delegation.Check is a
// DENY the policy cannot lift, on a READ under fail-open, with or without a
// bundle; the decision continues, so the policy's codes follow the kernel's.
func TestDelegationRefusalIsABuiltInDeny(t *testing.T) {
	k := kernelAt(t, failOpen())
	expired := readEnvelope()
	expired.Delegation = chain([]string{"read"}, base())
	cycle := readEnvelope()
	cycle.Delegation = []*controlv1.Delegation{
		hop("user-1", "svc", []string{"read"}, at(time.Hour)),
		hop("svc", "user-1", []string{"read"}, at(time.Hour)),
		hop("user-1", "agent-1", []string{"read"}, at(time.Hour)),
	}
	exceeds := readEnvelope()
	exceeds.Delegation = []*controlv1.Delegation{
		hop("user-1", "svc", []string{"read"}, at(time.Hour)),
		hop("svc", "agent-1", []string{"read", "admin"}, at(time.Hour)),
	}
	cases := []struct {
		name string
		env  *controlv1.ActionEnvelope
		code string
	}{
		{"expires exactly now", expired, codeDelegationExpired},
		{"a party met twice", cycle, codeDelegationCycle},
		{"one scope beyond the parent", exceeds, codeDelegationExceeds},
	}
	for _, c := range cases {
		out := decide(k, request(c.env), snapshot(t, allowReads))
		check(t, out, expect{verdict: verdictDeny, action: core.Block, codes: []string{c.code, codeRuleAllow}})
		out = decide(k, request(c.env), nil)
		check(t, out, expect{verdict: verdictDeny, action: core.Block, codes: []string{c.code, codePolicyUnavailable}})
	}
	// The accepting twin: the same chains one nanosecond from expiry, linked
	// and within their parents, pass.
	valid := readEnvelope()
	valid.Delegation = []*controlv1.Delegation{
		hop("user-1", "svc", []string{"read", "admin"}, at(time.Nanosecond)),
		hop("svc", "agent-1", []string{"read"}, at(time.Nanosecond)),
	}
	check(t, decide(k, request(valid), snapshot(t, allowReads)), expect{verdict: verdictAllow, action: core.Execute, codes: []string{codeRuleAllow}})
}

// TestUnlinkedChainIsRefusedBeforeItIsChecked: a chain of strangers, every
// hop live and within its own scopes, is one delegation.Check alone passes
// with the last hop's scopes, since none of its three codes names a hop that
// does not continue the one before. The kernel never hands it there: Validate
// refuses the link at step 1, and the decision stops with the contract's code
// and no code of the delegation step. The linked twin passes.
func TestUnlinkedChainIsRefusedBeforeItIsChecked(t *testing.T) {
	k := kernelAt(t, failOpen())
	snap := snapshot(t, allowReads)
	strangers := readEnvelope()
	strangers.Delegation = []*controlv1.Delegation{
		hop("user-1", "svc", []string{"read"}, at(time.Hour)),
		hop("other", "agent-1", []string{"read"}, at(time.Hour)),
	}
	out := decide(k, request(strangers), snap)
	check(t, out, expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{codeInvalidFieldValue}})
	for _, code := range out.Decision.GetReasonCodes() {
		if strings.HasPrefix(code, "DELEGATION_") {
			t.Errorf("the delegation step ran on a chain Validate refuses: %s", code)
		}
	}
	if out.Decision.GetActionDigest() != "" {
		t.Error("a refused envelope was digested")
	}
	linked := readEnvelope()
	linked.Delegation = []*controlv1.Delegation{
		hop("user-1", "svc", []string{"read"}, at(time.Hour)),
		hop("svc", "agent-1", []string{"read"}, at(time.Hour)),
	}
	check(t, decide(k, request(linked), snap), expect{verdict: verdictAllow, action: core.Execute, codes: []string{codeRuleAllow}})
}

// TestDelegatedScopesReachThePolicy: a one-hop chain holding the scope a DENY
// rule names, beside a broader ALLOW, is DENY. A kernel that copies Delegated
// and drops Scopes turns it into an ALLOW, which no test of the matcher alone
// can see, because such a test builds Inputs itself.
func TestDelegatedScopesReachThePolicy(t *testing.T) {
	k := kernelAt(t, options())
	snap := snapshot(t, allowReads, denyAdminScope)
	admin := readEnvelope()
	admin.Delegation = chain([]string{"admin"}, at(time.Hour))
	out := decide(k, request(admin), snap)
	check(t, out, expect{verdict: verdictDeny, action: core.Block, codes: []string{codeRuleAllow, codeRuleDeny}})
	if ids := out.Decision.GetPolicyRuleIds(); len(ids) != 2 || ids[0] != "allow-reads" || ids[1] != "deny-admin-scope" {
		t.Errorf("policy_rule_ids %q, want the two matched rules in document order", ids)
	}
	// A chain without the scope is not denied by it.
	reader := readEnvelope()
	reader.Delegation = chain([]string{"read"}, at(time.Hour))
	check(t, decide(k, request(reader), snap), expect{verdict: verdictAllow, action: core.Execute, codes: []string{codeRuleAllow}})
	// No chain at all leaves the rule unknown, which restricts (K2-SEC-04).
	check(t, decide(k, request(readEnvelope()), snap), expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{codeRuleAllow, codeRuleUndetermined}})
	// A refused chain hands the policy no scopes: the rule is unknown, and the
	// kernel's DENY stands beside it.
	expired := readEnvelope()
	expired.Delegation = chain([]string{"admin"}, base())
	out = decide(k, request(expired), snap)
	check(t, out, expect{verdict: verdictDeny, action: core.Block, codes: []string{codeDelegationExpired, codeRuleAllow, codeRuleUndetermined}})
	if ids := out.Decision.GetPolicyRuleIds(); len(ids) != 2 || ids[0] != "allow-reads" || ids[1] != "deny-admin-scope" {
		t.Errorf("policy_rule_ids %q, want the matched rule then the indeterminate one", ids)
	}
}

// allowChanges matches every DELETE and CONFIGURE: two material classes the
// contract lets through with one tenant id, beside WRITE.
const allowChanges = `{"id":"allow-changes","effect":"ALLOW","when":{"action":{"effect":["DELETE","CONFIGURE"]}}}`

// TestTenantRule: two tenants named and different, by exact comparison, is
// DENY on any class; one side named on a material class is INDETERMINATE and
// Block, on every material class the contract lets through one-sided, not on
// WRITE alone; one side on a READ, and no side on a material class the
// contract lets through, are nothing. A delegation refusal, step 3, is
// listed before the tenant's, step 4.
func TestTenantRule(t *testing.T) {
	k := kernelAt(t, failOpen())
	cross := readEnvelope()
	cross.Resource.TenantId = "tenant-2"
	folded := writeEnvelope()
	folded.Principal.TenantId, folded.Resource.TenantId = "Tenant-1", "tenant-1"
	longer := writeEnvelope()
	longer.Resource.TenantId = "tenant-1x"
	oneSideRead := readEnvelope()
	oneSideRead.Resource.TenantId = ""
	oneSideWrite := writeEnvelope()
	oneSideWrite.Principal.TenantId = ""
	noSideWrite := writeEnvelope()
	noSideWrite.Principal.TenantId, noSideWrite.Resource.TenantId = "", ""
	crossExpired := readEnvelope()
	crossExpired.Resource.TenantId = "tenant-2"
	crossExpired.Delegation = chain([]string{"read"}, base())
	snap := snapshot(t, allowReads, allowWrites, allowChanges)
	check(t, decide(k, request(cross), snap), expect{verdict: verdictDeny, action: core.Block, codes: []string{codeTenantMismatch, codeRuleAllow}})
	check(t, decide(k, request(cross), nil), expect{verdict: verdictDeny, action: core.Block, codes: []string{codeTenantMismatch, codePolicyUnavailable}})
	check(t, decide(k, request(folded), snap), expect{verdict: verdictDeny, action: core.Block, codes: []string{codeTenantMismatch, codeRuleAllow}})
	check(t, decide(k, request(longer), snap), expect{verdict: verdictDeny, action: core.Block, codes: []string{codeTenantMismatch, codeRuleAllow}})
	check(t, decide(k, request(oneSideWrite), snap), expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{codeTenantUndetermined, codeRuleAllow}})
	for _, effect := range []controlv1.EffectClass{controlv1.EffectClass_EFFECT_CLASS_DELETE, controlv1.EffectClass_EFFECT_CLASS_CONFIGURE} {
		oneSide := writeEnvelope()
		oneSide.Action.Effect = effect
		oneSide.Principal.TenantId = ""
		out := decide(k, request(oneSide), snap)
		check(t, out, expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{codeTenantUndetermined, codeRuleAllow}})
		if t.Failed() {
			t.Fatalf("one-sided tenant on %s: see above", effect)
		}
	}
	check(t, decide(k, request(oneSideRead), snap), expect{verdict: verdictAllow, action: core.Execute, codes: []string{codeRuleAllow}})
	check(t, decide(k, request(noSideWrite), snap), expect{verdict: verdictAllow, action: core.Execute, codes: []string{codeRuleAllow}})
	check(t, decide(k, request(crossExpired), snap), expect{verdict: verdictDeny, action: core.Block, codes: []string{codeDelegationExpired, codeTenantMismatch, codeRuleAllow}})
	check(t, decide(k, request(crossExpired), nil), expect{verdict: verdictDeny, action: core.Block, codes: []string{codeDelegationExpired, codeTenantMismatch, codePolicyUnavailable}})
}

// TestDecisionFields pins every field of the decision on an
// ALLOW_WITH_OBLIGATIONS made with a fresh snapshot.
func TestDecisionFields(t *testing.T) {
	calls := 0
	k := kernel(t, options(), stepClock(base(), 250*time.Microsecond, &calls))
	snap := snapshotAt(t, document(300, cappedReads), at(-time.Minute))
	env := readEnvelope()
	req := request(env)
	req.AuthorizedArgs = []byte(`{"limit": 10}`)
	d := decide(k, req, snap).Decision
	digest, err := canon.DigestV1(env, req.AuthorizedArgs)
	if err != nil {
		t.Fatalf("DigestV1: %v", err)
	}
	want := &controlv1.Decision{
		SchemaVersion:      "1.0",
		DecisionId:         "decision-1",
		RequestId:          "req-1",
		ActionDigest:       digest,
		PolicyBundleDigest: snap.Ref().GetDigest(),
		PolicyRuleIds:      []string{"capped-reads"},
		Verdict:            verdictObligations,
		ReasonCodes:        []string{codeObligationsAttached},
		Obligations: []*controlv1.Obligation{
			{Type: "cap_rate", Advisory: true},
			{Type: "redact_fields", Params: map[string]string{"fields": "ssn"}},
		},
		DecisionLatencyUs: 250,
		PdpType:           "builtin",
		EnforcementMode:   controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		PolicyFreshness:   fresh,
		PolicyLoadedAt:    timestampOf(at(-time.Minute)),
		DecidedAt:         timestampOf(base()),
	}
	if !proto.Equal(d, want) {
		t.Errorf("Decision:\n got %v\nwant %v", d, want)
	}
	if snap.Ref().GetDigest() == "" {
		t.Fatal("the snapshot has no digest, so the digest check above examined nothing")
	}
	if calls != 2 {
		t.Errorf("the clock was read %d times, want 2: once on entry and once for the latency", calls)
	}
}

// TestOneClockReadingOnEntry: with a clock that jumps an hour per reading, a
// hop that expires thirty minutes after the first reading passes, the snapshot
// confirmed at the first reading is fresh, and decided_at is the first reading:
// every comparison used it. The second reading shows in the latency alone.
func TestOneClockReadingOnEntry(t *testing.T) {
	calls := 0
	k := kernel(t, options(), stepClock(base(), time.Hour, &calls))
	env := readEnvelope()
	env.Delegation = chain([]string{"read"}, at(30*time.Minute))
	out := decide(k, request(env), snapshot(t, allowReads))
	check(t, out, expect{verdict: verdictAllow, action: core.Execute, codes: []string{codeRuleAllow}})
	d := out.Decision
	if !d.GetDecidedAt().AsTime().Equal(base()) || d.GetPolicyFreshness() != fresh {
		t.Errorf("decided_at %v, freshness %s; want the first reading and FRESH", d.GetDecidedAt().AsTime(), d.GetPolicyFreshness())
	}
	if d.GetDecisionLatencyUs() != int64(time.Hour/time.Microsecond) {
		t.Errorf("latency %d us, want one hour: the difference of the two readings", d.GetDecisionLatencyUs())
	}
	if calls != 2 {
		t.Errorf("the clock was read %d times, want 2", calls)
	}
}

// TestFreshnessBoundary: the age at the smaller budget is FRESH, one
// nanosecond over it is STALE, a negative age is STALE and stops the decision
// at the clock step, and the smaller of the author's and the operator's budget
// is the one in force, whichever it is.
func TestFreshnessBoundary(t *testing.T) {
	cases := []struct {
		name     string
		author   int
		operator time.Duration
		loadedAt time.Time
		want     controlv1.PolicyFreshness
	}{
		{"at the author's budget", 300, 10 * time.Minute, at(-300 * time.Second), fresh},
		{"one nanosecond over the author's budget", 300, 10 * time.Minute, at(-300*time.Second - time.Nanosecond), stale},
		{"at the author's smaller budget", 60, 10 * time.Minute, at(-time.Minute), fresh},
		{"one nanosecond over the author's smaller budget", 60, 10 * time.Minute, at(-time.Minute - time.Nanosecond), stale},
		{"at the operator's smaller budget", 300, time.Minute, at(-time.Minute), fresh},
		{"one nanosecond over the operator's smaller budget", 300, time.Minute, at(-time.Minute - time.Nanosecond), stale},
		{"confirmed one nanosecond after the clock reads", 300, 10 * time.Minute, at(time.Nanosecond), stale},
		{"confirmed now", 300, 10 * time.Minute, base(), fresh},
	}
	for _, c := range cases {
		opts := options()
		opts.MaxStale = c.operator
		out := decide(kernelAt(t, opts), request(readEnvelope()), snapshotAt(t, document(c.author, allowReads), c.loadedAt))
		if got := out.Decision.GetPolicyFreshness(); got != c.want {
			t.Errorf("%s: freshness %s, want %s", c.name, got, c.want)
		}
		codes := []string{codeRuleAllow}
		verdict, action := verdictAllow, core.Execute
		if c.want == stale {
			codes = []string{codePolicyStale, codeRuleAllow}
			verdict, action = verdictIndeterminate, core.Block
		}
		if c.loadedAt.After(base()) {
			codes = []string{codePolicyStale}
		}
		check(t, out, expect{verdict: verdict, action: action, codes: codes})
		if !out.Decision.GetPolicyLoadedAt().AsTime().Equal(c.loadedAt) {
			t.Errorf("%s: policy_loaded_at %v, want %v", c.name, out.Decision.GetPolicyLoadedAt().AsTime(), c.loadedAt)
		}
	}
}

// TestFreshnessOnRefusedBranches: a request refused at step 1 or 2 still
// reports the snapshot's freshness, since the field is computed on every
// branch; POLICY_STALE is not among its codes, since step 6 never ran.
func TestFreshnessOnRefusedBranches(t *testing.T) {
	past := at(-300*time.Second - time.Nanosecond)
	noRequestID := readEnvelope()
	noRequestID.RequestId = ""
	wrongHash := readEnvelope()
	wrongHash.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(t, []byte(`{"amount":1}`))}
	handedIn := request(readEnvelope())
	handedIn.Refusal = contract.ErrTooLarge
	hashed := request(wrongHash)
	hashed.AuthorizedArgs = []byte(`{"amount":2}`)
	refusals := []struct {
		name string
		req  core.Request
		code string
	}{
		{"a refusal handed in", handedIn, codeLimitExceeded},
		{"Validate's refusal", request(noRequestID), codeRequiredFieldAbsent},
		{"a hash of other arguments", hashed, codeInvalidFieldValue},
	}
	snapshots := []struct {
		name string
		snap *policy.Snapshot
		want controlv1.PolicyFreshness
	}{
		{"a stale snapshot", snapshotAt(t, document(300, allowReads), past), stale},
		{"a fresh snapshot", snapshotAt(t, document(300, allowReads), base()), fresh},
		{"no snapshot", nil, stale},
	}
	k := kernelAt(t, failOpen())
	for _, r := range refusals {
		for _, s := range snapshots {
			out := decide(k, r.req, s.snap)
			check(t, out, expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{r.code}})
			if got := out.Decision.GetPolicyFreshness(); got != s.want {
				t.Errorf("%s, %s: freshness %s, want %s", r.name, s.name, got, s.want)
			}
		}
	}
}

// TestNoSnapshotBranch: no snapshot is POLICY_UNAVAILABLE, STALE, no digest and
// no loaded_at, and the kernel's own steps have run before it.
func TestNoSnapshotBranch(t *testing.T) {
	out := decide(kernelAt(t, options()), request(writeEnvelope()), nil)
	check(t, out, expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{codePolicyUnavailable}})
	d := out.Decision
	if d.GetPolicyBundleDigest() != "" || d.GetPolicyLoadedAt() != nil || d.GetPolicyFreshness() != stale {
		t.Errorf("no snapshot: digest %q, loaded_at %v, freshness %s", d.GetPolicyBundleDigest(), d.GetPolicyLoadedAt(), d.GetPolicyFreshness())
	}
	if d.GetActionDigest() == "" {
		t.Error("no snapshot: the action digest is absent, and step 2 ran before step 5")
	}
}

// TestDecisionsShareNothing: two decisions alias none of each other's slices,
// and neither aliases the snapshot: writing into the first changes nothing in
// the second.
func TestDecisionsShareNothing(t *testing.T) {
	k := kernelAt(t, options())
	snap := snapshot(t, cappedReads)
	first := decide(k, request(readEnvelope()), snap).Decision
	reference := proto.CloneOf(first)
	first.ReasonCodes[0] = "RULE_ALLOW"
	first.PolicyRuleIds[0] = "other"
	first.Obligations[0].Advisory = false
	first.Obligations[1].Params["fields"] = "other"
	first.Obligations[1].Type = "require_sandbox"
	second := decide(k, request(readEnvelope()), snap).Decision
	reference.DecisionId, second.DecisionId = "", ""
	if !proto.Equal(second, reference) {
		t.Errorf("the second decision changed with the first:\n got %v\nwant %v", second, reference)
	}
}

// TestDecideClonesTheEnvelope: the decision's request id and digest are of the
// envelope as handed in, and a write to the caller's envelope after the call
// is not in the decision.
func TestDecideClonesTheEnvelope(t *testing.T) {
	k := kernelAt(t, options())
	env := readEnvelope()
	out := decide(k, request(env), snapshot(t, allowReads))
	env.RequestId = "req-2"
	env.Action.Effect = effectWrite
	if out.Decision.GetRequestId() != "req-1" {
		t.Errorf("request_id %q changed with the caller's envelope", out.Decision.GetRequestId())
	}
	want, err := canon.DigestV1(readEnvelope(), nil)
	if err != nil {
		t.Fatalf("DigestV1: %v", err)
	}
	if out.Decision.GetActionDigest() != want {
		t.Errorf("action_digest %q is not the digest of the envelope as handed in", out.Decision.GetActionDigest())
	}
}

// TestDecideIsSafeForConcurrentUse runs one kernel and one snapshot from many
// goroutines under -race and holds every decision to the one made alone.
func TestDecideIsSafeForConcurrentUse(t *testing.T) {
	k, err := core.New(options(), fixedClock(base()), func() string { return "decision" })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	snap := snapshot(t, cappedReads, denyArchive)
	reference := decide(k, request(readEnvelope()), snap).Decision
	const workers, rounds = 8, 50
	results := make(chan *controlv1.Decision, workers*rounds)
	for w := 0; w < workers; w++ {
		go func() {
			for i := 0; i < rounds; i++ {
				results <- decide(k, request(readEnvelope()), snap).Decision
			}
		}()
	}
	for i := 0; i < workers*rounds; i++ {
		if d := <-results; !proto.Equal(d, reference) {
			t.Fatalf("a concurrent decision differs:\n got %v\nwant %v", d, reference)
		}
	}
}
