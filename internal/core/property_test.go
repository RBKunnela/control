package core_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"pgregory.net/rapid"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/pkg/contract"
)

// The determinism property ADR-0012 asks for: the same request against a
// separately loaded snapshot of the same bundle, loaded at the same instant,
// decides the same, byte for byte, after a shuffled batch of other requests
// has run through both. Each check draws a set of rules, one load time and a
// batch of batchSize requests, each with its own kernel configuration; the
// batch is decided in order against the first snapshots and in a drawn
// permutation against the second. With rapid's default of 100 checks that is
// 10 000 cases, which TestDecideIsDeterministic holds the run to.
//
// The generator reaches every branch of Decide, and the run fails when one
// was never drawn: a property over a generator that stopped reaching the
// digest step would still pass on equality alone. What a check draws once
// would miss a branch by chance in some run, so the cases take turns at no
// bundle, the drawn rules and the rest of the pool.

const batchSize = 100

// coverage counts the branches the generator reached, by label.
type coverage map[string]int

func (c coverage) mark(label string) { c[label]++ }

// branches is every label the generator has to reach in a run.
func branches() []string {
	labels := []string{
		"bundle:none", "bundle:present", "stale", "fresh", "fail-open:on", "fail-open:off",
		"applicable:none", "applicable:some",
		"envelope:nil", "envelope:valid", "envelope:tab-in-request-id", "envelope:long-request-id",
		"envelope:schema-2.0", "envelope:undeclared-trust-zone", "envelope:no-resource",
		"tenant:same", "tenant:cross", "tenant:principal-only", "tenant:resource-only", "tenant:none",
		"delegation:none", "delegation:valid", "delegation:expired", "delegation:cycle", "delegation:exceeds",
		"arguments:none", "arguments:matching", "arguments:mismatch", "arguments:float", "arguments:deep",
		"labels:none", "labels:gold", "labels:silver", "flow:untrusted", "flow:trusted",
		"data:none", "data:confidential", "destination:none", "destination:internal", "destination:external",
		"decision-point:none", "decision-point:set", "needs-external", "consulted",
		"needed:denied", "needed:denied with obligations",
	}
	for _, a := range answers() {
		labels = append(labels, "external:"+a.name)
	}
	for _, r := range rulePool() {
		labels = append(labels, "rule:"+r.id)
	}
	for _, e := range effects() {
		labels = append(labels, "effect:"+e.String())
	}
	for _, s := range sentinels() {
		labels = append(labels, "refusal:"+s.name)
	}
	return labels
}

// poolRule is one rule the document generator can draw, by id.
type poolRule struct {
	id   string
	json string
}

func rulePool() []poolRule {
	return []poolRule{
		{"allow-reads", allowReads},
		{"allow-writes", allowWrites},
		{"deny-archive", denyArchive},
		{"deny-gold", denyGold},
		{"approve-gold", approveGold},
		{"approve-refunds", approveRefunds},
		{"capped-reads", cappedReads},
		{"sandboxed-reads", sandboxedReads},
		{"advisory-sandbox-reads", advisorySandboxReads},
		{"deny-admin-scope", denyAdminScope},
		{"allow-transactions", `{"id":"allow-transactions","effect":"ALLOW","when":{"action":{"effect":["TRANSACT","EXECUTE","DELETE"]}}}`},
		{"deny-confidential", `{"id":"deny-confidential","effect":"DENY","when":{"data":{"sensitivityAtLeast":"CONFIDENTIAL"}}}`},
		{"deny-toxic", `{"id":"deny-toxic","effect":"DENY","when":{"flow":{"toxicAtLeast":"RESTRICTED"}}}`},
		{"approve-external", `{"id":"approve-external","effect":"REQUIRE_APPROVAL","when":{"destination":{"trustZone":["UNTRUSTED_EXTERNAL"]}}}`},
		{"veto-reads", vetoReads},
		{"veto-gold", vetoGold},
		{"veto-all", vetoAll},
	}
}

// effects is every declared class, the zero value and a number this build
// does not declare, with the three the rules read most often repeated so a
// batch reaches the policy step more than it is refused.
func effects() []controlv1.EffectClass {
	return []controlv1.EffectClass{
		effectRead, effectRead, effectRead, effectWrite, effectWrite, effectTransact, effectTransact,
		controlv1.EffectClass_EFFECT_CLASS_DELETE, controlv1.EffectClass_EFFECT_CLASS_EXECUTE,
		controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE, controlv1.EffectClass_EFFECT_CLASS_IDENTITY_OR_ACCESS,
		controlv1.EffectClass_EFFECT_CLASS_CONFIGURE, controlv1.EffectClass_EFFECT_CLASS_SPAWN_OR_DELEGATE,
		controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED, controlv1.EffectClass(100),
	}
}

// sentinel is one refusal a decoder can hand in, with the code the contract
// page maps it to.
type sentinel struct {
	name string
	err  error
	code string
}

func sentinels() []sentinel {
	return []sentinel{
		{"unsupported-schema", contract.ErrUnsupportedSchema, codeUnsupportedSchema},
		{"unknown-field", contract.ErrUnknownField, codeUnsupportedSchema},
		{"invalid-enum", contract.ErrInvalidEnum, codeUnsupportedSchema},
		{"missing-field", contract.ErrMissingField, codeRequiredFieldAbsent},
		{"too-large", contract.ErrTooLarge, codeLimitExceeded},
		{"invalid-value", contract.ErrInvalidValue, codeInvalidFieldValue},
		{"not-this-contract", errNotThisContract, codeMalformedInput},
	}
}

// errNotThisContract is a decoder's refusal that names no sentinel.
const errNotThisContract = core.Error("decode: not this contract")

// scenario is one check: a kernel configuration per case is drawn later, so
// the snapshot's age meets more than one operator budget. Case i is decided
// against bundles[i%len(bundles)].
type scenario struct {
	now      time.Time
	bundles  []drawnBundle
	maxStale int
	loadedAt time.Time
	batch    []drawnCase
}

// drawnBundle is one document of a check and its rules; doc is nil for no
// bundle.
type drawnBundle struct {
	doc   []byte
	rules []poolRule
}

func (s scenario) bundleOf(i int) int { return i % len(s.bundles) }

// markBundle counts a case decided against b.
func markBundle(cov coverage, b drawnBundle) {
	if b.doc == nil {
		cov.mark("bundle:none")
		return
	}
	cov.mark("bundle:present")
	for _, r := range b.rules {
		cov.mark("rule:" + r.id)
	}
}

// drawnCase is one request with the options it is decided under.
type drawnCase struct {
	req  core.Request
	opts core.Options
	// read is whether the envelope carries the READ class, which is what the
	// fail-closed table may open; nil and refused envelopes are not reads.
	read bool
	// answer is the external answer req carries.
	answer answer
}

func drawScenario(rt *rapid.T, cov coverage) scenario {
	s := scenario{now: base()}
	drawn := rapid.SliceOfNDistinct(rapid.SampledFrom(rulePool()), 2, 8, func(r poolRule) string { return r.id }).Draw(rt, "rules")
	rest := slices.DeleteFunc(rulePool(), func(r poolRule) bool {
		return slices.ContainsFunc(drawn, func(d poolRule) bool { return d.id == r.id })
	})
	s.maxStale = rapid.SampledFrom([]int{1, 300, 900}).Draw(rt, "bundleMaxStale")
	s.bundles = []drawnBundle{{}, {doc: documentOf(s.maxStale, drawn), rules: drawn}, {doc: documentOf(s.maxStale, rest), rules: rest}}
	age := rapid.SampledFrom([]time.Duration{-time.Second, 0, time.Second, 299 * time.Second, 300 * time.Second, 301 * time.Second, time.Hour}).Draw(rt, "age")
	s.loadedAt = s.now.Add(-age)
	s.batch = make([]drawnCase, batchSize)
	for i := range s.batch {
		s.batch[i] = drawCase(rt, cov)
	}
	return s
}

// documentOf is the document of these rules, in this order.
func documentOf(maxStale int, rules []poolRule) []byte {
	texts := make([]string, 0, len(rules))
	for _, r := range rules {
		texts = append(texts, r.json)
	}
	return document(maxStale, texts...)
}

func drawOptions(rt *rapid.T, cov coverage) core.Options {
	opts := core.Options{
		Mode:          controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		FailOpenRead:  rapid.Bool().Draw(rt, "failOpenRead"),
		MaxStale:      rapid.SampledFrom([]time.Duration{time.Second, 300 * time.Second, 600 * time.Second}).Draw(rt, "maxStale"),
		Applicable:    rapid.SampledFrom([][]string{nil, {"redact_fields"}, {"cap_amount", "redact_fields"}}).Draw(rt, "applicable"),
		DecisionPoint: rapid.SampledFrom([]string{"", decisionPoint}).Draw(rt, "decisionPoint"),
	}
	cov.mark("fail-open:" + onOff(opts.FailOpenRead))
	cov.mark(map[bool]string{false: "decision-point:none", true: "decision-point:set"}[opts.DecisionPoint != ""])
	if len(opts.Applicable) == 0 {
		cov.mark("applicable:none")
	} else {
		cov.mark("applicable:some")
	}
	return opts
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func drawCase(rt *rapid.T, cov coverage) drawnCase {
	opts := drawOptions(rt, cov)
	env := readEnvelope()
	env.Action.Effect = rapid.SampledFrom(effects()).Draw(rt, "effect")
	cov.mark("effect:" + env.Action.Effect.String())
	env.Action.Name, env.Action.Provider = drawAction(rt)
	drawTenants(rt, cov, env)
	drawDelegation(rt, cov, env)
	drawLabelsDataDestination(rt, cov, env)
	args := drawArguments(rt, cov, env)
	a := rapid.SampledFrom(answers()).Draw(rt, "external")
	cov.mark("external:" + a.name)
	req := core.Request{AuthorizedArgs: args, Flow: drawFlow(rt, cov), External: a.external}
	req.Envelope, req.Refusal = drawFault(rt, cov, env)
	return drawnCase{req: req, opts: opts, read: req.Envelope != nil && req.Refusal == nil && env.Action.Effect == effectRead, answer: a}
}

func drawAction(rt *rapid.T) (name, provider string) {
	return rapid.SampledFrom([]string{"orders.read", "refund", "archive"}).Draw(rt, "actionName"),
		rapid.SampledFrom([]string{"orders", "payments"}).Draw(rt, "provider")
}

func drawTenants(rt *rapid.T, cov coverage, env *controlv1.ActionEnvelope) {
	switch rapid.SampledFrom([]string{"same", "same", "cross", "principal-only", "resource-only", "none"}).Draw(rt, "tenants") {
	case "same":
		cov.mark("tenant:same")
	case "cross":
		env.Resource.TenantId = "tenant-2"
		cov.mark("tenant:cross")
	case "principal-only":
		env.Resource.TenantId = ""
		cov.mark("tenant:principal-only")
	case "resource-only":
		env.Principal.TenantId = ""
		cov.mark("tenant:resource-only")
	case "none":
		env.Principal.TenantId, env.Resource.TenantId = "", ""
		cov.mark("tenant:none")
	}
}

func drawDelegation(rt *rapid.T, cov coverage, env *controlv1.ActionEnvelope) {
	scopes := rapid.SampledFrom([][]string{{"read"}, {"admin"}, {"read", "admin"}, {}}).Draw(rt, "scopes")
	switch rapid.SampledFrom([]string{"none", "none", "valid", "valid", "expired", "cycle", "exceeds"}).Draw(rt, "delegation") {
	case "none":
		cov.mark("delegation:none")
	case "valid":
		env.Delegation = []*controlv1.Delegation{hop("user-1", "svc", []string{"read", "admin"}, at(time.Hour)), hop("svc", "agent-1", scopes, at(time.Hour))}
		cov.mark("delegation:valid")
	case "expired":
		env.Delegation = chain(scopes, base())
		cov.mark("delegation:expired")
	case "cycle":
		env.Delegation = []*controlv1.Delegation{hop("user-1", "svc", scopes, at(time.Hour)), hop("svc", "user-1", scopes, at(time.Hour)), hop("user-1", "agent-1", scopes, at(time.Hour))}
		cov.mark("delegation:cycle")
	case "exceeds":
		env.Delegation = []*controlv1.Delegation{hop("user-1", "svc", []string{"read"}, at(time.Hour)), hop("svc", "agent-1", []string{"read", "admin"}, at(time.Hour))}
		cov.mark("delegation:exceeds")
	}
}

func drawLabelsDataDestination(rt *rapid.T, cov coverage, env *controlv1.ActionEnvelope) {
	switch tier := rapid.SampledFrom([]string{"none", "gold", "silver"}).Draw(rt, "tier"); tier {
	case "none":
		cov.mark("labels:none")
	default:
		env.Resource.Labels = map[string]string{"tier": tier}
		cov.mark("labels:" + tier)
	}
	if rapid.Bool().Draw(rt, "confidential") {
		env.Data = &controlv1.DataLabels{Sensitivities: []controlv1.Sensitivity{controlv1.Sensitivity_SENSITIVITY_CONFIDENTIAL}}
		cov.mark("data:confidential")
	} else {
		cov.mark("data:none")
	}
	switch rapid.SampledFrom([]string{"none", "internal", "external"}).Draw(rt, "destination") {
	case "none":
		cov.mark("destination:none")
	case "internal":
		env.Destination = &controlv1.Destination{TrustZone: controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL, Host: "ledger.internal"}
		cov.mark("destination:internal")
	case "external":
		env.Destination = &controlv1.Destination{TrustZone: controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL, Host: "paste.example.net"}
		cov.mark("destination:external")
	}
}

// drawArguments sets the envelope's arguments hash and returns the authorized
// arguments the kernel is handed beside it.
func drawArguments(rt *rapid.T, cov coverage, env *controlv1.ActionEnvelope) []byte {
	switch rapid.SampledFrom([]string{"none", "matching", "matching", "mismatch", "float", "deep"}).Draw(rt, "arguments") {
	case "matching":
		cov.mark("arguments:matching")
		env.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(rt, refundArgs())}
		return refundArgs()
	case "mismatch":
		cov.mark("arguments:mismatch")
		env.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(rt, refundArgs())}
		return []byte(`{"amount": 1251, "currency": "EUR"}`)
	case "float":
		cov.mark("arguments:float")
		return []byte(`{"amount": 1.5}`)
	case "deep":
		cov.mark("arguments:deep")
		return deepArguments(contract.MaxNesting + 1)
	}
	cov.mark("arguments:none")
	return nil
}

func drawFlow(rt *rapid.T, cov coverage) contract.FlowState {
	untrusted := rapid.Bool().Draw(rt, "untrusted")
	if untrusted {
		cov.mark("flow:untrusted")
	} else {
		cov.mark("flow:trusted")
	}
	floor := rapid.SampledFrom([]controlv1.Sensitivity{
		controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED, controlv1.Sensitivity_SENSITIVITY_PUBLIC,
		controlv1.Sensitivity_SENSITIVITY_CONFIDENTIAL, controlv1.Sensitivity_SENSITIVITY_RESTRICTED,
	}).Draw(rt, "floor")
	return contract.NewFlowState(untrusted, floor)
}

// drawFault leaves the envelope as built most of the time, and otherwise
// breaks it in one way the kernel's own Validate refuses, or hands in a
// decoder's refusal beside it.
func drawFault(rt *rapid.T, cov coverage, env *controlv1.ActionEnvelope) (*controlv1.ActionEnvelope, error) {
	faults := []string{"valid", "valid", "valid", "valid", "valid", "valid", "nil", "tab-in-request-id", "long-request-id",
		"schema-2.0", "undeclared-trust-zone", "no-resource", "refusal"}
	fault := rapid.SampledFrom(faults).Draw(rt, "fault")
	switch fault {
	case "nil":
		cov.mark("envelope:nil")
		return nil, nil
	case "tab-in-request-id":
		env.RequestId = "req\t1"
	case "long-request-id":
		env.RequestId = strings.Repeat("r", contract.MaxStringBytes+1)
	case "schema-2.0":
		env.SchemaVersion = "2.0"
	case "undeclared-trust-zone":
		env.Destination = &controlv1.Destination{TrustZone: controlv1.TrustZone(100)}
	case "no-resource":
		env.Resource = nil
	case "refusal":
		s := rapid.SampledFrom(sentinels()).Draw(rt, "sentinel")
		cov.mark("refusal:" + s.name)
		return env, s.err
	}
	cov.mark("envelope:" + fault)
	return env, nil
}

// decideBatch decides the batch against snaps, one per bundle, in the order
// given, with a fixed clock reading now and a constant id source. Kernels are
// built per case because the options are drawn per case; New is not on the
// path measured.
func decideBatch(rt *rapid.T, s scenario, order []int, snaps []*policy.Snapshot, now time.Time) []core.Outcome {
	out := make([]core.Outcome, len(s.batch))
	for _, i := range order {
		c := s.batch[i]
		k, err := core.New(c.opts, fixedClock(now), func() string { return "decision" })
		if err != nil {
			rt.Fatalf("New refused drawn options: %v", err)
		}
		out[i] = decide(k, c.req, snaps[s.bundleOf(i)])
	}
	return out
}

func inOrder(n int) []int {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	return order
}

// loadTwice signs each document once and loads its bundle twice at
// loadedAt, so a second snapshot shares nothing with the first but the bytes.
// No document is a nil snapshot in both.
func loadTwice(rt *rapid.T, s scenario, secondAt time.Time) (first, second []*policy.Snapshot) {
	first, second = make([]*policy.Snapshot, len(s.bundles)), make([]*policy.Snapshot, len(s.bundles))
	for j, d := range s.bundles {
		if d.doc == nil {
			continue
		}
		b, err := policy.Sign(d.doc, key(), "k1")
		if err != nil {
			rt.Fatalf("Sign refused a drawn document: %v", err)
		}
		if first[j], err = policy.Load(b, pinned(), s.loadedAt); err != nil {
			rt.Fatalf("Load refused a drawn document: %v", err)
		}
		if second[j], err = policy.Load(proto.CloneOf(b), pinned(), secondAt); err != nil {
			rt.Fatalf("the second Load refused what the first accepted: %v", err)
		}
	}
	return first, second
}

// determinism is the property. The first run decides with the process zone
// UTC and every instant in UTC; the second with the process zone set to zone
// and its clock and load time expressed in it. The decisions may not differ
// by any of that: the zone is an input no decision records.
func determinism(cov coverage, decided *int, zone *time.Location) func(rt *rapid.T) {
	return func(rt *rapid.T) {
		s := drawScenario(rt, cov)
		first, second := loadTwice(rt, s, s.loadedAt.In(zone))
		time.Local = time.UTC
		got := decideBatch(rt, s, inOrder(len(s.batch)), first, s.now)
		shuffled := rapid.Permutation(inOrder(len(s.batch))).Draw(rt, "order")
		time.Local = zone
		again := decideBatch(rt, s, shuffled, second, s.now.In(zone))
		for i := range s.batch {
			*decided++
			b := s.bundleOf(i)
			markBundle(cov, s.bundles[b])
			stale := staleAt(s, s.bundles[b].doc, s.batch[i].opts)
			cov.mark(map[bool]string{true: "stale", false: "fresh"}[stale])
			checkOutcomeShape(rt, s.batch[i], got[i], first[b] != nil, stale)
			checkAnswerShape(rt, cov, s.batch[i], got[i])
			if got[i].Action != again[i].Action || !proto.Equal(got[i].Decision, again[i].Decision) {
				rt.Fatalf("case %d decided differently: %v then %v", i, got[i], again[i])
			}
		}
	}
}

// staleAt is the freshness rule as ADR-0012 states it, computed here from
// the drawn ages and budgets rather than read back from the decision.
func staleAt(s scenario, doc []byte, opts core.Options) bool {
	if doc == nil {
		return true
	}
	age := s.now.Sub(s.loadedAt)
	bundleBudget := time.Duration(bundleMaxStaleSeconds(doc)) * time.Second
	return age < 0 || age > min(bundleBudget, opts.MaxStale)
}

// bundleMaxStaleSeconds reads the budget back out of the document text
// helpers_test.go writes, so the expectation is not taken from the snapshot.
func bundleMaxStaleSeconds(doc []byte) int {
	const key = `"maxStaleSeconds":`
	text := string(doc)
	i := strings.Index(text, key)
	rest := text[i+len(key):]
	n := 0
	for _, r := range rest {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// checkOutcomeShape holds every decision to the rules equality alone cannot
// see: the verdict is one of the five; each determinate verdict has its
// action; INDETERMINATE runs only a READ the operator opened and marks it;
// the bundle digest and load time are on a decision exactly when a snapshot
// was; the freshness is the rule's; the id source and the clock were used.
func checkOutcomeShape(rt *rapid.T, c drawnCase, out core.Outcome, withSnapshot, stale bool) {
	d := out.Decision
	if d == nil {
		rt.Fatalf("Decision is nil")
	}
	checkEnforcement(rt, c.opts.FailOpenRead, c.read, out)
	if (d.GetPolicyBundleDigest() != "") != withSnapshot || (d.GetPolicyLoadedAt() != nil) != withSnapshot {
		rt.Fatalf("snapshot %v, yet bundle digest %q and loaded_at %v", withSnapshot, d.GetPolicyBundleDigest(), d.GetPolicyLoadedAt())
	}
	checkStaleness(rt, d, stale)
	if d.GetDecisionId() != "decision" || d.GetDecisionLatencyUs() != 0 || !d.GetDecidedAt().AsTime().Equal(base()) {
		rt.Fatalf("id %q, latency %d, decided_at %v: not the fixed clock and id source", d.GetDecisionId(), d.GetDecisionLatencyUs(), d.GetDecidedAt().AsTime())
	}
	if len(d.GetReasonCodes()) == 0 || len(slices.Compact(slices.Sorted(slices.Values(d.GetReasonCodes())))) != len(d.GetReasonCodes()) {
		rt.Fatalf("codes %q: empty or repeated", d.GetReasonCodes())
	}
}

// checkStaleness holds a decision to the freshness rule computed from the
// drawn ages, on every branch, whether or not the freshness step ran; and a
// stale snapshot, or none, never lets a call proceed: not ALLOW, not
// ALLOW_WITH_OBLIGATIONS, not REQUIRE_APPROVAL.
func checkStaleness(rt *rapid.T, d *controlv1.Decision, stale bool) {
	if (d.GetPolicyFreshness() == controlv1.PolicyFreshness_POLICY_FRESHNESS_STALE) != stale {
		rt.Fatalf("freshness %s, want stale=%v; codes %q", d.GetPolicyFreshness(), stale, d.GetReasonCodes())
	}
	if v := d.GetVerdict(); stale && v != verdictDeny && v != verdictIndeterminate {
		rt.Fatalf("stale, yet verdict %s; codes %q", v, d.GetReasonCodes())
	}
}

// runDeterminism runs the property and then holds the run to its size and
// to the branches the generator has to have reached. The property sets the
// process zone; it is put back when the test ends.
func runDeterminism(t *testing.T, zone *time.Location) {
	t.Helper()
	local := time.Local
	t.Cleanup(func() { time.Local = local })
	cov := coverage{}
	decided := 0
	rapid.Check(t, determinism(cov, &decided, zone))
	if decided < 10_000 {
		t.Errorf("%d cases decided, the criterion is 10 000", decided)
	}
	for _, label := range branches() {
		if cov[label] == 0 {
			t.Errorf("the generator never reached %s", label)
		}
	}
}

// TestDecideIsDeterministic runs the determinism property under UTC.
func TestDecideIsDeterministic(t *testing.T) {
	runDeterminism(t, time.UTC)
}

// TestDecideIgnoresTheLocalZone is the same property with the second run
// under a process zone that is not UTC, on a whole-hour offset and on one
// that is not, so a zone read by any name changes a decision.
func TestDecideIgnoresTheLocalZone(t *testing.T) {
	for _, zone := range []*time.Location{time.FixedZone("UTC-08", -8*3600), time.FixedZone("UTC+05:45", 5*3600+45*60)} {
		t.Run(zone.String(), func(t *testing.T) { runDeterminism(t, zone) })
	}
}

// TestEveryRefusalAgainstEveryEffectClass is the refusal rule of ADR-0012,
// exhaustively: each sentinel a decoder can hand in, and each fault the
// kernel's own steps refuse in an in-memory request, against every effect
// class, the zero value and an undeclared number included, under fail-open,
// is INDETERMINATE, Block and one code. A handed-in refusal carries its own
// code on every class. An in-memory fault carries its code on a declared
// class, which the complete envelope otherwise passes; on the two classes
// Validate refuses by themselves, either that refusal or the fault's may come
// first.
func TestEveryRefusalAgainstEveryEffectClass(t *testing.T) {
	k := kernelAt(t, failOpen())
	snap := snapshot(t, allowReads, allowWrites)
	for _, effect := range slices.Compact(slices.Sorted(slices.Values(effects()))) {
		for _, s := range sentinels() {
			req := completeRequest(t, effect)
			req.Refusal = s.err
			checkRefused(t, effect.String()+" handed "+s.name, decide(k, req, snap), s.code)
		}
		for _, f := range inMemoryFaults(t) {
			req := completeRequest(t, effect)
			f.apply(&req)
			allowed := []string{f.code}
			if classCode := classRefusal(effect); classCode != "" {
				allowed = append(allowed, classCode)
			}
			checkRefused(t, effect.String()+" "+f.name, decide(k, req, snap), allowed...)
		}
	}
	// The complete request passes on every declared class, so a refusal above
	// was the fault's and not the envelope's.
	for _, effect := range slices.Compact(slices.Sorted(slices.Values(effects()))) {
		if classRefusal(effect) != "" {
			continue
		}
		if d := decide(k, completeRequest(t, effect), snap).Decision; d.GetActionDigest() == "" {
			t.Errorf("%s: the complete envelope was refused: %q", effect, d.GetReasonCodes())
		}
	}
}

// completeRequest is a request every declared class validates: both tenants,
// an arguments hash with its arguments, a destination and a one-hop chain.
func completeRequest(t *testing.T, effect controlv1.EffectClass) core.Request {
	t.Helper()
	env := readEnvelope()
	env.Action.Effect = effect
	env.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(t, refundArgs())}
	env.Destination = &controlv1.Destination{TrustZone: controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL, Host: "ledger.internal"}
	env.Delegation = chain([]string{"read"}, at(time.Hour))
	req := request(env)
	req.AuthorizedArgs = refundArgs()
	return req
}

// classRefusal is the code Validate refuses a class with on its own: the
// zero value names no class, and an undeclared number is not this contract.
func classRefusal(effect controlv1.EffectClass) string {
	switch effect {
	case controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED:
		return codeRequiredFieldAbsent
	case controlv1.EffectClass(100):
		return codeUnsupportedSchema
	}
	return ""
}

// inMemoryFault is one way to break a request so that Validate, or the
// digest step after it, refuses with a known code.
type inMemoryFault struct {
	name  string
	code  string
	apply func(*core.Request)
}

func inMemoryFaults(t *testing.T) []inMemoryFault {
	t.Helper()
	return []inMemoryFault{
		{"schema 2.0", codeUnsupportedSchema, func(r *core.Request) { r.Envelope.SchemaVersion = "2.0" }},
		{"undeclared trust zone", codeUnsupportedSchema, func(r *core.Request) { r.Envelope.Destination.TrustZone = controlv1.TrustZone(100) }},
		{"no request id", codeRequiredFieldAbsent, func(r *core.Request) { r.Envelope.RequestId = "" }},
		{"tab in request id", codeInvalidFieldValue, func(r *core.Request) { r.Envelope.RequestId = "req\t1" }},
		{"request id over the bound", codeLimitExceeded, func(r *core.Request) {
			r.Envelope.RequestId = strings.Repeat("r", contract.MaxStringBytes+1)
		}},
		{"arguments hash of other arguments", codeInvalidFieldValue, func(r *core.Request) { r.AuthorizedArgs = []byte(`{"amount": 1251}`) }},
		// The digest runs before the hash comparison, so these three refuse on
		// the arguments themselves, whatever hash the envelope names.
		{"arguments with a float", codeInvalidFieldValue, func(r *core.Request) { r.AuthorizedArgs = []byte(`{"amount": 1.5}`) }},
		{"arguments nested past the bound", codeLimitExceeded, func(r *core.Request) { r.AuthorizedArgs = deepArguments(contract.MaxNesting + 1) }},
		{"arguments over the size bound", codeLimitExceeded, func(r *core.Request) { r.AuthorizedArgs = argumentsOfSize(t, contract.MaxArgumentsBytes+1) }},
	}
}

// checkRefused: INDETERMINATE, Block, no action digest and exactly one code,
// which is one of allowed.
func checkRefused(t *testing.T, name string, out core.Outcome, allowed ...string) {
	t.Helper()
	d := out.Decision
	codes := d.GetReasonCodes()
	if d.GetVerdict() != verdictIndeterminate || out.Action != core.Block || len(codes) != 1 || d.GetActionDigest() != "" {
		t.Errorf("%s: verdict %s, action %d, codes %q, digest %q", name, d.GetVerdict(), out.Action, codes, d.GetActionDigest())
		return
	}
	if !slices.Contains(allowed, codes[0]) {
		t.Errorf("%s: code %s, want one of %q", name, codes[0], allowed)
	}
}

// TestChildBeyondParentThroughDecide is the parent-bound rule of ADR-0012
// through Decide: a two-hop chain whose sets are equal passes; one extra
// scope on the child, and a child holding a scope under a parent holding
// none, are DENY with DELEGATION_EXCEEDS_PARENT, with a bundle and without
// one.
func TestChildBeyondParentThroughDecide(t *testing.T) {
	k := kernelAt(t, failOpen())
	two := func(parent, child []string) []*controlv1.Delegation {
		return []*controlv1.Delegation{hop("user-1", "svc", parent, at(time.Hour)), hop("svc", "agent-1", child, at(time.Hour))}
	}
	cases := []struct {
		name    string
		chain   []*controlv1.Delegation
		bundled expect
		bare    expect
	}{
		{"equal sets", two([]string{"read", "admin"}, []string{"admin", "read"}),
			expect{verdictAllow, core.Execute, []string{codeRuleAllow}},
			expect{verdictIndeterminate, core.Execute, []string{codePolicyUnavailable, codeFailOpenRead}}},
		{"one extra scope", two([]string{"read"}, []string{"read", "admin"}),
			expect{verdictDeny, core.Block, []string{codeDelegationExceeds, codeRuleAllow}},
			expect{verdictDeny, core.Block, []string{codeDelegationExceeds, codePolicyUnavailable}}},
		{"an empty parent", two(nil, []string{"read"}),
			expect{verdictDeny, core.Block, []string{codeDelegationExceeds, codeRuleAllow}},
			expect{verdictDeny, core.Block, []string{codeDelegationExceeds, codePolicyUnavailable}}},
	}
	for _, c := range cases {
		env := readEnvelope()
		env.Delegation = c.chain
		snap := snapshot(t, allowReads)
		out := decide(k, request(env), snap)
		check(t, out, c.bundled)
		if out.Decision.GetPolicyBundleDigest() != snap.Ref().GetDigest() {
			t.Errorf("%s: bundle digest %q, want the snapshot's", c.name, out.Decision.GetPolicyBundleDigest())
		}
		out = decide(k, request(env), nil)
		check(t, out, c.bare)
		if out.Decision.GetPolicyBundleDigest() != "" {
			t.Errorf("%s: a decision without a snapshot carries bundle digest %q", c.name, out.Decision.GetPolicyBundleDigest())
		}
	}
}
