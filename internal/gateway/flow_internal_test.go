package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/pkg/contract"
)

// flowRules decide on the flow, on the destination and on the effect, so a
// tag the kernel read would change some verdict among them.
const flowRules = `{"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}},` +
	`{"id":"deny-toxic","effect":"DENY","reason":"TOXIC_FLOW_SENSITIVE_TO_EXTERNAL","when":{"flow":{"toxicAtLeast":"CONFIDENTIAL"}}},` +
	`{"id":"approve-writes","effect":"REQUIRE_APPROVAL","when":{"action":{"effect":["WRITE"]}}},` +
	`{"id":"allow-internal","effect":"ALLOW","when":{"destination":{"trustZone":["TRUSTED_INTERNAL"]}}}`

func flowSnapshot(t *testing.T) *policy.Snapshot {
	t.Helper()
	document := []byte(`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"flows","version":"1","serial":1,"maxStaleSeconds":600},"rules":[` + flowRules + `]}`)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	signed, err := policy.Sign(document, key, "k1")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	snap, err := policy.Load(signed, bundle.Keyring{"k1": ed25519.PublicKey(slices.Clone(key[ed25519.SeedSize:]))}, internalClock())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return snap
}

// TestTheFlowTagsChangeNoDecision: the kernel reads no run context, so an
// envelope with the stamped tags is decided as the same envelope without them,
// in verdict, rules and codes, over random envelopes and states.
func TestTheFlowTagsChangeNoDecision(t *testing.T) {
	snap := flowSnapshot(t)
	kernel, err := core.New(core.Options{Mode: modeEnforce, MaxStale: 10 * time.Minute}, internalClock, func() string { return "id" })
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	rng := rand.New(rand.NewPCG(3, 9)) //nolint:gosec // G404: a fixed seed keeps the property reproducible
	verdicts := map[controlv1.Verdict]bool{}
	for i := range 600 {
		env, f := randomCall(rng, i)
		c := &call{in: Admission{Envelope: env}, flow: f}
		c.stampFlow()
		if c.forged || len(c.in.Envelope.GetContext().GetTags()) != 1+len(f.tags()) {
			t.Fatalf("the stamp: forged %t, tags %q", c.forged, c.in.Envelope.GetContext().GetTags())
		}
		args := []byte(`{}`)
		plain := kernel.Decide(context.Background(), core.Request{Envelope: env, AuthorizedArgs: args, Flow: f.state}, snap).Decision
		tagged := kernel.Decide(context.Background(), core.Request{Envelope: c.in.Envelope, AuthorizedArgs: args, Flow: f.state}, snap).Decision
		if plain.GetVerdict() != tagged.GetVerdict() || !slices.Equal(plain.GetPolicyRuleIds(), tagged.GetPolicyRuleIds()) ||
			!slices.Equal(plain.GetReasonCodes(), tagged.GetReasonCodes()) || plain.GetActionDigest() != tagged.GetActionDigest() {
			t.Fatalf("%v with %q: %s %v %v; without: %s %v %v", env, f.tags(),
				tagged.GetVerdict(), tagged.GetPolicyRuleIds(), tagged.GetReasonCodes(),
				plain.GetVerdict(), plain.GetPolicyRuleIds(), plain.GetReasonCodes())
		}
		verdicts[plain.GetVerdict()] = true
		if !proto.Equal(env.GetContext(), &controlv1.RunContext{Tags: []string{"mcp.client=x/1"}}) {
			t.Fatalf("the stamp wrote to the producer's envelope: %v", env.GetContext())
		}
	}
	if len(verdicts) < 4 {
		t.Errorf("the envelopes reached only %v; the property examined too little", verdicts)
	}
}

// randomCall is an envelope of a random effect, destination and label, with a
// random flow state or none.
func randomCall(rng *rand.Rand, i int) (*controlv1.ActionEnvelope, flow) {
	effects := []controlv1.EffectClass{controlv1.EffectClass_EFFECT_CLASS_READ, controlv1.EffectClass_EFFECT_CLASS_WRITE, controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE}
	zones := []controlv1.TrustZone{0, controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL, controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL}
	levels := []controlv1.Sensitivity{0, 1, 2, 3, 4, 5}
	env := &controlv1.ActionEnvelope{
		SchemaVersion: "1.0", RequestId: "req-" + strconv.Itoa(i), ProjectId: "proj-1", TenantId: "tenant-1", Environment: "prod",
		OccurredAt: timestamppb.New(internalClock().Add(-time.Minute)),
		Principal:  &controlv1.Principal{Id: "user-1", TenantId: "tenant-1"},
		Action:     &controlv1.Action{Kind: channel.KindTool, Name: "op", Effect: effects[rng.IntN(len(effects))], Provider: "p", Protocol: channel.ProtocolMCP},
		Resource:   &controlv1.Resource{Type: "t", Id: "r", TenantId: "tenant-1", Environment: "prod"},
		Context:    &controlv1.RunContext{Tags: []string{"mcp.client=x/1"}},
	}
	if zone := zones[rng.IntN(len(zones))]; zone != 0 {
		env.Destination = &controlv1.Destination{TrustZone: zone}
	}
	if rng.IntN(2) == 0 {
		env.Data = &controlv1.DataLabels{Sensitivities: []controlv1.Sensitivity{levels[1+rng.IntN(5)]}}
	}
	if rng.IntN(4) == 0 {
		return env, flow{}
	}
	return env, flow{run: &run{id: "run"}, state: contract.NewFlowState(rng.IntN(2) == 0, levels[rng.IntN(len(levels))])}
}

// TestJoinReadAbsorbsTheUnknown: an unknown reading, or one this build cannot
// place, stays unknown whatever is read after it.
func TestJoinReadAbsorbsTheUnknown(t *testing.T) {
	unknown := controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED
	for _, tc := range []struct{ current, read, want controlv1.Sensitivity }{
		{1, 3, 3},
		{4, 2, 4},
		{2, unknown, unknown},
		{unknown, 5, unknown},
		{3, 99, unknown},
		{99, 1, unknown},
	} {
		if got := joinRead(tc.current, tc.read); got != tc.want {
			t.Errorf("joinRead(%d, %d) = %d, want %d", tc.current, tc.read, got, tc.want)
		}
	}
}
