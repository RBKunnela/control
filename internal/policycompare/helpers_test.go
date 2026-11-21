package policycompare

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// The current policy: reads run; a send is denied when the run's flow is
// toxic; a payment runs unless the decision point vetoes it; a wire to prod
// is held. The candidate lets writes run too, holds a wire under a second
// approver, and keeps its policy fresh for one minute instead of an hour.
const (
	currentDoc = `{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"shop","version":"1","serial":1,"maxStaleSeconds":3600},"rules":[
{"id":"reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}},
{"id":"flow-out","effect":"DENY","when":{"action":{"name":["send"]},"flow":{"toxicAtLeast":"INTERNAL"}}},
{"id":"send","effect":"ALLOW","when":{"action":{"name":["send"]}}},
{"id":"veto","effect":"DENY","when":{"action":{"name":["pay"]},"external":{"denies":true}}},
{"id":"pay","effect":"ALLOW","when":{"action":{"name":["pay"]}}},
{"id":"wire","effect":"REQUIRE_APPROVAL","when":{"action":{"name":["wire"]},"resource":{"environment":["prod"]}}}]}`
	candidateDoc = `{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"shop","version":"2","serial":2,"maxStaleSeconds":60},"rules":[
{"id":"reads","effect":"ALLOW","when":{"action":{"effect":["READ","WRITE"]}}},
{"id":"flow-out","effect":"DENY","when":{"action":{"name":["send"]},"flow":{"toxicAtLeast":"INTERNAL"}}},
{"id":"send","effect":"ALLOW","when":{"action":{"name":["send"]}}},
{"id":"veto","effect":"DENY","when":{"action":{"name":["pay"]},"external":{"denies":true}}},
{"id":"pay","effect":"ALLOW","when":{"action":{"name":["pay"]}}},
{"id":"wire","effect":"REQUIRE_APPROVAL","obligations":[{"type":"second_approver"}],"when":{"action":{"name":["wire"]},"resource":{"environment":["prod"]}}}]}`
)

var t0 = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

func signed(t *testing.T, doc string) Policy {
	t.Helper()
	d, canonical, err := rules.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", ed25519.SeedSize)))
	sig, err := bundle.SignBytes(canonical, key)
	if err != nil {
		t.Fatal(err)
	}
	return Policy{
		Bundle: &controlv1.PolicyBundle{
			Ref:          &controlv1.PolicyBundleRef{BundleId: d.Bundle.ID, Version: d.Bundle.Version, Digest: bundle.Digest(canonical)},
			Canonical:    canonical,
			SignatureAlg: bundle.SignatureAlg, Signature: sig, KeyId: "k", MaxStaleSeconds: d.Bundle.MaxStaleSeconds,
		},
		Keys: bundle.Keyring{"k": key.Public().(ed25519.PublicKey)},
	}
}

func envelope(req, name string, effect controlv1.EffectClass, env string) *controlv1.ActionEnvelope {
	return &controlv1.ActionEnvelope{
		SchemaVersion: "1.0", RequestId: req, ProjectId: "proj-1", TenantId: "tenant-1", Environment: "prod",
		OccurredAt:  timestamppb.New(t0),
		Principal:   &controlv1.Principal{Id: "user-1", TenantId: "tenant-1"},
		Agent:       &controlv1.Agent{Id: "agent-1"},
		Action:      &controlv1.Action{Name: name, Effect: effect, Provider: "shop"},
		Resource:    &controlv1.Resource{Type: "order", Id: "ord-1", TenantId: "tenant-1", Environment: env},
		Arguments:   &controlv1.Arguments{CanonicalHash: emptyArgumentsHash},
		Destination: &controlv1.Destination{TrustZone: controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL},
	}
}

// explicit is a case as an operator writes one: every input stated, the
// run's flow tracked and clean.
func explicit(id string, env *controlv1.ActionEnvelope) Case {
	return Case{ID: id, Source: SourceCase, Input: Input{
		Envelope:       env,
		AuthorizedArgs: []byte("{}"),
		Flow:           contract.NewFlowState(false, controlv1.Sensitivity_SENSITIVITY_PUBLIC),
		Options:        core.Options{Mode: controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE, MaxStale: time.Hour, Applicable: []string{"second_approver"}},
		LoadedAt:       t0,
		DecidedAt:      t0,
	}}
}

const (
	read  = controlv1.EffectClass_EFFECT_CLASS_READ
	write = controlv1.EffectClass_EFFECT_CLASS_WRITE
	pay   = controlv1.EffectClass_EFFECT_CLASS_TRANSACT
	send  = controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE
)

func compareOrFail(t *testing.T, cases []Case, labels *Labels) *Report {
	t.Helper()
	r, err := Compare(Run{Current: signed(t, currentDoc), Candidate: signed(t, candidateDoc), Cases: cases, Labels: labels, Build: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rowOf(t *testing.T, r *Report, id string) CaseRow {
	t.Helper()
	for _, row := range r.Cases {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("no row %q", id)
	return CaseRow{}
}

func reasonOf(row CaseRow) Reason {
	if row.UnknownReason == nil {
		return ""
	}
	return *row.UnknownReason
}
