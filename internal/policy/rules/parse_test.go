package rules

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

func sampleDocument(t testing.TB, name string) []byte {
	t.Helper()
	raw, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..", "..", "testdata", "policy", "documents")), name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The canonical forms of the two samples, written by hand and checked, before
// they were pinned, against an encoder in another language that sorts keys and
// writes no whitespace. Every key in them is in the basic multilingual plane,
// where that sort agrees with the canonical one.
const (
	exampleCanonical = `{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"payments","maxStaleSeconds":300,"serial":7,"version":"2026-09-10.1"},"rules":[{"effect":"REQUIRE_APPROVAL","id":"refunds-in-prod-need-approval","obligations":[{"params":{"max":"10000"},"type":"cap_amount"}],"when":{"action":{"effect":["TRANSACT"],"name":["refund"],"provider":["payments"]},"resource":{"environment":["prod"]}}}]}`

	everyFieldCanonical = `{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"payments","maxStaleSeconds":900,"serial":12,"version":"2026-09-11.1"},"rules":[` +
		`{"effect":"DENY","id":"no-secrets-to-untrusted-hosts","reason":"TOXIC_FLOW_SENSITIVE_TO_EXTERNAL","when":{"data":{"sensitivityAtLeast":"CONFIDENTIAL"},"destination":{"host":["paste.example.net"],"trustZone":["UNTRUSTED_EXTERNAL","USER_CONTROLLED"]},"flow":{"toxicAtLeast":"RESTRICTED"}}},` +
		`{"effect":"DENY","id":"prod-stays-in-its-team","reason":"RULE_DENY","when":{"principal":{"attributes":{"rôle":["équipe"],"team":["payments","risk"]},"authnStrength":["mfa"],"id":["user:ana"],"tenantId":["acme"],"type":["human"]},"resource":{"environment":["prod"],"id":["ledger/eu-1"],"labels":{"tier":["gold"]},"tenantId":["acme"],"type":["ledger"]}}},` +
		`{"effect":"REQUIRE_APPROVAL","id":"refunds-need-approval","obligations":[{"params":{"field":"amount","max":"10000"},"type":"cap_amount"},{"advisory":true,"type":"emit_alert"}],"when":{"action":{"effect":["TRANSACT","WRITE"],"kind":["tool_call"],"name":["refund"],"protocol":["mcp"],"provider":["payments"]},"agent":{"framework":["custom"],"id":["billing-agent"]}}},` +
		`{"effect":"ALLOW_WITH_OBLIGATIONS","id":"delegated-reads-stay-read-only","obligations":[{"advisory":false,"type":"read_only"}],"reason":"OBLIGATIONS_ATTACHED","when":{"action":{"effect":["READ"]},"delegation":{"scopes":["ledger:read"]}}},` +
		`{"effect":"ALLOW","id":"reads","when":{"action":{"effect":["READ"]}}}]}`
)

func exampleModel() *Document {
	return &Document{
		APIVersion: "agent-policy/v1alpha1",
		Bundle:     Bundle{ID: "payments", Version: "2026-09-10.1", Serial: 7, MaxStaleSeconds: 300},
		Rules: []Rule{{
			ID:          "refunds-in-prod-need-approval",
			Effect:      controlv1.Verdict_VERDICT_REQUIRE_APPROVAL,
			Obligations: []Obligation{{Type: "cap_amount", Params: map[string]string{"max": "10000"}}},
			When: When{
				Action: &ActionWhen{
					Name:     []string{"refund"},
					Provider: []string{"payments"},
					Effect:   []controlv1.EffectClass{controlv1.EffectClass_EFFECT_CLASS_TRANSACT},
				},
				Resource: &ResourceWhen{Environment: []string{"prod"}},
			},
		}},
	}
}

func everyFieldModel() *Document {
	read := []controlv1.EffectClass{controlv1.EffectClass_EFFECT_CLASS_READ}
	return &Document{
		APIVersion: "agent-policy/v1alpha1",
		Bundle:     Bundle{ID: "payments", Version: "2026-09-11.1", Serial: 12, MaxStaleSeconds: 900},
		Rules: []Rule{
			{
				ID: "no-secrets-to-untrusted-hosts", Effect: controlv1.Verdict_VERDICT_DENY,
				Reason: "TOXIC_FLOW_SENSITIVE_TO_EXTERNAL",
				When: When{
					Destination: &DestinationWhen{
						TrustZone: []controlv1.TrustZone{controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL, controlv1.TrustZone_TRUST_ZONE_USER_CONTROLLED},
						Host:      []string{"paste.example.net"},
					},
					Data: &DataWhen{SensitivityAtLeast: controlv1.Sensitivity_SENSITIVITY_CONFIDENTIAL},
					Flow: &FlowWhen{ToxicAtLeast: controlv1.Sensitivity_SENSITIVITY_RESTRICTED},
				},
			},
			{
				ID: "prod-stays-in-its-team", Effect: controlv1.Verdict_VERDICT_DENY,
				When: When{
					Principal: &PrincipalWhen{
						ID: []string{"user:ana"}, Type: []string{"human"}, AuthnStrength: []string{"mfa"}, TenantID: []string{"acme"},
						Attributes: map[string][]string{"team": {"payments", "risk"}, "rôle": {"équipe"}},
					},
					Resource: &ResourceWhen{
						Type: []string{"ledger"}, ID: []string{"ledger/eu-1"}, TenantID: []string{"acme"}, Environment: []string{"prod"},
						Labels: map[string][]string{"tier": {"gold"}},
					},
				},
			},
			{
				ID: "refunds-need-approval", Effect: controlv1.Verdict_VERDICT_REQUIRE_APPROVAL,
				Obligations: []Obligation{
					{Type: "cap_amount", Params: map[string]string{"max": "10000", "field": "amount"}},
					{Type: "emit_alert", Advisory: true},
				},
				When: When{
					Agent: &AgentWhen{ID: []string{"billing-agent"}, Framework: []string{"custom"}},
					Action: &ActionWhen{
						Name: []string{"refund"}, Provider: []string{"payments"}, Protocol: []string{"mcp"}, Kind: []string{"tool_call"},
						Effect: []controlv1.EffectClass{controlv1.EffectClass_EFFECT_CLASS_TRANSACT, controlv1.EffectClass_EFFECT_CLASS_WRITE},
					},
				},
			},
			{
				ID: "delegated-reads-stay-read-only", Effect: controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS,
				Obligations: []Obligation{{Type: "read_only"}},
				When:        When{Delegation: &DelegationWhen{Scopes: []string{"ledger:read"}}, Action: &ActionWhen{Effect: read}},
			},
			{ID: "reads", Effect: controlv1.Verdict_VERDICT_ALLOW, When: When{Action: &ActionWhen{Effect: read}}},
		},
	}
}

// TestParseReadsTheSampleDocuments pins the model and the canonical bytes of
// each sample. The models also pin what is absent: reflect.DeepEqual tells a
// nil list, map or group from an empty one, and Parse leaves every absent one
// nil. The canonical bytes parse again to themselves and to the same model.
func TestParseReadsTheSampleDocuments(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file      string
		model     *Document
		canonical string
	}{
		{"example.json", exampleModel(), exampleCanonical},
		{"every-field.json", everyFieldModel(), everyFieldCanonical},
	}
	for _, tc := range cases {
		for _, input := range [][]byte{sampleDocument(t, tc.file), []byte(tc.canonical)} {
			model, canonical, err := Parse(input)
			if err != nil {
				t.Fatalf("%s: %v", tc.file, err)
			}
			if string(canonical) != tc.canonical {
				t.Errorf("%s: canonical bytes\n got %s\nwant %s", tc.file, canonical, tc.canonical)
			}
			if !reflect.DeepEqual(model, tc.model) {
				t.Errorf("%s: model\n got %#v\nwant %#v", tc.file, model, tc.model)
			}
		}
	}
}

// TestParseReturnsTheCanonicalFormNotTheInput: whitespace, member order and
// escapes are the author's; the bytes returned, which are the bytes signed,
// are the canonical form, and the model holds the decoded strings.
func TestParseReturnsTheCanonicalFormNotTheInput(t *testing.T) {
	t.Parallel()
	raw := `{ "rules" : [ {"when":{"action":{"name":["a\/b", "a\"b", "a\\b"]}}, "effect":"DENY", "id":"r"} ],
	  "bundle": {"serial": 1, "maxStaleSeconds": 300, "version": "1", "id": "p"}, "apiVersion": "agent-policy/v1alpha1" }`
	want := `{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"p","maxStaleSeconds":300,"serial":1,"version":"1"},"rules":[{"effect":"DENY","id":"r","when":{"action":{"name":["a/b","a\"b","a\\b"]}}}]}`
	model, canonical, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != want {
		t.Errorf("canonical bytes\n got %s\nwant %s", canonical, want)
	}
	if got := model.Rules[0].When.Action.Name; !slices.Equal(got, []string{"a/b", `a"b`, `a\b`}) {
		t.Errorf("names = %q", got)
	}
}

// TestParseKeepsDocumentOrder: rules, obligations and values stay in document
// order, and a repeated value or obligation is kept; the matcher's union is
// where repeats are merged.
func TestParseKeepsDocumentOrder(t *testing.T) {
	t.Parallel()
	doc := docWithRules(
		`{"id":"z","effect":"DENY","when":{"action":{"name":["b","a","b"]}}}`,
		`{"id":"a","effect":"REQUIRE_APPROVAL","obligations":[{"type":"emit_alert"},{"type":"cap_amount"},{"type":"emit_alert"}],"when":{"action":{"name":["x"]}}}`,
		`{"id":"m","effect":"ALLOW","when":{"action":{"effect":["WRITE","READ"]}}}`)
	model := expectAccepted(t, doc)
	var ids []string
	for _, r := range model.Rules {
		ids = append(ids, r.ID)
	}
	if !slices.Equal(ids, []string{"z", "a", "m"}) {
		t.Errorf("rule ids = %q", ids)
	}
	if got := model.Rules[0].When.Action.Name; !slices.Equal(got, []string{"b", "a", "b"}) {
		t.Errorf("names = %q", got)
	}
	var types []string
	for _, o := range model.Rules[1].Obligations {
		types = append(types, o.Type)
	}
	if !slices.Equal(types, []string{"emit_alert", "cap_amount", "emit_alert"}) {
		t.Errorf("obligation types = %q", types)
	}
	want := []controlv1.EffectClass{controlv1.EffectClass_EFFECT_CLASS_WRITE, controlv1.EffectClass_EFFECT_CLASS_READ}
	if got := model.Rules[2].When.Action.Effect; !slices.Equal(got, want) {
		t.Errorf("effects = %v", got)
	}
}

// TestParseResultsShareNothing: a caller that changes one model cannot change
// the next one.
func TestParseResultsShareNothing(t *testing.T) {
	t.Parallel()
	raw := sampleDocument(t, "every-field.json")
	first := expectAccepted(t, string(raw))
	first.Rules[1].When.Principal.Attributes["team"][0] = "changed"
	first.Rules[2].Obligations[0].Params["max"] = "changed"
	first.Rules[0].When.Destination.Host[0] = "changed"
	if second := expectAccepted(t, string(raw)); !reflect.DeepEqual(second, everyFieldModel()) {
		t.Fatalf("a second parse sees the first one's changes: %#v", second)
	}
}
