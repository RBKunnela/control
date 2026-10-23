package contract_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// valid returns an envelope every check passes, built rather than read from a
// fixture: a test that mutates one field of a shared fixture would change what
// the other tests in the tree assert about it.
func valid() *controlv1.ActionEnvelope {
	return &controlv1.ActionEnvelope{
		SchemaVersion: "1.0",
		RequestId:     "req-1",
		ProjectId:     "proj-1",
		TenantId:      "tenant-1",
		OccurredAt:    timestamppb.New(time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)),
		Principal:     &controlv1.Principal{Id: "user-1", TenantId: "tenant-1"},
		Action: &controlv1.Action{
			Name:     "orders.read",
			Effect:   controlv1.EffectClass_EFFECT_CLASS_READ,
			Provider: "orders-mcp",
		},
		Resource: &controlv1.Resource{Type: "order", Id: "ord-1", TenantId: "tenant-1"},
	}
}

// assertRefused reports the sentinel and the field path of one refusal.
func assertRefused(t *testing.T, err error, want error, field string) {
	t.Helper()

	if err == nil {
		t.Fatalf("want %v naming %q, got no error", want, field)
	}
	if !errors.Is(err, want) {
		t.Errorf("got %v, want %v", err, want)
	}
	var ve *contract.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("got %v, which is not a *ValidationError", err)
	}
	if ve.Field != field {
		t.Errorf("refusal names %q, want %q", ve.Field, field)
	}
}

func TestValidateAcceptsTheBaseEnvelope(t *testing.T) {
	// Every negative case below mutates this one, so a base that already failed
	// would make all of them pass for the wrong reason.
	if err := contract.Validate(valid()); err != nil {
		t.Fatalf("the base envelope is refused, so no case below proves anything: %v", err)
	}
}

func TestValidateNil(t *testing.T) {
	err := contract.Validate(nil)
	if err == nil {
		t.Fatal("Validate(nil) = nil, want a refusal")
	}
	if !errors.Is(err, contract.ErrMissingField) {
		t.Errorf("Validate(nil) = %v, want ErrMissingField", err)
	}
}

func TestValidateSchemaVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		refused bool
	}{
		{"1.0", false},
		{"1.3", false},
		{"1.99", false},
		{"2.0", true},
		{"0.9", true},
		{"", true},
		{"banana", true},
		{"1", true},
		{"1.", true},
		{".0", true},
		{"1.0.0", true},
		{"v1.0", true},
		{" 1.0", true},
		{"1.0 ", true},
	} {
		t.Run("v"+tc.version, func(t *testing.T) {
			env := valid()
			env.SchemaVersion = tc.version

			err := contract.Validate(env)
			switch {
			case tc.refused:
				assertRefused(t, err, contract.ErrUnsupportedSchema, "schema_version")
			case err != nil:
				t.Errorf("Validate = %v, want the version accepted", err)
			}
		})
	}
}

// TestValidateRequiredAlways covers the fields no effect class can do without.
func TestValidateRequiredAlways(t *testing.T) {
	for _, tc := range []struct {
		field string
		clear func(*controlv1.ActionEnvelope)
	}{
		{"request_id", func(e *controlv1.ActionEnvelope) { e.RequestId = "" }},
		{"project_id", func(e *controlv1.ActionEnvelope) { e.ProjectId = "" }},
		{"tenant_id", func(e *controlv1.ActionEnvelope) { e.TenantId = "" }},
		{"principal.id", func(e *controlv1.ActionEnvelope) { e.Principal.Id = "" }},
		{"principal.id", func(e *controlv1.ActionEnvelope) { e.Principal = nil }},
		{"action.name", func(e *controlv1.ActionEnvelope) { e.Action.Name = "" }},
		{"occurred_at", func(e *controlv1.ActionEnvelope) { e.OccurredAt = nil }},
		{"occurred_at", func(e *controlv1.ActionEnvelope) { e.OccurredAt = &timestamppb.Timestamp{} }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			env := valid()
			tc.clear(env)
			assertRefused(t, contract.Validate(env), contract.ErrMissingField, tc.field)
		})
	}
}

// TestValidateEffectRequirements walks the contract's table, both ways: each
// class is accepted with what it requires and refused without each one.
func TestValidateEffectRequirements(t *testing.T) {
	for _, tc := range []struct {
		effect   controlv1.EffectClass
		required []string
	}{
		{controlv1.EffectClass_EFFECT_CLASS_READ, []string{"resource.type"}},
		{controlv1.EffectClass_EFFECT_CLASS_WRITE, []string{"resource.type", "resource.id", "environment", "resource.environment"}},
		{controlv1.EffectClass_EFFECT_CLASS_DELETE, []string{"resource.type", "resource.id", "environment", "resource.environment"}},
		{controlv1.EffectClass_EFFECT_CLASS_CONFIGURE, []string{"resource.type", "resource.id", "environment", "resource.environment"}},
		{controlv1.EffectClass_EFFECT_CLASS_EXECUTE, []string{"resource.type", "arguments.canonical_hash"}},
		{controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE, []string{"destination.trust_zone"}},
		{controlv1.EffectClass_EFFECT_CLASS_TRANSACT, []string{"resource.id", "arguments.canonical_hash", "principal.tenant_id", "resource.tenant_id"}},
		{controlv1.EffectClass_EFFECT_CLASS_IDENTITY_OR_ACCESS, []string{"resource.id", "principal.tenant_id", "resource.tenant_id"}},
		{controlv1.EffectClass_EFFECT_CLASS_SPAWN_OR_DELEGATE, []string{"agent.id", "delegation"}},
	} {
		t.Run(tc.effect.String(), func(t *testing.T) {
			if err := contract.Validate(satisfying(tc.effect, tc.required)); err != nil {
				t.Fatalf("an envelope carrying everything %s requires is refused, so the negatives below prove nothing: %v",
					tc.effect, err)
			}
			for _, path := range tc.required {
				t.Run("without "+path, func(t *testing.T) {
					env := satisfying(tc.effect, tc.required)
					clearPath(t, env, path)
					assertRefused(t, contract.Validate(env), contract.ErrMissingField, path)
				})
			}
		})
	}
}

// TestValidateProviderRequiredForMaterialEffects: only a read is exempt.
func TestValidateProviderRequiredForMaterialEffects(t *testing.T) {
	for effect, paths := range effectsUnderTest() {
		t.Run(effect.String(), func(t *testing.T) {
			env := satisfying(effect, paths)
			env.Action.Provider = ""

			err := contract.Validate(env)
			if effect == controlv1.EffectClass_EFFECT_CLASS_READ {
				if err != nil {
					t.Errorf("a read without a provider is refused: %v", err)
				}
				return
			}
			assertRefused(t, err, contract.ErrMissingField, "action.provider")
		})
	}
}

func TestValidateEffectUnspecified(t *testing.T) {
	env := valid()
	env.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
	assertRefused(t, contract.Validate(env), contract.ErrMissingField, "action.effect")
}

// TestValidateUndeclaredEnumNumber is the case neither unmarshaller catches:
// protojson accepts an out-of-range enum number and binary protobuf writes it
// into the typed field with no unknown bytes at all.
func TestValidateUndeclaredEnumNumber(t *testing.T) {
	const undeclared = 99

	t.Run("in memory", func(t *testing.T) {
		env := valid()
		env.Action.Effect = undeclared
		assertRefused(t, contract.Validate(env), contract.ErrInvalidEnum, "action.effect")
	})

	t.Run("binary path", func(t *testing.T) {
		env := valid()
		env.Action.Effect = undeclared
		wire, err := proto.Marshal(env)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		_, err = contract.Decode(wire)
		assertRefused(t, err, contract.ErrInvalidEnum, "action.effect")
	})

	t.Run("json path", func(t *testing.T) {
		env := valid()
		env.Action.Effect = undeclared
		document, err := protojson.Marshal(env)
		if err != nil {
			t.Fatalf("protojson marshal: %v", err)
		}
		if !strings.Contains(string(document), "99") {
			t.Fatalf("the document does not carry the undeclared number, so this case proves nothing: %s", document)
		}
		_, err = contract.DecodeJSON(document)
		assertRefused(t, err, contract.ErrInvalidEnum, "action.effect")
	})

	t.Run("repeated enum field", func(t *testing.T) {
		env := valid()
		env.Data = &controlv1.DataLabels{Sensitivities: []controlv1.Sensitivity{
			controlv1.Sensitivity_SENSITIVITY_PUBLIC,
			undeclared,
		}}
		assertRefused(t, contract.Validate(env), contract.ErrInvalidEnum, "data.sensitivities[1]")
	})
}

// TestDecodeRefusesAnUnknownFieldOnANestedMessage is the case a check that
// reads only the envelope's own unknown bytes misses: the bytes sit on the
// child, and the parent reports nothing.
func TestDecodeRefusesAnUnknownFieldOnANestedMessage(t *testing.T) {
	env := valid()
	env.Action.ProtoReflect().SetUnknown(unknownField(4095))
	wire, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// The premise: the envelope itself carries nothing unknown, so a check that
	// looked only there would report this message as clean.
	parsed := &controlv1.ActionEnvelope{}
	if err := proto.Unmarshal(wire, parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.ProtoReflect().GetUnknown()) != 0 {
		t.Fatal("the envelope carries the unknown bytes itself, so this case no longer tests the nested one")
	}
	if len(parsed.GetAction().ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("the nested message lost the unknown bytes, so there is nothing to refuse")
	}

	_, err = contract.Decode(wire)
	assertRefused(t, err, contract.ErrUnknownField, "action.<field 4095>")
}

func TestDecodeJSONRefusesAnUnknownField(t *testing.T) {
	_, err := contract.DecodeJSON([]byte(`{"schemaVersion":"1.0","bogusSecurityField":true}`))
	if err == nil {
		t.Fatal("an unknown JSON field was accepted")
	}
	// The name is the caller's text, and a refusal is written into evidence
	// (docs/contracts.md, "Refusals"), so it is not rendered. The codec's
	// error, which names it, stays in the chain, and that is what shows the
	// refusal is about this field.
	if strings.Contains(err.Error(), "bogusSecurityField") {
		t.Errorf("refused with %v, which repeats the caller's field name", err)
	}
	if !chainNames(err, "bogusSecurityField") {
		t.Errorf("refused with %v, and nothing in its chain names the offending field", err)
	}
	var ve *contract.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("refused with %v, which is not a *ValidationError", err)
	}
}

// TestDecodeFailureCarriesNoSentinel records the refusal class the six
// sentinels do not cover, and that it is still a *ValidationError.
func TestDecodeFailureCarriesNoSentinel(t *testing.T) {
	env, err := contract.Decode([]byte{0xff, 0xff, 0xff, 0xff})
	if err == nil {
		t.Fatal("invalid wire-format bytes were accepted")
	}
	// The other half of the rule TestDecodeReturnsTheMessageWithTheRefusal
	// states: a message comes back with a refusal and never with a parse
	// failure, so "it decoded" is not a reading of a non-nil message and
	// err == nil is the only test that separates the two.
	if env != nil {
		t.Errorf("Decode returned a message for bytes it could not parse: %v", env)
	}
	var ve *contract.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("got %v, which is not a *ValidationError", err)
	}
	for _, sentinel := range sentinels() {
		if errors.Is(err, sentinel) {
			t.Errorf("a decode failure matches %v, so a caller would classify it as one", sentinel)
		}
	}
}

// TestDecodeReturnsTheMessageWithTheRefusal: a refused envelope still names a
// request, and the decision and evidence about it need those identifiers.
func TestDecodeReturnsTheMessageWithTheRefusal(t *testing.T) {
	env := valid()
	env.Action.Name = ""
	wire, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decoded, err := contract.Decode(wire)
	assertRefused(t, err, contract.ErrMissingField, "action.name")
	if decoded == nil {
		t.Fatal("Decode returned no message with the refusal, so nothing can record which request was refused")
	}
	if decoded.GetRequestId() != env.GetRequestId() {
		t.Errorf("request id is %q, want %q", decoded.GetRequestId(), env.GetRequestId())
	}
}

func TestDecodeRefusesAnOversizedDocument(t *testing.T) {
	_, err := contract.Decode(make([]byte, contract.MaxEnvelopeBytes+1))
	if !errors.Is(err, contract.ErrTooLarge) {
		t.Errorf("Decode of an oversized payload = %v, want ErrTooLarge", err)
	}
	_, err = contract.DecodeJSON(make([]byte, contract.MaxEnvelopeBytes+1))
	if !errors.Is(err, contract.ErrTooLarge) {
		t.Errorf("DecodeJSON of an oversized document = %v, want ErrTooLarge", err)
	}
}

// TestValidateStringLimits proves the boundary from both sides, and proves the
// preview really has a limit of its own.
func TestValidateStringLimits(t *testing.T) {
	t.Run("at the limit", func(t *testing.T) {
		env := valid()
		env.Action.Name = strings.Repeat("a", contract.MaxStringBytes)
		if err := contract.Validate(env); err != nil {
			t.Errorf("a name of exactly %d bytes is refused: %v", contract.MaxStringBytes, err)
		}
	})

	t.Run("one over", func(t *testing.T) {
		env := valid()
		env.Action.Name = strings.Repeat("a", contract.MaxStringBytes+1)
		assertRefused(t, contract.Validate(env), contract.ErrTooLarge, "action.name")
	})

	t.Run("the preview has its own limit", func(t *testing.T) {
		const size = 2000

		env := valid()
		env.Arguments = &controlv1.Arguments{RedactedPreview: strings.Repeat("p", size), RedactionProfile: "default"}
		if err := contract.Validate(env); err != nil {
			t.Errorf("a %d byte preview is refused: %v", size, err)
		}

		env = valid()
		env.Action.Name = strings.Repeat("n", size)
		assertRefused(t, contract.Validate(env), contract.ErrTooLarge, "action.name")
	})
}

func TestValidateCollectionLimits(t *testing.T) {
	t.Run("delegation depth", func(t *testing.T) {
		if err := contract.Validate(withDelegation(contract.MaxDelegationDepth)); err != nil {
			t.Errorf("%d hops are refused: %v", contract.MaxDelegationDepth, err)
		}
		env := withDelegation(contract.MaxDelegationDepth + 1)
		assertRefused(t, contract.Validate(env), contract.ErrTooLarge, "delegation")
	})

	for _, tc := range []struct {
		path string
		fill func(*controlv1.ActionEnvelope, int)
	}{
		{"resource.labels", func(e *controlv1.ActionEnvelope, n int) { e.Resource.Labels = entries(n) }},
		{"principal.attributes", func(e *controlv1.ActionEnvelope, n int) { e.Principal.Attributes = entries(n) }},
		{"context.tags", func(e *controlv1.ActionEnvelope, n int) {
			e.Context = &controlv1.RunContext{Tags: values(n)}
		}},
		{"data.sources", func(e *controlv1.ActionEnvelope, n int) {
			e.Data = &controlv1.DataLabels{Sources: values(n)}
		}},
		{"delegation[0].scopes", func(e *controlv1.ActionEnvelope, n int) {
			e.Agent = &controlv1.Agent{Id: "agent-1"}
			e.Delegation = []*controlv1.Delegation{expiring("user-1", "agent-1")}
			e.Delegation[0].Scopes = values(n)
		}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			env := valid()
			tc.fill(env, contract.MaxLabels)
			if err := contract.Validate(env); err != nil {
				t.Errorf("%d entries are refused: %v", contract.MaxLabels, err)
			}

			env = valid()
			tc.fill(env, contract.MaxLabels+1)
			assertRefused(t, contract.Validate(env), contract.ErrTooLarge, tc.path)
		})
	}
}

func TestValidateRefusedValues(t *testing.T) {
	t.Run("reserved attribute key", func(t *testing.T) {
		env := valid()
		// Sorted order puts "reserved.owner" second, which is what the position
		// in the path has to name.
		env.Principal.Attributes = map[string]string{"department": "ops", "reserved.owner": "x"}
		assertRefused(t, contract.Validate(env), contract.ErrInvalidValue, "principal.attributes[1]")
	})

	t.Run("delegation chain does not link", func(t *testing.T) {
		env := withDelegation(2)
		env.Delegation[1].From = "somebody-else"
		assertRefused(t, contract.Validate(env), contract.ErrInvalidValue, "delegation[1].from")
	})

	t.Run("delegation chain links", func(t *testing.T) {
		if err := contract.Validate(withDelegation(2)); err != nil {
			t.Errorf("a chain that links is refused: %v", err)
		}
	})

	for _, hash := range []string{
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 65),
		"sha256:" + strings.Repeat("z", 64),
		"md5:" + strings.Repeat("a", 64),
		strings.Repeat("a", 64),
	} {
		t.Run("canonical hash "+hash[:12], func(t *testing.T) {
			env := valid()
			env.Arguments = &controlv1.Arguments{CanonicalHash: hash}
			assertRefused(t, contract.Validate(env), contract.ErrInvalidValue, "arguments.canonical_hash")
		})
	}

	t.Run("canonical hash accepted", func(t *testing.T) {
		env := valid()
		env.Arguments = &controlv1.Arguments{CanonicalHash: "sha256:" + strings.Repeat("0a", 32)}
		if err := contract.Validate(env); err != nil {
			t.Errorf("a well formed digest is refused: %v", err)
		}
	})
}

// TestValidateRefusesATimestampTheRuntimeCannotRepresent closes a gap between
// the two entry points. protojson parses a Timestamp from RFC 3339 and refuses
// what the type cannot hold; binary protobuf writes the two integers straight
// into the field, and every consumer downstream reads them through AsTime,
// which renormalises out-of-range nanos into a different instant without
// saying so. Both paths have to admit the same set of envelopes, and an
// expiry comparison must never be handed a time nobody could have meant.
func TestValidateRefusesATimestampTheRuntimeCannotRepresent(t *testing.T) {
	for _, tc := range []struct {
		name string
		ts   *timestamppb.Timestamp
	}{
		{"a nanos field holding a whole second", &timestamppb.Timestamp{Seconds: 1, Nanos: 1000000000}},
		{"two seconds of nanos", &timestamppb.Timestamp{Seconds: 1, Nanos: 2000000000}},
		{"negative nanos", &timestamppb.Timestamp{Seconds: 1, Nanos: -1}},
		{"after 9999-12-31", &timestamppb.Timestamp{Seconds: 1 << 60}},
		{"before 0001-01-01", &timestamppb.Timestamp{Seconds: -62135596801}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := valid()
			env.OccurredAt = tc.ts
			assertRefused(t, contract.Validate(env), contract.ErrInvalidValue, "occurred_at")

			// Through the wire as well: that is the path that can carry it,
			// and the reason this check exists rather than a doc line.
			wire, err := proto.Marshal(env)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			_, err = contract.Decode(wire)
			assertRefused(t, err, contract.ErrInvalidValue, "occurred_at")

			// The JSON path cannot even write it, which is the asymmetry this
			// test is here to remove: what one entry point refuses to spell,
			// the other must refuse to read.
			if out, err := protojson.Marshal(env); err == nil {
				t.Errorf("protojson wrote %s for a timestamp the type cannot represent", out)
			}
		})
	}
}

// TestValidateChecksEveryTimestampAndNotOnlyOccurredAt: the rule is on the
// walk, so it reaches the two on a delegation hop, which internal/identity is
// planned to compare for expiry, and any Timestamp a later minor adds.
func TestValidateChecksEveryTimestampAndNotOnlyOccurredAt(t *testing.T) {
	for _, tc := range []struct {
		field string
		set   func(*controlv1.Delegation, *timestamppb.Timestamp)
	}{
		{"delegation[0].issued_at", func(d *controlv1.Delegation, ts *timestamppb.Timestamp) { d.IssuedAt = ts }},
		{"delegation[0].expires_at", func(d *controlv1.Delegation, ts *timestamppb.Timestamp) { d.ExpiresAt = ts }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			env := withDelegation(1)
			tc.set(env.Delegation[0], &timestamppb.Timestamp{Seconds: 1, Nanos: -1})
			assertRefused(t, contract.Validate(env), contract.ErrInvalidValue, tc.field)
		})
	}

	// A time the type can represent passes, so the rows above are refused for
	// being out of range and not for being present.
	env := withDelegation(1)
	env.Delegation[0].ExpiresAt = timestamppb.New(time.Date(2026, 9, 9, 13, 0, 0, 0, time.UTC))
	if err := contract.Validate(env); err != nil {
		t.Errorf("an expiry the type can represent is refused: %v", err)
	}
}

// TestValidateRefusesADelegationHopThatNamesNobody covers what proto3 defaults
// do to the continuity check. Unset strings are "", so hops that name nobody
// all continue each other, and the delegation that EFFECT_CLASS_SPAWN_OR_DELEGATE
// requires is satisfied by a list that grants nothing to nobody. A pass over a
// check that cannot fail is the shape this project refuses everywhere else.
func TestValidateRefusesADelegationHopThatNamesNobody(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		hops  []*controlv1.Delegation
	}{
		{"neither end named", "delegation[0].from", []*controlv1.Delegation{{Reason: "because"}}},
		{"no from", "delegation[0].from", []*controlv1.Delegation{{To: "agent-1"}}},
		{"no to", "delegation[0].to", []*controlv1.Delegation{{From: "user-1"}}},
		{"the second hop names nobody", "delegation[1].from", []*controlv1.Delegation{
			expiring("user-1", "agent-1"), {},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := valid()
			env.Delegation = tc.hops
			assertRefused(t, contract.Validate(env), contract.ErrMissingField, tc.field)
		})
	}

	t.Run("a spawn that delegates to nobody", func(t *testing.T) {
		env := withDelegation(8)
		env.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_SPAWN_OR_DELEGATE
		env.Agent = &controlv1.Agent{Id: "agent-1"}
		for _, hop := range env.Delegation {
			hop.From, hop.To, hop.Reason = "", "", "because"
		}
		assertRefused(t, contract.Validate(env), contract.ErrMissingField, "delegation[0].from")
	})

	// Recorded as accepted until ADR-0011 anchored the chain: hops that name
	// somebody, rooted at nobody the envelope mentions. Refused at the root.
	t.Run("a chain anchored to nobody in this envelope", func(t *testing.T) {
		env := withDelegation(1)
		env.Delegation[0].From = "attacker"
		env.Delegation[0].To = "root"
		assertRefused(t, contract.Validate(env), contract.ErrInvalidValue, "delegation[0].from")
	})
}

// TestArgumentsCannotReachTheirDeclaredByteBound measures rather than enforces,
// for the same reason as TestNoV1MessageReachesTheNestingBound. Every field of
// Arguments is a string the walk already bounds, so the largest Arguments this
// package accepts is an order of magnitude under MaxArgumentsBytes and a check
// against that constant would be one no input could reach: a bound no test can
// separate from its absence is not a bound. This fails the day a field is added
// that changes the arithmetic, which is when enforcing it starts to mean
// something.
func TestArgumentsCannotReachTheirDeclaredByteBound(t *testing.T) {
	env := valid()
	env.Arguments = &controlv1.Arguments{
		CanonicalHash:    "sha256:" + strings.Repeat("a", 64),
		RedactedPreview:  strings.Repeat("p", contract.MaxPreviewBytes),
		SchemaRef:        strings.Repeat("s", contract.MaxStringBytes),
		RedactionProfile: strings.Repeat("r", contract.MaxStringBytes),
	}
	if err := contract.Validate(env); err != nil {
		t.Fatalf("the largest Arguments the field limits allow is refused, so this measures nothing: %v", err)
	}

	largest := proto.Size(env.GetArguments())
	if largest > contract.MaxArgumentsBytes {
		t.Fatalf("an Arguments of %d bytes passes every check and MaxArgumentsBytes is %d: the constant is reachable now, and Validate has to enforce it",
			largest, contract.MaxArgumentsBytes)
	}
	t.Logf("largest Arguments the field limits allow: %d bytes, against MaxArgumentsBytes %d", largest, contract.MaxArgumentsBytes)
}

// TestValidateCannotSeeDiscardedUnknowns records the hole in Validate that the
// decode exists to close: DiscardUnknown leaves a message byte-identical to one
// that never carried an unknown field.
func TestValidateCannotSeeDiscardedUnknowns(t *testing.T) {
	env := valid()
	env.Action.ProtoReflect().SetUnknown(unknownField(4095))
	wire, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	discarded := &controlv1.ActionEnvelope{}
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(wire, discarded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := contract.Validate(discarded); err != nil {
		t.Errorf("Validate = %v; the recorded behaviour is that it cannot see a discarded unknown field", err)
	}
	if _, err := contract.Decode(wire); !errors.Is(err, contract.ErrUnknownField) {
		t.Errorf("Decode of the same bytes = %v, want ErrUnknownField: the decode is what closes this hole", err)
	}
}

// TestUnknownFieldInsideAMapEntryIsDiscardedByTheRuntime records why Decode
// reads map entries itself (ADR-0011). The runtime drops an unknown field
// inside a map entry before any walk can reach it, and a map entry is one key
// and one value in a JSON object, with nowhere to put a third field. Decode
// refuses such an entry before the parse
// (TestDecodeRefusesWhatAMapEntryWouldDrop); a message parsed anywhere else has
// lost the field for good, which is what this test shows of the runtime.
func TestUnknownFieldInsideAMapEntryIsDiscardedByTheRuntime(t *testing.T) {
	// One map entry: key "k", value "v", plus field 3 which no entry declares.
	var entry []byte
	entry = protowire.AppendTag(entry, 1, protowire.BytesType)
	entry = protowire.AppendString(entry, "k")
	entry = protowire.AppendTag(entry, 2, protowire.BytesType)
	entry = protowire.AppendString(entry, "v")
	entry = append(entry, unknownField(3)...)

	var wire []byte
	wire = protowire.AppendTag(wire, 5, protowire.BytesType) // Principal.attributes
	wire = protowire.AppendBytes(wire, entry)

	principal := &controlv1.Principal{}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(wire, principal); err != nil {
		t.Fatalf("the runtime refused the entry after all, which would be better than the recorded behaviour: %v", err)
	}
	if got := principal.GetAttributes()["k"]; got != "v" {
		t.Fatalf("the entry did not parse, so this case proves nothing: %q", got)
	}
	if unknown := principal.ProtoReflect().GetUnknown(); len(unknown) != 0 {
		t.Errorf("the unknown bytes are reachable after all, at the message: %x. ADR-0002 and this test are out of date", unknown)
	}

	again, err := proto.Marshal(principal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(again) >= len(wire) {
		t.Errorf("re-marshalling kept %d bytes of %d, so the unknown field survived somewhere", len(again), len(wire))
	}
}

// TestNoV1MessageReachesTheNestingBound measures what the constant guards. It
// is the honest form of a test for MaxNesting: no v1 message is recursive and
// the deepest chain is far below the bound, so the bound cannot be reached
// through this contract at all, and a test claiming to exercise it would be
// asserting on a message the schema cannot express. If a later contract adds a
// recursive message, this fails and the walk's depth guard becomes live.
func TestNoV1MessageReachesTheNestingBound(t *testing.T) {
	root := (&controlv1.ActionEnvelope{}).ProtoReflect().Descriptor()

	depth, recursive := chainDepth(root, map[protoreflect.FullName]bool{})
	if recursive {
		t.Errorf("%s is recursive: the walk's depth guard is now load-bearing and needs a test that reaches it", root.FullName())
	}
	if depth < 2 {
		t.Fatalf("measured a depth of %d, so the measurement is broken rather than the schema shallow", depth)
	}
	if depth >= contract.MaxNesting {
		t.Errorf("the deepest chain is %d, at or past MaxNesting %d", depth, contract.MaxNesting)
	}
	t.Logf("deepest chain in the contract: %d levels, MaxNesting is %d", depth, contract.MaxNesting)
}

// chainDepth returns the longest chain of nested messages reachable from md,
// counting md itself, and whether it met a message twice on one path.
func chainDepth(md protoreflect.MessageDescriptor, path map[protoreflect.FullName]bool) (int, bool) {
	if path[md.FullName()] {
		return 0, true
	}
	path[md.FullName()] = true
	defer delete(path, md.FullName())

	best, recursive := 0, false
	fields := md.Fields()
	for i := range fields.Len() {
		child := fields.Get(i).Message()
		if child == nil {
			continue
		}
		deeper, cycle := chainDepth(child, path)
		recursive = recursive || cycle
		best = max(best, deeper)
	}
	return best + 1, recursive
}

func TestEffectTableCoversEveryDeclaredClass(t *testing.T) {
	declared := controlv1.EffectClass(0).Descriptor().Values()
	for i := range declared.Len() {
		number := declared.Get(i).Number()
		if number == 0 {
			continue // UNSPECIFIED is refused, not required to have a row
		}
		effect := controlv1.EffectClass(number)
		if _, ok := effectsUnderTest()[effect]; !ok {
			t.Errorf("%s is declared in the contract and this test names no requirements for it", effect)
		}
	}
}

// TestExportedFunctionSetIsClosed pins the package's public function surface.
// The closure tests in limits_test.go read constants and variables and
// TestExportedTypeSetIsClosed reads types, so between them nothing enters a
// package ADR-0007 calls a compatibility promise without something saying so.
func TestExportedFunctionSetIsClosed(t *testing.T) {
	promised := map[string]bool{
		// The decode and validation boundary, and the three value rules it
		// applies, which the evidence builder and the policy parser apply too
		// rather than holding a second copy (docs/contracts.md, "Decoding and
		// validation").
		"Decode":          true,
		"DecodeJSON":      true,
		"Validate":        true,
		"CheckIdentifier": true,
		"CheckHost":       true,
		"CheckMapKey":     true,
		// The predicates the matcher keys on.
		"ParseEffect":        true,
		"IsMaterial":         true,
		"SensitivityAtLeast": true,
		"IsUntrusted":        true,
		"ToxicFlow":          true,
		// What a caller needs to hold a state and a floor ToxicFlow answers
		// about, rather than one it refuses.
		"NewFlowState":          true,
		"ValidSensitivityFloor": true,
		// What Validate requires of each class, for a loader that refuses a
		// classification no envelope could carry (ADR-0060).
		"EffectRequires": true,
	}

	found := exportedFunctions(t)
	if len(found) == 0 {
		t.Fatal("no exported function found in the package; this test reads its subject from the source")
	}
	for _, name := range found {
		if !promised[name] {
			t.Errorf("%s is exported from pkg/contract and this test does not know it: document it on docs/contracts.md and list it here, or unexport it",
				name)
		}
		delete(promised, name)
	}
	for name := range promised {
		t.Errorf("%s is promised here and the package no longer declares it", name)
	}
}

// exportedFunctions returns the exported package-level functions, methods
// excluded: a method belongs to a type this file already pins.
func exportedFunctions(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(packageDir)
	if err != nil {
		t.Fatalf("reading %s: %v", packageDir, err)
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(packageDir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && fn.Name.IsExported() {
				names = append(names, fn.Name.Name)
			}
		}
	}
	return names
}

// effectsUnderTest mirrors the table in effect.go. It is a copy on purpose:
// reading the implementation's own table would make every case above assert
// that the code agrees with itself.
func effectsUnderTest() map[controlv1.EffectClass][]string {
	mutating := []string{"resource.type", "resource.id", "environment", "resource.environment"}
	return map[controlv1.EffectClass][]string{
		controlv1.EffectClass_EFFECT_CLASS_READ:               {"resource.type"},
		controlv1.EffectClass_EFFECT_CLASS_WRITE:              mutating,
		controlv1.EffectClass_EFFECT_CLASS_DELETE:             mutating,
		controlv1.EffectClass_EFFECT_CLASS_CONFIGURE:          mutating,
		controlv1.EffectClass_EFFECT_CLASS_EXECUTE:            {"resource.type", "arguments.canonical_hash"},
		controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE:        {"destination.trust_zone"},
		controlv1.EffectClass_EFFECT_CLASS_TRANSACT:           {"resource.id", "arguments.canonical_hash", "principal.tenant_id", "resource.tenant_id"},
		controlv1.EffectClass_EFFECT_CLASS_IDENTITY_OR_ACCESS: {"resource.id", "principal.tenant_id", "resource.tenant_id"},
		controlv1.EffectClass_EFFECT_CLASS_SPAWN_OR_DELEGATE:  {"agent.id", "delegation"},
	}
}

// satisfying returns an envelope for one effect class with every path it
// requires set.
func satisfying(effect controlv1.EffectClass, required []string) *controlv1.ActionEnvelope {
	env := valid()
	env.Action.Effect = effect
	for _, path := range required {
		set(env, path)
	}
	return env
}

func set(env *controlv1.ActionEnvelope, path string) {
	switch path {
	case "environment":
		env.Environment = "prod"
	case "resource.environment":
		env.Resource.Environment = "prod"
	case "principal.tenant_id":
		env.Principal.TenantId = "tenant-1"
	case "resource.tenant_id":
		env.Resource.TenantId = "tenant-1"
	case "agent.id":
		env.Agent = &controlv1.Agent{Id: "agent-1"}
	case "arguments.canonical_hash":
		env.Arguments = &controlv1.Arguments{CanonicalHash: "sha256:" + strings.Repeat("ab", 32)}
	case "destination.trust_zone":
		env.Destination = &controlv1.Destination{TrustZone: controlv1.TrustZone_TRUST_ZONE_PARTNER}
	case "delegation":
		// From the principal valid() sets to the agent "agent.id" sets.
		env.Delegation = []*controlv1.Delegation{expiring("user-1", "agent-1")}
	}
}

// clearPath empties one path so the refusal for it can be observed.
func clearPath(t *testing.T, env *controlv1.ActionEnvelope, path string) {
	t.Helper()

	switch path {
	case "action.provider":
		env.Action.Provider = ""
	case "resource.type":
		env.Resource.Type = ""
	case "resource.id":
		env.Resource.Id = ""
	case "environment":
		env.Environment = ""
	case "resource.environment":
		env.Resource.Environment = ""
	case "principal.tenant_id":
		env.Principal.TenantId = ""
	case "resource.tenant_id":
		env.Resource.TenantId = ""
	case "agent.id":
		env.Agent = nil
	case "arguments.canonical_hash":
		env.Arguments = nil
	case "destination.trust_zone":
		env.Destination = nil
	case "delegation":
		env.Delegation = nil
	default:
		t.Fatalf("no way to clear %q, so this case would pass without testing anything", path)
	}
}

// withDelegation returns the base envelope acting for agent-1 through a chain
// of hops from user-1, its principal, to agent-1: user-1 -> party-1 -> ... ->
// agent-1. Every hop is one the chain rules accept on its own, so a case that
// edits one of them is refused for that edit.
func withDelegation(hops int) *controlv1.ActionEnvelope {
	env := valid()
	env.Agent = &controlv1.Agent{Id: "agent-1"}
	for i := range hops {
		from, to := "party-"+strconv.Itoa(i), "party-"+strconv.Itoa(i+1)
		if i == 0 {
			from = "user-1"
		}
		if i == hops-1 {
			to = "agent-1"
		}
		env.Delegation = append(env.Delegation, expiring(from, to))
	}
	return env
}

// expiring returns a hop issued at 11:00 and expiring at 13:00 on the day the
// base envelope was proposed. New timestamps each call: a case that edits one
// hop's time must not move every hop's.
func expiring(from, to string) *controlv1.Delegation {
	return &controlv1.Delegation{
		From:      from,
		To:        to,
		IssuedAt:  timestamppb.New(time.Date(2026, 9, 9, 11, 0, 0, 0, time.UTC)),
		ExpiresAt: timestamppb.New(time.Date(2026, 9, 9, 13, 0, 0, 0, time.UTC)),
	}
}

func entries(n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m["k"+strconv.Itoa(i)] = "v"
	}
	return m
}

func values(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, "v"+strconv.Itoa(i))
	}
	return out
}

// unknownField returns the wire bytes of one field number no message declares.
func unknownField(number protowire.Number) protoreflect.RawFields {
	var b []byte
	b = protowire.AppendTag(b, number, protowire.VarintType)
	b = protowire.AppendVarint(b, 1)
	return b
}
