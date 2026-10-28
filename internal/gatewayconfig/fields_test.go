package gatewayconfig

import (
	"slices"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/pkg/contract"
)

// TestEnvNamesAreUnique: two keys with one variable name would make a variable
// ambiguous, and the operator would never learn which key it set.
func TestEnvNamesAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, f := range Fields() {
		if other, ok := seen[f.Env]; ok {
			t.Errorf("%s and %s both read %s", other, f.Path, f.Env)
		}
		seen[f.Env] = f.Path
	}
	if name := brand.Env(EnvName(HeadersPrefix)); seen[strings.TrimSuffix(name, "_")] != "" {
		t.Errorf("a key reads %s, which the header prefix owns", name)
	}
}

// TestFieldsSpellTheTable pins a row of each table as literals: the path, the
// variable with the product's prefix, the kind, the default, whether a value
// is required and, for a key that takes one of a set, the set in order.
func TestFieldsSpellTheTable(t *testing.T) {
	byPath := map[string]Field{}
	for _, f := range Fields() {
		if _, ok := byPath[f.Path]; ok {
			t.Errorf("%s is listed twice", f.Path)
		}
		byPath[f.Path] = f
	}
	for _, want := range []Field{
		{Path: "mode", Kind: "one of", Required: true, Env: brand.Env("MODE"),
			Values: []string{"OBSERVE", "SHADOW", "WARN", "APPROVE", "ENFORCE", "LOCKDOWN"}},
		{Path: "evidence.max_bytes", Kind: "bytes, plain or with KiB, MiB, GiB", Default: "1GiB", Env: brand.Env("EVIDENCE_MAX_BYTES")},
		{Path: "policy.fail_open_read", Kind: "true or false", Default: "false", Env: brand.Env("POLICY_FAIL_OPEN_READ")},
		{Path: "approvals.ttl", Kind: "duration", Default: "15m", Env: brand.Env("APPROVALS_TTL")},
		{Path: "export.in_flight", Kind: "integer", Default: "4", Env: brand.Env("EXPORT_IN_FLIGHT")},
		{Path: "upstreams.N.name", Kind: "string", Required: true, Env: brand.Env("UPSTREAMS_N_NAME")},
		{Path: "overrides.N.trust_zone", Kind: "one of", Env: brand.Env("OVERRIDES_N_TRUST_ZONE"),
			Values: []string{"", "TRUSTED_INTERNAL", "PARTNER", "UNTRUSTED_EXTERNAL", "USER_CONTROLLED", "MODEL_GENERATED"}},
		{Path: "overrides.N.returns.sensitivity", Kind: "one of", Env: brand.Env("OVERRIDES_N_RETURNS_SENSITIVITY"),
			Values: []string{"", "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SECRET"}},
		{Path: "flow.max_runs", Kind: "integer", Default: "64", Env: brand.Env("FLOW_MAX_RUNS")},
		{Path: "listener.kind", Kind: "one of", Default: "stateless_http", Required: true, Env: brand.Env("LISTENER_KIND"),
			Values: []string{"stateless_http", "stateful_http", "stdio", "enforce_api"}},
		{Path: "listener.socket", Kind: "string", Env: brand.Env("LISTENER_SOCKET")},
		{Path: "listener.execution_lifetime", Kind: "duration", Env: brand.Env("LISTENER_EXECUTION_LIFETIME")},
		{Path: "listener.max_body_bytes", Kind: "bytes, plain or with KiB, MiB, GiB", Default: "128KiB", Env: brand.Env("LISTENER_MAX_BODY_BYTES")},
		{Path: "tools.N.provider", Kind: "string", Required: true, Env: brand.Env("TOOLS_N_PROVIDER")},
		{Path: "tools.N.resource_from", Kind: "string", Env: brand.Env("TOOLS_N_RESOURCE_FROM")},
		{Path: "tools.N.returns.trust", Kind: "one of", Env: brand.Env("TOOLS_N_RETURNS_TRUST"),
			Values: []string{"", "TRUSTED_INTERNAL", "PARTNER", "UNTRUSTED_EXTERNAL", "USER_CONTROLLED", "MODEL_GENERATED"}},
	} {
		got, ok := byPath[want.Path]
		if !ok {
			t.Errorf("%s is not listed", want.Path)
			continue
		}
		if got.Kind != want.Kind || got.Default != want.Default || got.Required != want.Required || got.Env != want.Env || !slices.Equal(got.Values, want.Values) {
			t.Errorf("%s is %+v, want %+v", want.Path, got, want)
		}
	}
	for _, f := range Fields() {
		if (f.Kind == enumKind) != (len(f.Values) > 0) {
			t.Errorf("%s is of kind %q and lists %d values", f.Path, f.Kind, len(f.Values))
		}
	}
}

// TestEveryEffectClassOfTheContractLoads: an override takes each of the
// contract's nine classes, spelled as the contract parses it, on an upstream
// with every key a class's envelope reads from it.
func TestEveryEffectClassOfTheContractLoads(t *testing.T) {
	withTenant := replaced(t, document, "    environment: prod\n", "    environment: prod\n    tenant_id: acme\n")
	for _, name := range []string{
		"READ", "WRITE", "DELETE", "EXECUTE", "COMMUNICATE", "TRANSACT",
		"IDENTITY_OR_ACCESS", "CONFIGURE", "SPAWN_OR_DELEGATE",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := load(t, writeDocument(t, withTenant+overrideEffect(name)))
			if len(cfg.Overrides) != 1 || cfg.Overrides[0].Effect != name {
				t.Errorf("the override loaded as %+v, want effect %s", cfg.Overrides, name)
			}
		})
	}
}

// TestTheEffectKeyTakesExactlyTheContractsClasses: every spelling the
// configuration takes is one the contract parses, and every class the
// contract declares but the zero one is a spelling the configuration takes,
// so doctor never passes an override that run refuses.
func TestTheEffectKeyTakesExactlyTheContractsClasses(t *testing.T) {
	var values []string
	for _, f := range Fields() {
		if f.Path == "overrides.N.effect" {
			values = f.Values
		}
	}
	if len(values) == 0 {
		t.Fatal("overrides.N.effect lists no values")
	}
	for _, v := range values {
		if _, err := contract.ParseEffect(v); err != nil {
			t.Errorf("the configuration takes effect %q, which the contract refuses: %v", v, err)
		}
	}
	declared := 0
	for number, name := range controlv1.EffectClass_name {
		if number == 0 {
			continue
		}
		declared++
		if spelled := strings.TrimPrefix(name, "EFFECT_CLASS_"); !slices.Contains(values, spelled) {
			t.Errorf("the contract declares %s, which the configuration does not take", spelled)
		}
	}
	if len(values) != declared {
		t.Errorf("the configuration takes %d effect spellings, the contract declares %d classes", len(values), declared)
	}
}

// TestFieldsFollowTheTables is the property the reference page rests on: a
// key added to a table is listed without another edit, and in the table's
// place. The tables are restored after the test.
func TestFieldsFollowTheTables(t *testing.T) {
	before := len(Fields())
	scalar, item := configFields, overrideFields
	t.Cleanup(func() { configFields, overrideFields = scalar, item })
	configFields = append(slices.Clone(configFields), intField("probe.count", "3", func(c *Config) *int { return &c.Approvals.MaxOpen }))
	overrideFields = append(slices.Clone(overrideFields), stringField("probe", "", true, func(o *OverrideConfig) *string { return &o.Tool }))
	fields := Fields()
	if len(fields) != before+2 {
		t.Fatalf("%d fields after two keys were added to the tables, want %d", len(fields), before+2)
	}
	scalarAt, itemAt, toolsAt := -1, -1, -1
	for i, f := range fields {
		switch {
		case f.Path == "probe.count":
			scalarAt = i
		case f.Path == "overrides.N.probe":
			itemAt = i
		case toolsAt < 0 && strings.HasPrefix(f.Path, "tools.N."):
			toolsAt = i
		}
	}
	if scalarAt != len(scalar) {
		t.Errorf("the added scalar key is at %d, want %d, the end of the scalar table", scalarAt, len(scalar))
	}
	if toolsAt < 0 || itemAt != toolsAt-1 {
		t.Errorf("the added override key is at %d, want the end of the override keys, before the tool keys at %d", itemAt, toolsAt)
	}
}

// TestFieldsValuesAreACopy: a caller that sorts or trims the spellings must
// not change what the loader admits.
func TestFieldsValuesAreACopy(t *testing.T) {
	for _, f := range Fields() {
		if f.Path == "mode" {
			f.Values[0] = "AUDIT"
		}
	}
	if !slices.Contains(modeNames, "OBSERVE") || slices.Contains(modeNames, "AUDIT") {
		t.Errorf("the mode spellings are %q after a caller rewrote a listed value", modeNames)
	}
}

// TestModeNamesSpellTheModes pins the mode spellings a reader outside this
// package checks against, and holds the list it hands out to a copy.
func TestModeNamesSpellTheModes(t *testing.T) {
	want := []string{"OBSERVE", "SHADOW", "WARN", "APPROVE", "ENFORCE", "LOCKDOWN"}
	got := ModeNames()
	if !slices.Equal(got, want) {
		t.Fatalf("ModeNames() = %q, want %q", got, want)
	}
	got[0] = "AUDIT"
	if again := ModeNames(); again[0] != "OBSERVE" {
		t.Errorf("ModeNames() = %q after a caller rewrote the list it was handed", again)
	}
}

// TestDefaultsAreValuesTheirKeysTake: every default in every table is read
// by its own setter, so a table cannot declare a default the loader refuses.
func TestDefaultsAreValuesTheirKeysTake(t *testing.T) {
	if err := applyDefaults(&Config{}, configFields); err != nil {
		t.Error(err)
	}
	if err := applyDefaults(&UpstreamConfig{}, upstreamFields); err != nil {
		t.Error(err)
	}
	if err := applyDefaults(&OverrideConfig{}, overrideFields); err != nil {
		t.Error(err)
	}
	if err := applyDefaults(&ToolConfig{}, toolFields); err != nil {
		t.Error(err)
	}
}
