package gatewayconfig

import (
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

const identifierBlock = "pdp:\n  identifier: https://pdp.example.test\n"

// headerBlocks writes one header under each map key, spelled as name.
var headerBlocks = []struct {
	key   string
	block func(name, value string) string
	get   func(*Config) map[string]string
}{
	{"export.headers", func(name, value string) string {
		return strings.Replace(document, exportLine, exportLine+"  headers:\n    "+name+": "+value+"\n", 1)
	}, func(c *Config) map[string]string { return c.Export.Headers }},
	{"pdp.headers", func(name, value string) string {
		return document + identifierBlock + "  headers:\n    " + name + ": " + value + "\n"
	}, func(c *Config) map[string]string { return c.PDP.Headers }},
}

// TestAVariableWinsOverTheFilesHeaderHoweverEitherSpellsIt: the file's name
// and the variable's are one header, which holds the variable's value alone.
func TestAVariableWinsOverTheFilesHeaderHoweverEitherSpellsIt(t *testing.T) {
	for _, m := range headerBlocks {
		for _, spelled := range []string{"X-Tenant-Key", "x-tenant-key", "X-TENANT-KEY"} {
			t.Run(m.key+" "+spelled, func(t *testing.T) {
				path := writeDocument(t, m.block(spelled, "from-file"))
				environ := []string{brand.Env(EnvName(m.key)) + "_X_TENANT_KEY=from-env"}
				cfg, err := Load(path, environ)
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if got, want := m.get(cfg), map[string]string{"X-Tenant-Key": "from-env"}; !maps.Equal(got, want) {
					t.Errorf("%s is %v, want %v", m.key, got, want)
				}
			})
		}
	}
}

// TestAHeaderTheFileSpellsTwiceIsRefused: two spellings of one name are one
// header set twice, as a doubled index is one item set twice.
func TestAHeaderTheFileSpellsTwiceIsRefused(t *testing.T) {
	for _, m := range headerBlocks {
		t.Run(m.key, func(t *testing.T) {
			doc := strings.Replace(m.block("X-Tenant-Key", "first"), "X-Tenant-Key: first\n", "X-Tenant-Key: first\n    x-tenant-key: second\n", 1)
			_, err := Load(writeDocument(t, doc), nil)
			if err == nil {
				t.Fatalf("the loader accepted X-Tenant-Key and x-tenant-key under %s", m.key)
			}
			if !strings.Contains(err.Error(), m.key+".X-Tenant-Key is set twice") {
				t.Errorf("the refusal is %q", err)
			}
			for _, value := range []string{"first", "second"} {
				if strings.Contains(err.Error(), value) {
					t.Errorf("the refusal quotes the header's value %q: %q", value, err)
				}
			}
		})
	}
}

// TestTwoVariablesOfOneHeaderAreRefused: variables that fold to one name are
// one header set twice, whichever comes first in the environment.
func TestTwoVariablesOfOneHeaderAreRefused(t *testing.T) {
	path := write(t, identifierBlock)
	for _, pair := range [][2]string{
		{"PDP_HEADERS_X_TENANT", "PDP_HEADERS_x_tenant"},
		{"PDP_HEADERS_X-TENANT-KEY", "PDP_HEADERS_X_TENANT_KEY"},
		{"EXPORT_HEADERS_X_A", "EXPORT_HEADERS_x-a"},
	} {
		for _, order := range [][2]string{{pair[0], pair[1]}, {pair[1], pair[0]}} {
			t.Run(order[0]+" then "+order[1], func(t *testing.T) {
				_, err := Load(path, []string{brand.EnvPrefix + order[0] + "=first", brand.EnvPrefix + order[1] + "=second"})
				if err == nil {
					t.Fatalf("the loader accepted %s and %s", order[0], order[1])
				}
				if !strings.Contains(err.Error(), "is set twice; it was set by "+brand.EnvPrefix+order[0]) {
					t.Errorf("the refusal is %q", err)
				}
				for _, value := range []string{"first", "second"} {
					if strings.Contains(err.Error(), value) {
						t.Errorf("the refusal quotes the header's value %q: %q", value, err)
					}
				}
			})
		}
	}
	cfg, err := Load(path, []string{brand.EnvPrefix + "PDP_HEADERS_X_A=a", brand.EnvPrefix + "PDP_HEADERS_X_B=b"})
	if err != nil {
		t.Fatalf("two headers from two variables are refused: %v", err)
	}
	if got := cfg.PDP.Headers; !maps.Equal(got, map[string]string{"X-A": "a", "X-B": "b"}) {
		t.Errorf("pdp.headers is %v", got)
	}
}

// TestAHeaderNameFromTheFileIsOneToken: a list, a nested mapping and a name
// no HTTP header carries are refused naming the key, and the value, which is
// a credential, is never quoted.
func TestAHeaderNameFromTheFileIsOneToken(t *testing.T) {
	for _, m := range headerBlocks {
		for _, c := range []struct{ name, under, wants string }{
			{"a list", "    - Bearer s3cret\n", m.key + " takes a mapping"},
			{"a list of mappings", "    - X-A: s3cret\n", m.key + " takes a mapping"},
			{"an all-digit name", "    0: s3cret\n", m.key + " takes a mapping"},
			{"a nested mapping", "    X-A:\n      B: s3cret\n", "names no single header"},
			{"a name with a space", "    X A: s3cret\n", "is not a header name"},
			{"a name with a parenthesis", "    X(A): s3cret\n", "is not a header name"},
			{"a name with an underscore", "    X_Tenant: s3cret\n", "no variable can name"},
		} {
			t.Run(m.key+" "+c.name, func(t *testing.T) {
				doc := strings.Replace(m.block("X-Placeholder", "v"), "    X-Placeholder: v\n", c.under, 1)
				_, err := Load(writeDocument(t, doc), nil)
				if err == nil {
					t.Fatalf("the loader accepted %s under %s", c.name, m.key)
				}
				if !strings.Contains(err.Error(), c.wants) {
					t.Errorf("the refusal is %q, which does not say %q", err, c.wants)
				}
				if strings.Contains(err.Error(), "s3cret") {
					t.Errorf("the refusal quotes the header's value: %q", err)
				}
			})
		}
	}
}

// TestAHeaderNameFromAVariableIsOneToken: the variable's name is held to the
// file's rule, and a well-formed one is read.
func TestAHeaderNameFromAVariableIsOneToken(t *testing.T) {
	path := write(t, identifierBlock)
	for _, c := range []struct{ name, wants string }{
		{"PDP_HEADERS_", "names no header"},
		{"PDP_HEADERS_A.B", "names no single header"},
		{"PDP_HEADERS_X\nY", "is not a header name"},
		{"PDP_HEADERS_X Y", "is not a header name"},
		{"PDP_HEADERS_0", "pdp.headers takes a mapping"},
		{"EXPORT_HEADERS_12", "export.headers takes a mapping"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(path, []string{brand.EnvPrefix + c.name + "=s3cret"})
			if err == nil {
				t.Fatalf("the loader accepted %q", c.name)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Errorf("the refusal is %q, which does not say %q", err, c.wants)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Errorf("the refusal quotes the header's value: %q", err)
			}
		})
	}
	cfg, err := Load(path, []string{brand.EnvPrefix + "PDP_HEADERS_X_A1=v"})
	if err != nil {
		t.Fatalf("a well-formed header variable is refused: %v", err)
	}
	if got := cfg.PDP.Headers; !maps.Equal(got, map[string]string{"X-A1": "v"}) {
		t.Errorf("pdp.headers is %v", got)
	}
}

// TestEveryDecisionPointCollectionNeedsADecisionPoint: a pdp list or map
// added to the tables is refused with no identifier, as the scalars are,
// with no second list of them to keep.
func TestEveryDecisionPointCollectionNeedsADecisionPoint(t *testing.T) {
	lists, maplist := listFields, mapFields
	t.Cleanup(func() { listFields, mapFields = lists, maplist })
	var items []string
	headers := map[string]string{}
	listFields = append(append([]listField(nil), lists...), listField{"pdp.probe_items", "one probe",
		func(*Config) *[]string { return &items }})
	mapFields = append(append([]mapField(nil), maplist...), mapField{"pdp.probe_headers.", "one probe",
		func(*Config) *map[string]string { return &headers }})
	for _, c := range []struct{ key, block string }{
		{"pdp.probe_items", "pdp:\n  probe_items:\n    - https://app.example.test\n"},
		{"pdp.probe_headers", "pdp:\n  probe_headers:\n    X-A: v\n"},
	} {
		t.Run(c.key, func(t *testing.T) {
			items = nil
			_, err := Load(write(t, c.block), os.Environ())
			if err == nil || !strings.HasPrefix(err.Error(), c.key+": ") || !strings.Contains(err.Error(), "pdp.identifier") {
				t.Fatalf("the refusal is %v; it has to name %s and pdp.identifier", err, c.key)
			}
			items = nil
			with := strings.Replace(c.block, "pdp:\n", identifierBlock, 1)
			if _, err := Load(write(t, with), os.Environ()); err != nil {
				t.Errorf("with an identifier, %s is refused: %v", c.key, err)
			}
		})
	}
}

// TestAnAddressThatCouldHideACredentialIsNotPrinted: userinfo, a query or a
// fragment withholds the whole value and says why; an address with none of
// them is printed as it is.
func TestAnAddressThatCouldHideACredentialIsNotPrinted(t *testing.T) {
	for _, c := range []struct{ value, why string }{
		{"https://operator:s3cret@pdp.example.test/t", "userinfo"},
		{"https://s3cret@pdp.example.test", "userinfo"},
		{"https://pdp.example.test/e?api_key=s3cret", "a query"},
		{"https://pdp.example.test/e?", "a query"},
		{"https://pdp.example.test/e#s3cret", "a fragment"},
		{"https:operator:s3cret@pdp.example.test", "userinfo"},
	} {
		for _, key := range []string{"pdp.identifier", "pdp.evaluation_endpoint", "export.endpoint"} {
			if key == "export.endpoint" && !strings.Contains(c.value, "//") {
				continue
			}
			t.Run(key+" "+c.value, func(t *testing.T) {
				path := write(t, identifierBlock)
				cfg, err := Load(path, []string{brand.Env(EnvName(key)) + "=" + c.value})
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				got := settingOf(t, cfg, key)
				if want := NotPrinted + ": it carries " + c.why; got != want {
					t.Errorf("%s shows %q, want %q", key, got, want)
				}
			})
		}
	}
	cfg := load(t, write(t, pdpBlock))
	if got := settingOf(t, cfg, "pdp.evaluation_endpoint"); got != "https://pdp.example.test/tenant-a/eval" {
		t.Errorf("an address with nothing to hide shows %q", got)
	}
	if got := ShowAddress("http://127.0.0.1:1/mcp"); got != "http://127.0.0.1:1/mcp" {
		t.Errorf("ShowAddress withholds %q", got)
	}
}

// TestARefusedAddressIsNotQuotedWhenItCouldHideACredential: the refusal
// names the key and why the value is withheld, never the value.
func TestARefusedAddressIsNotQuotedWhenItCouldHideACredential(t *testing.T) {
	for _, key := range []string{"export.endpoint", "upstreams.0.endpoint"} {
		t.Run(key, func(t *testing.T) {
			_, err := Load(write(t, ""), []string{brand.Env(EnvName(key)) + "=ftp://operator:s3cret@collector.example.test"})
			if err == nil {
				t.Fatalf("the loader accepted an ftp %s", key)
			}
			if !strings.Contains(err.Error(), key+": "+NotPrinted+": it carries userinfo") || strings.Contains(err.Error(), "s3cret") {
				t.Errorf("the refusal is %q", err)
			}
		})
	}
}

func settingOf(t *testing.T, cfg *Config, key string) string {
	t.Helper()
	for _, s := range cfg.Settings() {
		if s.Path == key {
			return s.Value
		}
	}
	t.Fatalf("no setting %s", key)
	return ""
}
